// Package webhook delivers imprimatur's events to other apps and checks
// deliveries other apps send it, in the Standard Webhooks 1.0 shape the estate
// uses (sange webhooks-and-events.md §5–§6): headers webhook-id,
// webhook-timestamp and webhook-signature, signed content "id.timestamp.body",
// "v1,<base64 HMAC-SHA256>" entries, secrets "whsec_<base64>" of 24 to 64
// random bytes, several signatures during a rotation, constant-time compare.
// The asymmetric v1a scheme is opt-in: "v1a,<base64 ed25519 signature>" over
// the same content, signed with a whsk_ key and checked with its whpk_ public
// key, so a receiver holds nothing that can forge a delivery.
package webhook

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Header names.
const (
	HeaderID        = "webhook-id"
	HeaderTimestamp = "webhook-timestamp"
	HeaderSignature = "webhook-signature"
	SecretPrefix    = "whsec_"
	// SigningKeyPrefix and PublicKeyPrefix mark v1a ed25519 keys.
	SigningKeyPrefix = "whsk_"
	PublicKeyPrefix  = "whpk_"
)

// DefaultTolerance is how far a timestamp may be from now (Stripe's and the
// estate's default).
const DefaultTolerance = 5 * time.Minute

// NewSecret makes a whsec_ secret of 32 random bytes. impr generates every
// secret it signs with, so none is ever chosen by hand.
func NewSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return SecretPrefix + base64.StdEncoding.EncodeToString(b), nil
}

// DecodeSecret checks and decodes a whsec_ secret.
func DecodeSecret(s string) ([]byte, error) {
	raw, ok := strings.CutPrefix(strings.TrimSpace(s), SecretPrefix)
	if !ok {
		return nil, errors.New("a webhook secret starts with whsec_")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("a webhook secret is whsec_ and base64: %w", err)
	}
	if len(b) < 24 || len(b) > 64 {
		return nil, fmt.Errorf("a webhook secret holds 24 to 64 bytes, not %d", len(b))
	}
	return b, nil
}

// NewSigningKey makes a v1a ed25519 pair: the whsk_ signing key impr keeps
// by reference, and the whpk_ public key the receiver holds.
func NewSigningKey() (signing, public string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return SigningKeyPrefix + base64.StdEncoding.EncodeToString(priv), PublicKeyPrefix + base64.StdEncoding.EncodeToString(pub), nil
}

// DecodeSigningKey checks and decodes a whsk_ key: the 64-byte ed25519
// private key, or its 32-byte seed.
func DecodeSigningKey(s string) (ed25519.PrivateKey, error) {
	raw, ok := strings.CutPrefix(strings.TrimSpace(s), SigningKeyPrefix)
	if !ok {
		return nil, errors.New("a v1a signing key starts with whsk_")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("a v1a signing key is whsk_ and base64: %w", err)
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		k := ed25519.PrivateKey(b)
		// The second half is the public key; refuse one that does not match.
		if !ed25519.NewKeyFromSeed(k.Seed()).Equal(k) {
			return nil, errors.New("a v1a signing key's public half does not match its seed")
		}
		return k, nil
	}
	return nil, fmt.Errorf("a v1a signing key holds 32 or 64 bytes, not %d", len(b))
}

// DecodePublicKey checks and decodes a whpk_ public key.
func DecodePublicKey(s string) (ed25519.PublicKey, error) {
	raw, ok := strings.CutPrefix(strings.TrimSpace(s), PublicKeyPrefix)
	if !ok {
		return nil, errors.New("a v1a public key starts with whpk_")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("a v1a public key is whpk_ and base64: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("a v1a public key holds 32 bytes, not %d", len(b))
	}
	return ed25519.PublicKey(b), nil
}

// PublicKeyOf is the whpk_ form of a signing key's public half.
func PublicKeyOf(k ed25519.PrivateKey) string {
	pub, _ := k.Public().(ed25519.PublicKey)
	return PublicKeyPrefix + base64.StdEncoding.EncodeToString(pub)
}

// KeyID names a key without revealing it: the first 16 hex of its sha256.
func KeyID(key []byte) string {
	s := sha256.Sum256(key)
	return hex.EncodeToString(s[:8])
}

func mac(key []byte, id string, ts int64, body []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = fmt.Fprintf(m, "%s.%d.", id, ts)
	_, _ = m.Write(body)
	return m.Sum(nil)
}

// Signature is the webhook-signature value: one v1 entry per key, so a
// receiver holding either key during a rotation verifies.
func Signature(keys [][]byte, id string, ts int64, body []byte) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, "v1,"+base64.StdEncoding.EncodeToString(mac(k, id, ts, body)))
	}
	return strings.Join(parts, " ")
}

func content(id string, ts int64, body []byte) []byte {
	return append([]byte(fmt.Sprintf("%s.%d.", id, ts)), body...)
}

// SignatureV1a is one v1a entry per ed25519 key.
func SignatureV1a(keys []ed25519.PrivateKey, id string, ts int64, body []byte) string {
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, "v1a,"+base64.StdEncoding.EncodeToString(ed25519.Sign(k, content(id, ts, body))))
	}
	return strings.Join(parts, " ")
}

// SetHeaders signs body and sets the three headers on h.
func SetHeaders(h http.Header, keys [][]byte, id string, now time.Time, body []byte) {
	SetHeadersWith(h, keys, nil, id, now, body)
}

// SetHeadersWith signs body with v1 (HMAC) keys and v1a (ed25519) keys, one
// entry each, so a rotation from one scheme to the other overlaps too.
func SetHeadersWith(h http.Header, keys [][]byte, signing []ed25519.PrivateKey, id string, now time.Time, body []byte) {
	ts := now.Unix()
	h.Set(HeaderID, id)
	h.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	sig := Signature(keys, id, ts, body)
	if v1a := SignatureV1a(signing, id, ts, body); v1a != "" {
		sig = strings.TrimSpace(sig + " " + v1a)
	}
	h.Set(HeaderSignature, sig)
}

// ErrVerify is every verification failure. Callers answer one 401 for all of
// them, so a forger does not learn which check failed; Verify's wrapped
// message is for the receiver's own log.
var ErrVerify = errors.New("webhook signature does not verify")

// Verify checks a delivery against any of keys: the id is present, the
// timestamp is within tolerance (past or future), and at least one v1 entry
// matches under at least one key, compared in constant time. Entries of other
// schemes are ignored, never trusted. It returns the id of the key that matched.
func Verify(h http.Header, body []byte, keys [][]byte, now time.Time, tolerance time.Duration) (string, error) {
	return VerifyWith(h, body, keys, nil, now, tolerance)
}

// VerifyWith is Verify that also accepts v1a entries under any of the
// ed25519 public keys. A v1 entry is checked only against keys, and a v1a
// entry only against public keys, so one scheme's key never stands in for
// the other's.
func VerifyWith(h http.Header, body []byte, keys [][]byte, public []ed25519.PublicKey, now time.Time, tolerance time.Duration) (string, error) {
	id, tsRaw, sig := h.Get(HeaderID), h.Get(HeaderTimestamp), h.Get(HeaderSignature)
	if id == "" || tsRaw == "" || sig == "" {
		return "", fmt.Errorf("%w: missing webhook headers", ErrVerify)
	}
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if err != nil {
		return "", fmt.Errorf("%w: bad timestamp", ErrVerify)
	}
	if tolerance <= 0 {
		tolerance = DefaultTolerance
	}
	if d := now.Sub(time.Unix(ts, 0)); d > tolerance || d < -tolerance {
		return "", fmt.Errorf("%w: timestamp outside %s", ErrVerify, tolerance)
	}
	for _, k := range keys {
		want := mac(k, id, ts, body)
		for _, entry := range strings.Fields(sig) {
			scheme, val, ok := strings.Cut(entry, ",")
			if !ok || scheme != "v1" {
				continue
			}
			got, err := base64.StdEncoding.DecodeString(val)
			if err == nil && hmac.Equal(got, want) {
				return KeyID(k), nil
			}
		}
	}
	for _, k := range public {
		msg := content(id, ts, body)
		for _, entry := range strings.Fields(sig) {
			scheme, val, ok := strings.Cut(entry, ",")
			if !ok || scheme != "v1a" {
				continue
			}
			got, err := base64.StdEncoding.DecodeString(val)
			if err == nil && len(got) == ed25519.SignatureSize && ed25519.Verify(k, msg, got) {
				return KeyID(k), nil
			}
		}
	}
	return "", fmt.Errorf("%w: no v1 or v1a signature matches", ErrVerify)
}
