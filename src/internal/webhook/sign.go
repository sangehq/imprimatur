// Package webhook delivers imprimatur's events to other apps and checks
// deliveries other apps send it, in the Standard Webhooks 1.0 shape the estate
// uses (sange webhooks-and-events.md §5–§6): headers webhook-id,
// webhook-timestamp and webhook-signature, signed content "id.timestamp.body",
// "v1,<base64 HMAC-SHA256>" entries, secrets "whsec_<base64>" of 24 to 64
// random bytes, several signatures during a rotation, constant-time compare.
package webhook

import (
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

// SetHeaders signs body and sets the three headers on h.
func SetHeaders(h http.Header, keys [][]byte, id string, now time.Time, body []byte) {
	ts := now.Unix()
	h.Set(HeaderID, id)
	h.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	h.Set(HeaderSignature, Signature(keys, id, ts, body))
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
	return "", fmt.Errorf("%w: no v1 signature matches", ErrVerify)
}
