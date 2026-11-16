package webhook

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestV1aRoundTripAndRefusals(t *testing.T) {
	sk, pk, err := NewSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := DecodeSigningKey(sk)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := DecodePublicKey(pk)
	if err != nil || PublicKeyOf(priv) != pk {
		t.Fatalf("public key %q (%v), derived %q", pk, err, PublicKeyOf(priv))
	}
	now := time.Unix(1700000000, 0)
	body := []byte(`{"type":"sh.sange.imprimatur.signing.run.completed"}`)
	h := http.Header{}
	SetHeadersWith(h, nil, []ed25519.PrivateKey{priv}, "id-1", now, body)
	if !strings.HasPrefix(h.Get(HeaderSignature), "v1a,") {
		t.Fatalf("signature %q", h.Get(HeaderSignature))
	}
	if kid, err := VerifyWith(h, body, nil, []ed25519.PublicKey{pub}, now, 0); err != nil || kid != KeyID(pub) {
		t.Fatalf("v1a verify: %q %v", kid, err)
	}

	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	hmacKey := []byte("an hmac key that must not stand in")
	for name, check := range map[string]func() error{
		"wrong public key": func() error { _, err := VerifyWith(h, body, nil, []ed25519.PublicKey{otherPub}, now, 0); return err },
		"changed body":     func() error { _, err := VerifyWith(h, []byte(`{}`), nil, []ed25519.PublicKey{pub}, now, 0); return err },
		"stale": func() error {
			_, err := VerifyWith(h, body, nil, []ed25519.PublicKey{pub}, now.Add(6*time.Minute), 0)
			return err
		},
		// A v1a entry is never checked as HMAC, and plain Verify knows no v1a.
		"hmac key only": func() error { _, err := VerifyWith(h, body, [][]byte{hmacKey}, nil, now, 0); return err },
		"plain Verify":  func() error { _, err := Verify(h, body, [][]byte{hmacKey}, now, 0); return err },
	} {
		if check() == nil {
			t.Errorf("%s verified", name)
		}
	}

	// A v1 delivery is not accepted by a public key alone.
	v1 := http.Header{}
	SetHeaders(v1, [][]byte{hmacKey}, "id-2", now, body)
	if _, err := VerifyWith(v1, body, nil, []ed25519.PublicKey{pub}, now, 0); err == nil {
		t.Error("a v1 signature verified under a public key")
	}

	// Moving from v1 to v1a overlaps: both entries, either receiver verifies.
	both := http.Header{}
	SetHeadersWith(both, [][]byte{hmacKey}, []ed25519.PrivateKey{priv}, "id-3", now, body)
	if n := len(strings.Fields(both.Get(HeaderSignature))); n != 2 {
		t.Fatalf("%d entries during a scheme rotation", n)
	}
	if _, err := Verify(both, body, [][]byte{hmacKey}, now, 0); err != nil {
		t.Errorf("the v1 receiver: %v", err)
	}
	if _, err := VerifyWith(both, body, nil, []ed25519.PublicKey{pub}, now, 0); err != nil {
		t.Errorf("the v1a receiver: %v", err)
	}
}

func TestDecodeV1aKeys(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	seed := SigningKeyPrefix + base64.StdEncoding.EncodeToString(priv.Seed())
	if k, err := DecodeSigningKey(seed); err != nil || !k.Equal(priv) {
		t.Fatalf("a 32-byte seed: %v", err)
	}
	mismatched := append(append([]byte{}, priv.Seed()...), make([]byte, 32)...)
	for name, s := range map[string]string{
		"no prefix":         base64.StdEncoding.EncodeToString(priv),
		"hmac prefix":       SecretPrefix + base64.StdEncoding.EncodeToString(priv),
		"not base64":        SigningKeyPrefix + "!!!",
		"short":             SigningKeyPrefix + base64.StdEncoding.EncodeToString(priv[:16]),
		"public half wrong": SigningKeyPrefix + base64.StdEncoding.EncodeToString(mismatched),
	} {
		if _, err := DecodeSigningKey(s); err == nil {
			t.Errorf("signing key %s accepted", name)
		}
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	for name, s := range map[string]string{
		"signing key": SigningKeyPrefix + base64.StdEncoding.EncodeToString(pub),
		"short":       PublicKeyPrefix + base64.StdEncoding.EncodeToString(pub[:16]),
	} {
		if _, err := DecodePublicKey(s); err == nil {
			t.Errorf("public key %s accepted", name)
		}
	}
}
