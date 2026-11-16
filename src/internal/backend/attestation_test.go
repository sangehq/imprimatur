package backend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
	"github.com/sangehq/imprimatur/src/internal/secrets"
)

type intotoFixture struct {
	dir, sums string
	be        Backend
	p         profile.Profile
	art       Artifact
	h         Host
	otherFP   string
}

func newIntoto(t *testing.T) intotoFixture {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("real ssh-keygen: not installed")
	}
	dir := t.TempDir()
	key, fp := sshKey(t, dir, "release")
	other, otherFP := sshKey(t, dir, "other")
	if err := os.MkdirAll(filepath.Join(dir, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	var lines string
	for _, f := range []string{"build/tool", "build/tool.exe"} {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(randHex(t, 16)), 0o600); err != nil {
			t.Fatal(err)
		}
		lines += randHex(t, 32) + "  " + f + "\n"
	}
	sums := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(sums, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"IMPR_SSH_KEY": key, "IMPR_OTHER_KEY": other}
	h := Host{GOOS: runtime.GOOS, Runner: execx.OS{Timeout: time.Minute}, Now: time.Now,
		Secrets: secrets.Resolver{Getenv: func(k string) string { return env[k] }}}
	p := profile.Profile{Name: "acme-release", Platforms: profile.Platforms{
		Checksums:    &profile.ChecksumSpec{Kind: "ssh", KeyRef: "env://IMPR_SSH_KEY", Fingerprint: fp},
		Attestations: &profile.AttestationSpec{Kind: "in-toto", Signer: "checksums"}}}
	be, err := For(h, p, profile.Attestations)
	if err != nil {
		t.Fatal(err)
	}
	build := &Build{Repo: "https://github.com/acme/tool", Commit: randHex(t, 20), Tree: randHex(t, 20), ManifestDigest: "sha256:" + randHex(t, 32)}
	return intotoFixture{dir: dir, sums: sums, be: be, p: p, h: h, otherFP: otherFP,
		art: Artifact{Path: sums, Rel: "SHA256SUMS", Build: build}}
}

func readEnvelope(t *testing.T, path string) (Envelope, Statement) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(env.Payload)
	var st Statement
	if err := json.Unmarshal(payload, &st); err != nil {
		t.Fatal(err)
	}
	return env, st
}

func TestInTotoSignsEveryChecksumEntryWithProvenance(t *testing.T) {
	f := newIntoto(t)
	ctx := context.Background()
	if c := f.be.Capability(f.h); !c.Supported || !c.Sign || c.Kind != "in-toto" {
		t.Fatalf("capability %+v", c)
	}
	sig, err := f.be.Sign(ctx, f.art, f.p)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig.Outputs) != 1 || sig.Outputs[0].Path != f.sums+AttestationExt || sig.Kind != "in-toto" {
		t.Fatalf("signature %+v", sig)
	}
	env, st := readEnvelope(t, f.sums+AttestationExt)
	if env.PayloadType != PayloadType || len(env.Signatures) != 1 || !strings.HasPrefix(env.Signatures[0].KeyID, "checksums:SHA256:") {
		t.Fatalf("envelope %+v", env)
	}
	if st.Type != StatementType || st.PredicateType != ProvenanceType || len(st.Subject) != 2 || st.Subject[1].Name != "build/tool.exe" {
		t.Fatalf("statement %+v", st)
	}
	ext := st.Predicate.BuildDefinition.ExternalParameters
	if ext["commit"] != f.art.Build.Commit || ext["repository"] != f.art.Build.Repo || st.Predicate.RunDetails.Builder.ID != BuilderID {
		t.Fatalf("provenance %+v", st.Predicate)
	}
	if err := f.be.Verify(ctx, f.art, f.p); err != nil {
		t.Fatalf("a fresh attestation must verify: %v", err)
	}
}

func TestInTotoRefuses(t *testing.T) {
	ctx := context.Background()
	t.Run("no build", func(t *testing.T) {
		f := newIntoto(t)
		f.art.Build = nil
		_, err := f.be.Sign(ctx, f.art, f.p)
		wantCode(t, err, contract.SignFailed)
	})
	t.Run("checksum file changed", func(t *testing.T) {
		f := newIntoto(t)
		if _, err := f.be.Sign(ctx, f.art, f.p); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f.sums, []byte(randHex(t, 32)+"  build/tool\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		wantCode(t, f.be.Verify(ctx, f.art, f.p), contract.VerifyFailed)
	})
	t.Run("statement edited", func(t *testing.T) {
		f := newIntoto(t)
		if _, err := f.be.Sign(ctx, f.art, f.p); err != nil {
			t.Fatal(err)
		}
		env, st := readEnvelope(t, f.sums+AttestationExt)
		st.Predicate.BuildDefinition.ExternalParameters["commit"] = randHex(t, 20)
		payload, _ := json.Marshal(st)
		env.Payload = base64.StdEncoding.EncodeToString(payload)
		b, _ := json.Marshal(env)
		if err := os.WriteFile(f.sums+AttestationExt, b, 0o600); err != nil {
			t.Fatal(err)
		}
		wantCode(t, f.be.Verify(ctx, f.art, f.p), contract.VerifyFailed)
	})
	t.Run("another build", func(t *testing.T) {
		f := newIntoto(t)
		if _, err := f.be.Sign(ctx, f.art, f.p); err != nil {
			t.Fatal(err)
		}
		b := *f.art.Build
		b.Commit = randHex(t, 20)
		f.art.Build = &b
		err := f.be.Verify(ctx, f.art, f.p)
		wantCode(t, err, contract.VerifyFailed)
		if !strings.Contains(err.Error(), "attests commit") {
			t.Fatalf("want the commit mismatch, got %v", err)
		}
	})
	t.Run("another pinned key", func(t *testing.T) {
		f := newIntoto(t)
		if _, err := f.be.Sign(ctx, f.art, f.p); err != nil {
			t.Fatal(err)
		}
		q := f.p
		c := *q.Platforms.Checksums
		c.Fingerprint = f.otherFP
		q.Platforms.Checksums = &c
		be, err := For(f.h, q, profile.Attestations)
		if err != nil {
			t.Fatal(err)
		}
		wantCode(t, be.Verify(ctx, f.art, q), contract.VerifyFailed)
	})
	t.Run("checksum-file signature passed off as an attestation", func(t *testing.T) {
		// A signature over SHA256SUMS in the "file" namespace must not verify
		// as an attestation: PAE and the in-toto namespace separate them.
		f := newIntoto(t)
		s := &SSH{H: f.h, Spec: *f.p.Platforms.Checksums}
		if _, err := s.Sign(ctx, Artifact{Path: f.sums, Rel: "SHA256SUMS"}, f.p); err != nil {
			t.Fatal(err)
		}
		raw, _ := os.ReadFile(f.sums + ".sig")
		st := NewStatement([][2]string{}, *f.art.Build)
		payload, _ := json.Marshal(st)
		env := Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(payload),
			Signatures: []EnvelopeEntry{{KeyID: "checksums:x", Sig: base64.StdEncoding.EncodeToString(raw)}}}
		b, _ := json.Marshal(env)
		if err := os.WriteFile(f.sums+AttestationExt, b, 0o600); err != nil {
			t.Fatal(err)
		}
		wantCode(t, f.be.Verify(ctx, f.art, f.p), contract.VerifyFailed)
	})
}

func TestPAE(t *testing.T) {
	// The DSSE specification's own example.
	if got := string(PAE("http://example.com/HelloWorld", []byte("hello world"))); got != "DSSEv1 29 http://example.com/HelloWorld 11 hello world" {
		t.Fatalf("PAE %q", got)
	}
}

func TestInTotoNeedsItsSigner(t *testing.T) {
	_, err := For(Host{}, profile.Profile{Platforms: profile.Platforms{Attestations: &profile.AttestationSpec{Kind: "in-toto", Signer: "cosign"}}}, profile.Attestations)
	wantCode(t, err, contract.Usage)
}
