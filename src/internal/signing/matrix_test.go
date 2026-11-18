package signing

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/backend"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
	"github.com/sangehq/imprimatur/src/internal/secrets"
)

// Owner, 2026-11-18: test certificates, Certum (SimplySign) and Azure
// Artifact Signing are each configurable for test and for release signing.
// Real Certum and Artifact Signing credentials are not available, so each
// combination is proven by validation and a dry run on a fake Windows host:
// the plan names the backend's own signtool or osslsigncode arguments, signs
// nothing, and writes no record.
func TestEveryWindowsBackendSignsForTestAndRelease(t *testing.T) {
	const thumb = "0123456789ABCDEF0123456789ABCDEF01234567"
	notAfter := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	dlib, meta := filepath.Join(dir, "Azure.CodeSigning.Dlib.dll"), filepath.Join(dir, "metadata.json")
	for _, f := range []string{dlib, meta} {
		body := "{}"
		if f == meta {
			body = `{"Endpoint":"https://weu.codesigning.azure.net","CodeSigningAccountName":"acme","CertificateProfileName":"acme-public"}`
		}
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	specs := map[string]profile.WindowsSpec{
		profile.BackendPFX:       {Kind: "authenticode", Backend: profile.BackendPFX, CertRef: "env://IMPR_TEST_PFX", PasswordRef: "env://IMPR_TEST_PFX_PASS", Thumbprint: thumb, NotAfter: &notAfter},
		profile.BackendCertStore: {Kind: "authenticode", Backend: profile.BackendCertStore, Thumbprint: thumb, NotAfter: &notAfter},
		profile.BackendCertum:    {Kind: "authenticode", Backend: profile.BackendCertum, Thumbprint: thumb, Subject: "CN=Acme Ltd", NotAfter: &notAfter},
		profile.BackendAzure:     {Kind: "authenticode", Backend: profile.BackendAzure, Subject: "CN=Acme Ltd", DlibPath: dlib, MetadataPath: meta},
	}
	want := map[string][]string{
		profile.BackendPFX:       {"osslsigncode", "-pkcs12", "env://IMPR_TEST_PFX", "-readpass", "env://IMPR_TEST_PFX_PASS"},
		profile.BackendCertStore: {"signtool", "/sha1", thumb},
		profile.BackendCertum:    {"signtool", "/sha1", thumb},
		profile.BackendAzure:     {"signtool", "/dlib", dlib, "/dmdf", meta},
	}
	if len(specs) != len(profile.WindowsBackends()) {
		t.Fatalf("the matrix covers %d backends; impr has %d", len(specs), len(profile.WindowsBackends()))
	}
	for _, be := range profile.WindowsBackends() {
		for _, purpose := range []profile.Purpose{profile.PurposeTest, profile.PurposeRelease} {
			t.Run(be+"/"+string(purpose), func(t *testing.T) {
				rel := "build/windows/tool_amd64.exe"
				svc, _, root, manifest := setupMulti(t, map[string]uint16{rel: 0x8664})
				p := profile.Profile{Name: "win", Scope: profile.ScopePersonal, Owner: "me", Purpose: []profile.Purpose{purpose},
					AllowedRepos: []string{"github.com/acme/tool"}, Platforms: profile.Platforms{Windows: ptr(specs[be])}}
				if err := svc.Store.Save(p, true); err != nil {
					t.Fatalf("a %s %s profile does not save: %v", purpose, be, err)
				}
				f := execx.NewFake("signtool", "osslsigncode", "certutil", "az")
				env := map[string]string{"IMPR_TEST_PFX": base64.StdEncoding.EncodeToString([]byte(randomName(t))), "IMPR_TEST_PFX_PASS": randomName(t)}
				get := func(k string) string { return env[k] }
				svc.Host = backend.Host{GOOS: "windows", Runner: f, Now: svc.Host.Now, Secrets: secrets.Resolver{Runner: f, Getenv: get, GOOS: "windows"}}
				svc.BackendFor = nil // the real Authenticode backend
				o := SignOptions{Root: root, Manifest: manifest, Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40),
					Profile: "win", Purpose: string(purpose), Platforms: []string{"windows"}, DryRun: true}
				if purpose == profile.PurposeRelease {
					o.Repo = "git@github.com:acme/tool.git"
				}
				res, err := svc.Sign(context.Background(), o)
				if err != nil || !res.DryRun || len(res.Plan) != 1 {
					t.Fatalf("dry run: %+v %v", res, err)
				}
				st := res.Plan[0]
				if st.Backend != be || !st.Ready || !slices.Equal(st.Files, []string{rel}) {
					t.Fatalf("plan: %+v", st)
				}
				for _, w := range want[be] {
					if !slices.Contains(st.Command, w) {
						t.Errorf("command %v lacks %q", st.Command, w)
					}
				}
				for _, c := range f.Calls {
					if (c.Tool == "signtool" || c.Tool == "osslsigncode") && len(c.Args) > 0 && c.Args[0] == "sign" {
						t.Fatalf("a dry run signed: %s %v", c.Tool, c.Args)
					}
				}
				if _, err := os.Stat(filepath.Join(root, ManifestFile)); !os.IsNotExist(err) {
					t.Fatalf("a dry run wrote the signed record: %v", err)
				}
			})
		}
	}
}

func ptr[T any](v T) *T { return &v }

// randomName is a throwaway value for a credential the fake host never uses.
func randomName(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}
