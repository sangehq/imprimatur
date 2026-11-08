package rules

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/contract"
)

func rh(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func request(t *testing.T) Request {
	t.Helper()
	return Request{Contract: 1, ManifestDigest: "sha256:" + rh(t, 32), Version: "v1.8.0", FileVersion: "1.8.0.0",
		Publisher: Publisher{Subject: "O=ACME LTD, L=LONDON, C=GB", LeafCN: "Acme Ltd", IssuerName: "Acme CA", IssuerTBS: strings.ToUpper(rh(t, 32)),
			EKU: "1.3.6.1.4.1.311.97.1.0", Product: "tool"},
		Files: []File{
			{Path: "build/windows/tool_amd64.exe", SHA256: rh(t, 32), Collection: Exe, BinaryName: "tool.exe"},
			{Path: "build/windows/tool_arm64.exe", SHA256: rh(t, 32), Collection: Exe, BinaryName: "tool.exe"},
			{Path: "build/windows/helper.dll", SHA256: rh(t, 32), Collection: Dll, BinaryName: "helper.dll"},
		},
		Options: Options{Name: "tool", BasePolicyID: "{A244370E-44C9-4C06-B551-F6016E563076}", AppLocker: true, WDAC: true}}
}

func TestRenderIsDeterministicSupplementalAndHashFree(t *testing.T) {
	req := request(t)
	a, err := Render(req, "imprimatur test")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Render(req, "imprimatur test")
	if a.AppLocker != b.AppLocker || a.WDAC != b.WDAC {
		t.Fatal("the same request rendered different bytes")
	}
	for _, doc := range []string{a.AppLocker, a.WDAC} {
		if err := xml.Unmarshal([]byte(doc), new(struct{})); err != nil {
			t.Fatalf("not XML: %v", err)
		}
		for _, banned := range []string{"FileHashRule", "Hash=", "FileHash"} {
			if strings.Contains(doc, banned) {
				t.Fatalf("a file-hash rule was rendered (%s)", banned)
			}
		}
	}
	if !strings.Contains(a.WDAC, `PolicyType="Supplemental Policy"`) || strings.Contains(a.WDAC, "Base Policy") {
		t.Fatal("the WDAC policy is not supplemental")
	}
	if strings.Count(a.AppLocker, "<FilePublisherRule") != 2 || !strings.Contains(a.AppLocker, `LowSection="1.8.0.0"`) {
		t.Fatalf("one rule per binary name and collection, from the release version:\n%s", a.AppLocker)
	}
	if !strings.Contains(a.WDAC, "<CertEKU") || !strings.Contains(a.WDAC, `Type="TBS"`) {
		t.Fatal("the EKU is not pinned")
	}
	if len(a.Files) != 3 || a.ManifestDigest != req.ManifestDigest {
		t.Fatal("the answer does not name the request's files and manifest")
	}
}

func TestRenderRefusesABadRequest(t *testing.T) {
	cases := map[string]func(r *Request){
		"no files":              func(r *Request) { r.Files = nil },
		"a non-Windows file":    func(r *Request) { r.Files[0].Path = "build/linux/tool" },
		"a wrong collection":    func(r *Request) { r.Files[2].Collection = Exe },
		"no base policy":        func(r *Request) { r.Options.BasePolicyID = "" },
		"a bad digest":          func(r *Request) { r.ManifestDigest = "md5:x" },
		"another contract":      func(r *Request) { r.Contract = 2 },
		"a missing subject":     func(r *Request) { r.Publisher.Subject = "" },
		"a bad TBS":             func(r *Request) { r.Publisher.IssuerTBS = "xyz" },
		"a duplicated file":     func(r *Request) { r.Files[1].Path = r.Files[0].Path },
		"a non-numeric version": func(r *Request) { r.FileVersion = "v1" },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			r := request(t)
			edit(&r)
			if _, err := Render(r, "x"); contract.CodeOf(err) != contract.Usage {
				t.Fatalf("want a usage error, got %v", err)
			}
		})
	}
}

func TestEKUValue(t *testing.T) {
	v, err := EKUValue("1.3.6.1.5.5.7.3.3")
	if err != nil || v != "01082B06010505070303" {
		t.Fatalf("%q %v", v, err)
	}
}
