package backend

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// fakeNotary is Apple's notary API and the S3 bucket it hands out, as one
// TLS test server each.
type fakeNotary struct {
	t       *testing.T
	pub     *ecdsa.PublicKey
	keyID   string
	issuer  string
	bucket  string
	status  []string // answered in turn, the last one repeated
	big     bool     // answer the submission with more than the cap
	mu      sync.Mutex
	sha     string
	put     []byte
	token   string
	secret  string
	polls   int
	api, s3 *httptest.Server
}

func newFakeNotary(t *testing.T, pub *ecdsa.PublicKey) *fakeNotary {
	t.Helper()
	f := &fakeNotary{t: t, pub: pub, keyID: "ABCDE12345", issuer: "57246542-96fe-1a63-e053-0824d011072a", bucket: "notary-submissions-prod",
		status: []string{"In Progress", "Accepted"}, token: hex.EncodeToString(randBytes(t, 16)), secret: hex.EncodeToString(randBytes(t, 20))}
	f.api = httptest.NewTLSServer(http.HandlerFunc(f.serveAPI))
	f.s3 = httptest.NewTLSServer(http.HandlerFunc(f.serveS3))
	t.Cleanup(func() { f.api.Close(); f.s3.Close() })
	old := notaryAt
	notaryAt = notaryEndpoints{API: f.api.URL + "/notary/v2", S3: func(string) string { return f.s3.URL },
		Client: f.api.Client(), Upload: f.s3.Client(), Poll: time.Millisecond, Wait: 5 * time.Second}
	t.Cleanup(func() { notaryAt = old })
	return f
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// checkJWT verifies the App Store Connect token: ES256 by the key, its key
// id, issuer and audience, and a lifetime within Apple's 20 minutes.
func (f *fakeNotary) checkJWT(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(tok, ".")
	if !ok || len(parts) != 3 {
		return false
	}
	var hdr struct{ Alg, Kid, Typ string }
	var claims struct {
		Iss string `json:"iss"`
		Aud string `json:"aud"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	h, _ := base64.RawURLEncoding.DecodeString(parts[0])
	c, _ := base64.RawURLEncoding.DecodeString(parts[1])
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	if json.Unmarshal(h, &hdr) != nil || json.Unmarshal(c, &claims) != nil || len(sig) != 64 {
		return false
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	rr, ss := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(f.pub, sum[:], rr, ss) && hdr.Alg == "ES256" && hdr.Kid == f.keyID && hdr.Typ == "JWT" &&
		claims.Iss == f.issuer && claims.Aud == "appstoreconnect-v1" && claims.Exp > claims.Iat && claims.Exp-claims.Iat <= 20*60
}

func (f *fakeNotary) serveAPI(w http.ResponseWriter, r *http.Request) {
	if !f.checkJWT(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == "POST" && r.URL.Path == "/notary/v2/submissions":
		var req struct {
			SHA256 string `json:"sha256"`
			Name   string `json:"submissionName"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.SHA256) != 64 || req.Name == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		f.sha = req.SHA256
		if f.big {
			_, _ = w.Write(bytes.Repeat([]byte(" "), 2<<20))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "sub-1", "type": "submissionsPostResponses",
			"attributes": map[string]any{"awsAccessKeyId": "ASIAFAKEKEY", "awsSecretAccessKey": f.secret, "awsSessionToken": f.token,
				"bucket": f.bucket, "object": "prefix/sub-1.zip"}}})
	case r.Method == "GET" && r.URL.Path == "/notary/v2/submissions/sub-1":
		st := f.status[min(f.polls, len(f.status)-1)]
		f.polls++
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "sub-1", "attributes": map[string]any{"status": st, "name": "x"}}})
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeNotary) serveS3(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	sum := sha256.Sum256(body)
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != "PUT" || r.URL.Path != "/prefix/sub-1.zip" || r.Header.Get("X-Amz-Security-Token") != f.token ||
		r.Header.Get("X-Amz-Content-Sha256") != hex.EncodeToString(sum[:]) || hex.EncodeToString(sum[:]) != f.sha ||
		!strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=ASIAFAKEKEY/") ||
		!strings.Contains(r.Header.Get("Authorization"), "/us-west-2/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	f.put = body
}

// ascKey is an App Store Connect API key (.p8, PKCS#8 PEM) made at run time.
func ascKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return k, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func notaryApple(t *testing.T, keyPEM string, f *fakeNotary) *Apple {
	t.Helper()
	h := fakeHost("linux", execx.NewFake(), map[string]string{"ASC_KEY": keyPEM, "ASC_ISSUER": f.issuer})
	return &Apple{H: h, Spec: profile.MacOSSpec{Kind: "developer-id", TeamID: "TEAM123456", Identity: "x", CertRef: "env://P12",
		Notary: &profile.NotarySpec{APIKeyRef: "env://ASC_KEY", KeyID: f.keyID, Issuer: "env://ASC_ISSUER"}}}
}

func notaryFiles(t *testing.T) []Artifact {
	t.Helper()
	dir := t.TempDir()
	var out []Artifact
	for i, name := range []string{"a/tool", "b/tool"} {
		p := filepath.Join(dir, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		if err := os.WriteFile(p, []byte{byte(i), 1, 2, 3}, 0o600); err != nil {
			t.Fatal(err)
		}
		out = append(out, Artifact{Path: p, Rel: name})
	}
	return out
}

// O-140 (ID-36): off a Mac, impr notarises through Apple's notary API with
// its own client: a submission under an ES256 token made in memory from the
// App Store Connect key, the zip uploaded to the S3 bucket Apple names with
// SigV4 and the session token, and the status polled until Accepted.
func TestNotaryOffAMacSubmitsUploadsAndWaits(t *testing.T) {
	k, keyPEM := ascKey(t)
	f := newFakeNotary(t, &k.PublicKey)
	a := notaryApple(t, keyPEM, f)
	files := notaryFiles(t)
	id, err := a.Notarize(context.Background(), files)
	if err != nil {
		t.Fatal(err)
	}
	if id != "sub-1" || f.polls < 2 {
		t.Fatalf("id %q after %d polls", id, f.polls)
	}
	z, err := zip.NewReader(bytes.NewReader(f.put), int64(len(f.put)))
	if err != nil || len(z.File) != 2 {
		t.Fatalf("the upload is not a zip of both files: %v", err)
	}
}

// Refusals: a bucket that is not Apple's notary bucket is never uploaded to;
// an answer over the size cap is refused; a rejected submission fails the
// run; no message carries the key or the session secret.
func TestNotaryOffAMacRefuses(t *testing.T) {
	k, keyPEM := ascKey(t)
	for name, edit := range map[string]func(*fakeNotary){
		"another bucket":      func(f *fakeNotary) { f.bucket = "attacker-bucket" },
		"an oversized answer": func(f *fakeNotary) { f.big = true },
		"rejected":            func(f *fakeNotary) { f.status = []string{"Invalid"} },
	} {
		f := newFakeNotary(t, &k.PublicKey)
		edit(f)
		_, err := notaryApple(t, keyPEM, f).Notarize(context.Background(), notaryFiles(t))
		if err == nil {
			t.Errorf("%s: notarised", name)
			continue
		}
		if contract.CodeOf(err) == contract.OK || strings.Contains(err.Error(), f.secret) || strings.Contains(err.Error(), "PRIVATE KEY") {
			t.Errorf("%s: %v", name, err)
		}
		if want := map[string]string{"another bucket": "not Apple's notary bucket", "an oversized answer": "more than", "rejected": "not accepted"}[name]; !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want it to say %q", name, err, want)
		}
		if name != "rejected" && f.put != nil {
			t.Errorf("%s: uploaded", name)
		}
	}
}

// The production endpoints are pinned: Apple's notary API, and the S3 host of
// a bucket the API names, on HTTPS in us-west-2.
func TestNotaryHostsArePinned(t *testing.T) {
	if notaryAt.API != "https://appstoreconnect.apple.com/notary/v2" || notaryAt.S3("notary-submissions-prod") != "https://notary-submissions-prod.s3.us-west-2.amazonaws.com" {
		t.Fatalf("endpoints %q %q", notaryAt.API, notaryAt.S3("notary-submissions-prod"))
	}
	if notaryAt.Client.Timeout == 0 || notaryAt.Upload.Timeout == 0 || notaryAt.Client.CheckRedirect == nil {
		t.Fatal("a notary client has no timeout, or follows redirects")
	}
	for _, b := range []string{"attacker", "notary-submissions-prod.evil.com", "notary-submissions-", "x.notary-submissions-prod"} {
		if appleBucket(b) {
			t.Errorf("%q passed as Apple's bucket", b)
		}
	}
}

// SigV4 is checked against AWS's own published example (Signature Version 4,
// "Example: GET Object"), not against itself.
func TestSigV4MatchesAWSExample(t *testing.T) {
	at := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	hdr := map[string]string{"host": "examplebucket.s3.amazonaws.com", "range": "bytes=0-9",
		"x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "x-amz-date": "20130524T000000Z"}
	// @credential-literal-exempt: AWS's published SigV4 example key pair, which proves exact bytes
	got := sigV4("GET", "/test.txt", hdr, hdr["x-amz-content-sha256"], "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-1", "s3", at)
	want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
	if strings.ReplaceAll(got, ", ", ",") != want {
		t.Fatalf("\ngot  %s\nwant %s", got, want)
	}
}
