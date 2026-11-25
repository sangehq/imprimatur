package backend

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/secrets"
)

// impr's own client for Apple's notary API (design ID-36, threat I-25), used
// off a Mac in place of notarytool: create a submission, upload the zip to
// the S3 bucket Apple names, poll until Apple decides. Standard library only:
// the token is an ES256 JWT made in memory from the App Store Connect key,
// and the upload is signed with AWS Signature Version 4 under the short-lived
// session credentials the submission returns.

// notaryEndpoints are where the client goes. Production pins them; a test
// points them at its own servers.
type notaryEndpoints struct {
	API    string                     // Apple's notary API, .../notary/v2
	S3     func(bucket string) string // the upload base URL for an Apple bucket
	Client *http.Client               // API calls
	Upload *http.Client               // the S3 upload
	Poll   time.Duration              // between status checks
	Wait   time.Duration              // how long to wait for Apple's verdict
}

// noRedirect keeps a call on the host it was sent to.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

var notaryAt = notaryEndpoints{
	API:    "https://appstoreconnect.apple.com/notary/v2",
	S3:     func(bucket string) string { return "https://" + bucket + ".s3.us-west-2.amazonaws.com" },
	Client: &http.Client{Timeout: 60 * time.Second, CheckRedirect: noRedirect},
	Upload: &http.Client{Timeout: 30 * time.Minute, CheckRedirect: noRedirect},
	Poll:   15 * time.Second,
	Wait:   60 * time.Minute,
}

// maxNotaryAnswer caps every API answer the client reads.
const maxNotaryAnswer = 1 << 20

// appleBucketRe is Apple's notary submissions bucket (notary-submissions-prod
// as of 2026-11-25); anything else is never uploaded to.
var appleBucketRe = regexp.MustCompile(`^notary-submissions-[a-z0-9][a-z0-9-]{0,40}$`)

func appleBucket(b string) bool { return appleBucketRe.MatchString(b) }

// objectRe is the key Apple names inside its bucket.
var objectRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,500}$`)

// notarizeOffMac zips the signed files, submits them and waits for Apple's
// verdict. It returns the submission id. Apple keeps the ticket online: a
// bare Mach-O cannot be stapled, and a .dmg or .pkg is stapled on a Mac only.
func (a *Apple) notarizeOffMac(ctx context.Context, files []Artifact) (string, error) {
	n := a.Spec.Notary
	for _, f := range files {
		if ext := strings.ToLower(filepath.Ext(f.Path)); ext == ".dmg" || ext == ".pkg" {
			return "", contract.New(contract.Unavailable, "%s needs its ticket stapled, which only a Mac can do", f.Rel)
		}
	}
	keyText, err := a.H.Secrets.Resolve(ctx, n.APIKeyRef)
	if err != nil {
		return "", err
	}
	keyPEM, err := secrets.AsBytes(keyText, false)
	if err != nil {
		return "", err
	}
	key, err := ascPrivateKey(keyPEM)
	if err != nil {
		return "", err
	}
	keyID, err := a.literalOrRef(ctx, n.KeyID)
	if err != nil {
		return "", err
	}
	issuer, err := a.literalOrRef(ctx, n.Issuer)
	if err != nil {
		return "", err
	}
	if keyID == "" || issuer == "" {
		return "", contract.New(contract.Usage, "notarisation off a Mac needs notary.keyId and notary.issuer")
	}
	body, err := zipFiles(files)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	c := notaryClient{at: notaryAt, key: key, keyID: keyID, issuer: issuer, now: a.H.Now}
	if c.now == nil {
		c.now = time.Now
	}
	sub, err := c.submit(ctx, hex.EncodeToString(sum[:]), fmt.Sprintf("impr-%d.zip", c.now().Unix()))
	if err != nil {
		return "", err
	}
	if err := c.upload(ctx, sub, body, hex.EncodeToString(sum[:])); err != nil {
		return "", err
	}
	return sub.ID, c.wait(ctx, sub.ID)
}

// ascPrivateKey reads an App Store Connect .p8 key: PKCS#8 PEM, ECDSA P-256.
func ascPrivateKey(b []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, contract.New(contract.Usage, "the App Store Connect key is not a PEM .p8 key")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, contract.New(contract.Usage, "the App Store Connect key cannot be read")
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, contract.New(contract.Usage, "the App Store Connect key is not an ECDSA key")
	}
	return ek, nil
}

// zipFiles puts each file in its own folder, so two files of one name are
// both submitted, as the Mac path does.
func zipFiles(files []Artifact) ([]byte, error) {
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	for i, f := range files {
		b, err := os.ReadFile(f.Path)
		if err != nil {
			return nil, err
		}
		h := &zip.FileHeader{Name: fmt.Sprintf("%03d/%s", i, filepath.Base(f.Path)), Method: zip.Deflate}
		h.SetMode(0o755)
		w, err := z.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(b); err != nil {
			return nil, err
		}
	}
	if err := z.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type notaryClient struct {
	at            notaryEndpoints
	key           *ecdsa.PrivateKey
	keyID, issuer string
	now           func() time.Time
}

type notarySubmission struct {
	ID                                 string
	AccessKey, SecretKey, SessionToken string
	Bucket, Object                     string
}

// token is App Store Connect's ES256 JWT, valid for 15 minutes (Apple allows
// 20), made for each call so a long wait never outlives it.
func (c notaryClient) token() (string, error) {
	now := c.now()
	hdr, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": c.keyID, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{"iss": c.issuer, "iat": now.Unix(), "exp": now.Add(15 * time.Minute).Unix(), "aud": "appstoreconnect-v1"})
	signing := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, c.key, sum[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// call makes one API request and decodes its answer, read to at most
// maxNotaryAnswer bytes.
func (c notaryClient) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.at.API+path, body)
	if err != nil {
		return err
	}
	tok, err := c.token()
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.at.Client.Do(req)
	if err != nil {
		return contract.Wrap(contract.Unavailable, redactURL(err), "Apple's notary service could not be reached")
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxNotaryAnswer+1))
	if err != nil {
		return contract.Wrap(contract.Unavailable, err, "Apple's notary service answer could not be read")
	}
	if len(b) > maxNotaryAnswer {
		return contract.New(contract.Unavailable, "Apple's notary service answered more than %d bytes; refused", maxNotaryAnswer)
	}
	if resp.StatusCode/100 != 2 {
		return contract.New(contract.SignFailed, "Apple's notary service answered %d to %s %s", resp.StatusCode, method, path).
			WithFix("check notary.keyId, notary.issuer and that the key may notarise (App Store Connect, Users and Access, Integrations)")
	}
	if err := json.Unmarshal(b, out); err != nil {
		return contract.New(contract.Unavailable, "Apple's notary service answer is not the JSON it documents")
	}
	return nil
}

// redactURL keeps a transport error from carrying query strings.
func redactURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %s: %w", ue.Op, strings.SplitN(ue.URL, "?", 2)[0], ue.Err)
	}
	return err
}

func (c notaryClient) submit(ctx context.Context, sha, name string) (notarySubmission, error) {
	var out struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				AccessKey    string `json:"awsAccessKeyId"`
				SecretKey    string `json:"awsSecretAccessKey"`
				SessionToken string `json:"awsSessionToken"`
				Bucket       string `json:"bucket"`
				Object       string `json:"object"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := c.call(ctx, http.MethodPost, "/submissions", map[string]string{"sha256": sha, "submissionName": name}, &out); err != nil {
		return notarySubmission{}, err
	}
	at := out.Data.Attributes
	s := notarySubmission{ID: out.Data.ID, AccessKey: at.AccessKey, SecretKey: at.SecretKey, SessionToken: at.SessionToken, Bucket: at.Bucket, Object: at.Object}
	switch {
	case !regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`).MatchString(s.ID):
		return s, contract.New(contract.Unavailable, "Apple's notary service named no usable submission id")
	case !appleBucket(s.Bucket):
		return s, contract.New(contract.Unavailable, "Apple's notary service named bucket %q, which is not Apple's notary bucket; nothing was uploaded", s.Bucket)
	case !objectRe.MatchString(s.Object) || strings.Contains(s.Object, ".."):
		return s, contract.New(contract.Unavailable, "Apple's notary service named an object key impr will not use; nothing was uploaded")
	case s.AccessKey == "" || s.SecretKey == "" || s.SessionToken == "":
		return s, contract.New(contract.Unavailable, "Apple's notary service gave no upload credentials")
	}
	return s, nil
}

// upload PUTs the zip to Apple's bucket, signed with SigV4 under the
// submission's session credentials.
func (c notaryClient) upload(ctx context.Context, s notarySubmission, body []byte, sha string) error {
	base, err := url.Parse(c.at.S3(s.Bucket))
	if err != nil || base.Scheme != "https" {
		return contract.New(contract.Unavailable, "the upload address for %s is not HTTPS", s.Bucket)
	}
	var segs []string
	for _, p := range strings.Split(s.Object, "/") {
		segs = append(segs, url.PathEscape(p))
	}
	path := "/" + strings.Join(segs, "/")
	now := c.now().UTC()
	hdr := map[string]string{"host": base.Host, "x-amz-content-sha256": sha, "x-amz-date": now.Format("20060102T150405Z"),
		"x-amz-security-token": s.SessionToken}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, base.Scheme+"://"+base.Host+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(body))
	for k, v := range hdr {
		if k != "host" {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Authorization", sigV4(http.MethodPut, path, hdr, sha, s.AccessKey, s.SecretKey, "us-west-2", "s3", now))
	resp, err := c.at.Upload.Do(req)
	if err != nil {
		return contract.Wrap(contract.Unavailable, redactURL(err), "the upload to Apple's notary bucket failed")
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxNotaryAnswer))
	if resp.StatusCode/100 != 2 {
		return contract.New(contract.SignFailed, "Apple's notary bucket answered %d to the upload", resp.StatusCode)
	}
	return nil
}

// wait polls the submission until Apple accepts or refuses it, or Wait ends.
func (c notaryClient) wait(ctx context.Context, id string) error {
	deadline := c.now().Add(c.at.Wait)
	for {
		var out struct {
			Data struct {
				Attributes struct {
					Status string `json:"status"`
				} `json:"attributes"`
			} `json:"data"`
		}
		if err := c.call(ctx, http.MethodGet, "/submissions/"+url.PathEscape(id), nil, &out); err != nil {
			return err
		}
		switch st := out.Data.Attributes.Status; st {
		case "Accepted":
			return nil
		case "In Progress":
		default:
			return contract.New(contract.SignFailed, "notarisation was not accepted (status %q, submission %s)", st, id).
				WithFix("read Apple's log: GET " + notaryAt.API + "/submissions/" + id + "/logs, or xcrun notarytool log " + id + " on a Mac")
		}
		if c.now().After(deadline) {
			return contract.New(contract.Unavailable, "Apple had not decided submission %s after %s", id, c.at.Wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(c.at.Poll):
		}
	}
}

// sigV4 is the Authorization header of AWS Signature Version 4 for a request
// with no query string: hdr holds every header signed (lower-case names, host
// among them) and payloadHash the hex sha256 of the body.
func sigV4(method, path string, hdr map[string]string, payloadHash, akid, secret, region, service string, at time.Time) string {
	names := make([]string, 0, len(hdr))
	for k := range hdr {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	var canon strings.Builder
	for _, n := range names {
		canon.WriteString(n + ":" + strings.TrimSpace(hdr[n]) + "\n")
	}
	signed := strings.Join(names, ";")
	creq := method + "\n" + path + "\n\n" + canon.String() + "\n" + signed + "\n" + payloadHash
	day := at.UTC().Format("20060102")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	h := sha256.Sum256([]byte(creq))
	sts := "AWS4-HMAC-SHA256\n" + at.UTC().Format("20060102T150405Z") + "\n" + scope + "\n" + hex.EncodeToString(h[:])
	mac := func(key []byte, s string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(s))
		return m.Sum(nil)
	}
	k := mac(mac(mac(mac([]byte("AWS4"+secret), day), region), service), "aws4_request")
	return "AWS4-HMAC-SHA256 Credential=" + akid + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + hex.EncodeToString(mac(k, sts))
}
