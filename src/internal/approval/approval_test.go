package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
)

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

type person struct{ name, key, pub string }

func newPerson(t *testing.T, name string) person {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("real ssh-keygen: not installed")
	}
	key := filepath.Join(t.TempDir(), name)
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	pub, _ := os.ReadFile(key + ".pub")
	f := strings.Fields(string(pub))
	return person{name: name, key: key, pub: f[0] + " " + f[1]}
}

func runner() execx.Runner { return execx.OS{Timeout: time.Minute} }

func testRun(t *testing.T) Run {
	return Run{Profile: "acme-release", Purpose: "release", Commit: randHex(t, 20), Tree: randHex(t, 20), BuildManifestDigest: "sha256:" + randHex(t, 32)}
}

func approve(t *testing.T, p person, r Run, now time.Time, ttl time.Duration) File {
	t.Helper()
	a, err := New(p.name, r, now, ttl)
	if err != nil {
		t.Fatal(err)
	}
	data, sig, err := Sign(context.Background(), runner(), a, p.key)
	if err != nil {
		t.Fatal(err)
	}
	return File{Name: p.name + ".json", Data: data, Sig: sig}
}

func TestCheckAcceptsEnoughDistinctApprovers(t *testing.T) {
	alice, bob := newPerson(t, "alice"), newPerson(t, "bob")
	pol := Policy{Approvers: []Approver{{alice.name, alice.pub}, {bob.name, bob.pub}}, Required: 2}
	if ps := pol.Problems(); len(ps) > 0 {
		t.Fatal(ps)
	}
	r, now := testRun(t), time.Now()
	a, b := approve(t, alice, r, now, time.Hour), approve(t, bob, r, now, time.Hour)
	got, err := Check(context.Background(), runner(), pol, r, now, []File{a, b})
	if err != nil || len(got) != 2 || got[0].Approver != "alice" || got[1].File != 1 {
		t.Fatalf("two approvers: %v %v", got, err)
	}
	// The same approver twice is one approval.
	_, err = Check(context.Background(), runner(), pol, r, now, []File{a, approve(t, alice, r, now, time.Hour)})
	if contract.CodeOf(err) != contract.SignFailed || !strings.Contains(strings.Join(err.(*contract.Error).Details, " "), "does not count twice") {
		t.Fatalf("a repeated approver must not count twice: %v", err)
	}
}

func TestCheckRefuses(t *testing.T) {
	alice, mallory := newPerson(t, "alice"), newPerson(t, "mallory")
	pol := Policy{Approvers: []Approver{{alice.name, alice.pub}}}
	r, now := testRun(t), time.Now()
	good := approve(t, alice, r, now, time.Hour)
	other := r
	other.Commit = randHex(t, 20)

	// mallory signs a document that claims to be alice's.
	forged := approve(t, mallory, r, now, time.Hour)
	forged.Data = []byte(strings.Replace(string(forged.Data), `"approver": "mallory"`, `"approver": "alice"`, 1))
	// alice's signature over a changed document.
	changed := good
	var doc map[string]any
	_ = json.Unmarshal(good.Data, &doc)
	doc["expiresAt"] = now.Add(MaxValidity).UTC().Format(time.RFC3339)
	changed.Data, _ = json.Marshal(doc)
	// alice's key signing the same bytes in another namespace.
	ns := good
	cmd := exec.Command("ssh-keygen", "-Y", "sign", "-q", "-f", alice.key, "-n", "file")
	cmd.Stdin = strings.NewReader(string(good.Data))
	ns.Sig, _ = cmd.Output()

	cases := map[string]struct {
		pol   Policy
		files []File
		want  string
	}{
		"no approvers configured": {Policy{}, []File{good}, "no approvers are configured"},
		"no approval":             {pol, nil, "has 0 valid"},
		"unknown approver":        {pol, []File{approve(t, mallory, r, now, time.Hour)}, "not a configured approver"},
		"forged approver":         {pol, []File{forged}, "not alice's"},
		"edited after signing":    {pol, []File{changed}, "not alice's"},
		"another namespace":       {pol, []File{ns}, "not alice's"},
		"another run":             {pol, []File{approve(t, alice, other, now, time.Hour)}, "commit"},
		"expired":                 {pol, []File{approve(t, alice, r, now.Add(-2*time.Hour), time.Hour)}, "expired"},
		"issued in the future":    {pol, []File{approve(t, alice, r, now.Add(time.Hour), time.Hour)}, "future"},
		"not JSON":                {pol, []File{{Name: "x", Data: []byte("x"), Sig: good.Sig}}, "not an"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Check(context.Background(), runner(), c.pol, r, now, c.files)
			if contract.CodeOf(err) != contract.SignFailed {
				t.Fatalf("want sign failed, got %v", err)
			}
			e := err.(*contract.Error)
			if all := e.Error() + " " + strings.Join(e.Details, " "); !strings.Contains(all, c.want) {
				t.Fatalf("want %q in %q", c.want, all)
			}
		})
	}
}

func TestNewAndPolicyLimits(t *testing.T) {
	r := testRun(t)
	if _, err := New("alice", r, time.Now(), MaxValidity+time.Second); err == nil {
		t.Fatal("an approval longer than the maximum was made")
	}
	if _, err := New("Alice", r, time.Now(), time.Hour); err == nil {
		t.Fatal("a bad approver name was accepted")
	}
	if ps := (Policy{Approvers: []Approver{{"a", "ssh-ed25519 AAAA"}}, Required: 2}).Problems(); len(ps) == 0 {
		t.Fatal("requiring more approvers than are listed must be a problem")
	}
	if ps := (Policy{Approvers: []Approver{{"a", "ssh-ed25519 AAAA comment"}}}).Problems(); len(ps) == 0 {
		t.Fatal("a key line with a comment must be a problem")
	}
}
