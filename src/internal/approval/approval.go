// Package approval is two-person control for signing profiles with
// requiresApproval (design ID-05). An approver signs an
// imprimatur.approval/v1 document with their SSH key in the
// imprimatur-approval namespace. It names exactly one profile, purpose,
// commit, tree and build manifest, and it expires. A signing run needs as
// many valid approvals, from distinct approvers in the config, as
// approvals.required says.
package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/bundle"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
)

// Schema identifies an approval document.
const Schema = "imprimatur.approval/v1"

// Namespace is the ssh-keygen -Y namespace approvals are signed in, so no
// other SSH signature can pass for one.
const Namespace = "imprimatur-approval"

// MaxValidity bounds how long any approval may be valid.
const MaxValidity = 7 * 24 * time.Hour

// clockSkew is how far in the future an approval's issue time may be.
const clockSkew = 5 * time.Minute

// Approval is one approver's consent to one signing run.
type Approval struct {
	Schema              string    `json:"schema"`
	Approver            string    `json:"approver"`
	Profile             string    `json:"profile"`
	Purpose             string    `json:"purpose"`
	Commit              string    `json:"commit"`
	Tree                string    `json:"tree"`
	BuildManifestDigest string    `json:"buildManifestDigest"`
	IssuedAt            time.Time `json:"issuedAt"`
	ExpiresAt           time.Time `json:"expiresAt"`
}

// Approver is a person allowed to approve, and their SSH public key.
type Approver struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

// Policy is the config's approvals section.
type Policy struct {
	// Enforce makes impr itself require approval for profiles with
	// requiresApproval. It is off by default because sange enforces approval
	// (APR-11) before it calls impr sign; turn it on where impr is the gate:
	// standalone use, CI and the REST API.
	Enforce   bool       `json:"enforce,omitempty"`
	Approvers []Approver `json:"approvers,omitempty"`
	// Required is how many distinct approvers a run needs; 0 means 1.
	Required int `json:"required,omitempty"`
}

// Need is how many approvals a run needs.
func (p Policy) Need() int {
	if p.Required < 1 {
		return 1
	}
	return p.Required
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Problems reports what is wrong with a policy.
func (p Policy) Problems() []string {
	var out []string
	seen := map[string]bool{}
	for i, a := range p.Approvers {
		if !nameRe.MatchString(a.Name) {
			out = append(out, fmt.Sprintf("approvals.approvers[%d].name must be lower-case letters, digits, . _ -", i))
		}
		if seen[a.Name] {
			out = append(out, fmt.Sprintf("approvals.approvers[%d]: %s is listed twice", i, a.Name))
		}
		seen[a.Name] = true
		if !bundle.ValidPublicKey(a.PublicKey) {
			out = append(out, fmt.Sprintf("approvals.approvers[%d].publicKey must be an SSH public key line, without a comment", i))
		}
	}
	if p.Required < 0 || (len(p.Approvers) > 0 && p.Need() > len(p.Approvers)) {
		out = append(out, fmt.Sprintf("approvals.required is %d, but %d approver(s) are listed", p.Required, len(p.Approvers)))
	}
	return out
}

// Run is what a signing run is about to do.
type Run struct {
	Profile             string
	Purpose             string
	Commit              string
	Tree                string
	BuildManifestDigest string
}

// New builds an approval for a run, valid for ttl from now.
func New(approver string, r Run, now time.Time, ttl time.Duration) (Approval, error) {
	if !nameRe.MatchString(approver) {
		return Approval{}, contract.New(contract.Usage, "--approver must be lower-case letters, digits, . _ -")
	}
	if ttl <= 0 || ttl > MaxValidity {
		return Approval{}, contract.New(contract.Usage, "an approval is valid for more than nothing and at most %s", MaxValidity)
	}
	if r.Profile == "" || r.Purpose == "" || r.Commit == "" || r.Tree == "" || r.BuildManifestDigest == "" {
		return Approval{}, contract.New(contract.Usage, "an approval names a profile, a purpose and a build manifest with its commit and tree")
	}
	now = now.UTC().Truncate(time.Second)
	return Approval{Schema: Schema, Approver: approver, Profile: r.Profile, Purpose: r.Purpose, Commit: r.Commit, Tree: r.Tree,
		BuildManifestDigest: r.BuildManifestDigest, IssuedAt: now, ExpiresAt: now.Add(ttl)}, nil
}

// Sign signs an approval with an SSH key file (a private key, or a public key
// whose private half is in ssh-agent) and returns the document and its
// signature.
func Sign(ctx context.Context, r execx.Runner, a Approval, key string) ([]byte, []byte, error) {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	data = append(data, '\n')
	dir, err := os.MkdirTemp("", "impr-approval-")
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	doc := filepath.Join(dir, "approval.json")
	if err := os.WriteFile(doc, data, 0o600); err != nil { //nolint:gosec // G703: a fixed name in a fresh temporary directory
		return nil, nil, err
	}
	res, err := r.Run(ctx, execx.Cmd{Tool: "ssh-keygen", Args: []string{"-Y", "sign", "-q", "-f", key, "-n", Namespace, doc}})
	if err != nil {
		return nil, nil, contract.Wrap(contract.Unavailable, err, "ssh-keygen could not run")
	}
	if res.ExitCode != 0 {
		return nil, nil, contract.New(contract.SignFailed, "ssh-keygen could not sign the approval with %s", key).WithDetails(strings.TrimSpace(res.Output()))
	}
	sig, err := os.ReadFile(doc + ".sig") //nolint:gosec // G304: ssh-keygen's output in impr's temp dir
	if err != nil {
		return nil, nil, err
	}
	return data, sig, nil
}

// File is one approval document and its signature, as read from disk.
type File struct {
	Name string
	Data []byte
	Sig  []byte
}

// Read loads an approval and the signature beside it (path + ".sig").
func Read(path string) (File, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: a path the operator named
	if err != nil {
		return File{}, contract.Wrap(contract.Usage, err, "read approval %s", path)
	}
	sig, err := os.ReadFile(path + ".sig") //nolint:gosec // G304: its signature beside it
	if err != nil {
		return File{}, contract.Wrap(contract.Usage, err, "approval %s has no signature beside it", path)
	}
	return File{Name: filepath.Base(path), Data: data, Sig: sig}, nil
}

// Accepted is a valid approval: its approver and its index in files.
type Accepted struct {
	Approver string
	File     int
}

// Check returns every valid approval for the run, one per approver, and an
// error unless there are enough of them. Each problem is named, so a refused
// run says which approval failed and why.
func Check(ctx context.Context, r execx.Runner, pol Policy, run Run, now time.Time, files []File) ([]Accepted, error) {
	if len(pol.Approvers) == 0 {
		return nil, contract.New(contract.SignFailed, "this profile requires signed approval, and no approvers are configured; nothing was signed").
			WithFix("an administrator lists approvers in approvals.approvers of the system config.json")
	}
	var ok []Accepted
	var problems []string
	for i, f := range files {
		a, err := verify(ctx, r, pol, f)
		if err == nil {
			err = matches(a, run, now)
		}
		if err != nil {
			problems = append(problems, f.Name+": "+err.Error())
			continue
		}
		if slices.ContainsFunc(ok, func(x Accepted) bool { return x.Approver == a.Approver }) {
			problems = append(problems, f.Name+": a second approval from "+a.Approver+" does not count twice")
			continue
		}
		ok = append(ok, Accepted{Approver: a.Approver, File: i})
	}
	if len(ok) < pol.Need() {
		e := contract.New(contract.SignFailed, "this run needs %d approval(s) and has %d valid; nothing was signed", pol.Need(), len(ok)).
			WithFix("an approver runs: impr approve --manifest BUILD-MANIFEST --profile " + run.Profile + " --purpose " + run.Purpose + " --approver NAME --key ~/.ssh/id_ed25519")
		if len(problems) > 0 {
			e = e.WithDetails(problems...)
		}
		return ok, e
	}
	return ok, nil
}

func verify(ctx context.Context, r execx.Runner, pol Policy, f File) (Approval, error) {
	dec := json.NewDecoder(bytes.NewReader(f.Data))
	dec.DisallowUnknownFields()
	var a Approval
	if err := dec.Decode(&a); err != nil || dec.More() || a.Schema != Schema {
		return Approval{}, fmt.Errorf("not an %s document", Schema)
	}
	i := slices.IndexFunc(pol.Approvers, func(x Approver) bool { return x.Name == a.Approver })
	if i < 0 {
		return Approval{}, fmt.Errorf("%q is not a configured approver", a.Approver)
	}
	dir, err := os.MkdirTemp("", "impr-approval-")
	if err != nil {
		return Approval{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	allowed := filepath.Join(dir, "allowed_signers")
	sigPath := filepath.Join(dir, "approval.sig")
	line := a.Approver + ` namespaces="` + Namespace + `" ` + strings.TrimSpace(pol.Approvers[i].PublicKey) + "\n"
	if err := os.WriteFile(allowed, []byte(line), 0o600); err != nil { //nolint:gosec // G703: a fixed name in a fresh temporary directory
		return Approval{}, err
	}
	if err := os.WriteFile(sigPath, f.Sig, 0o600); err != nil { //nolint:gosec // G703: a fixed name in a fresh temporary directory
		return Approval{}, err
	}
	res, err := r.Run(ctx, execx.Cmd{Tool: "ssh-keygen", Args: []string{"-Y", "verify", "-f", allowed, "-I", a.Approver, "-n", Namespace, "-s", sigPath}, Stdin: f.Data})
	if err != nil {
		return Approval{}, contract.Wrap(contract.Unavailable, err, "ssh-keygen could not run")
	}
	if res.ExitCode != 0 {
		return Approval{}, fmt.Errorf("the signature is not %s's", a.Approver)
	}
	return a, nil
}

func matches(a Approval, r Run, now time.Time) error {
	var diff []string
	for _, c := range [][3]string{{"profile", a.Profile, r.Profile}, {"purpose", a.Purpose, r.Purpose}, {"commit", a.Commit, r.Commit},
		{"tree", a.Tree, r.Tree}, {"buildManifestDigest", a.BuildManifestDigest, r.BuildManifestDigest}} {
		if c[1] != c[2] {
			diff = append(diff, c[0])
		}
	}
	if len(diff) > 0 {
		return fmt.Errorf("it approves another run (%s differ)", strings.Join(diff, ", "))
	}
	switch {
	case !a.ExpiresAt.After(a.IssuedAt) || a.ExpiresAt.Sub(a.IssuedAt) > MaxValidity:
		return fmt.Errorf("its validity is not between now and %s", MaxValidity)
	case a.IssuedAt.After(now.Add(clockSkew)):
		return fmt.Errorf("it was issued in the future (%s)", a.IssuedAt.Format(time.RFC3339))
	case !now.Before(a.ExpiresAt):
		return fmt.Errorf("it expired at %s", a.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}
