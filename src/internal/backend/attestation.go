package backend

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/artifact"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// The in-toto attestation: an in-toto Statement v1 whose subjects are every
// entry of the checksum file, with a SLSA provenance v1 predicate naming the
// source the build came from. It is wrapped in a DSSE envelope and written
// beside the checksum file as SHA256SUMS.intoto.jsonl.
//
// The envelope is signed by the profile's own pinned signer: the checksum
// key (gpg, minisign or ssh) or cosign, as platforms.attestations.signer
// says. That signer signs DSSE's pre-authentication encoding (PAE), which
// begins "DSSEv1", so the signature cannot pass for one over a checksum
// file. An ssh key signs it in its own namespace, "in-toto".
const (
	StatementType  = "https://in-toto.io/Statement/v1"
	ProvenanceType = "https://slsa.dev/provenance/v1"
	PayloadType    = "application/vnd.in-toto+json"
	// BuildType is the provenance build type under events.source sange.sh,
	// the default, and the only one written before 2026-11-17.
	BuildType = "https://sange.sh/imprimatur/buildtypes/manifest/v1"
	// SimtabiBuildType is the same build type under events.source
	// simtabi.com (owner, 2026-11-17: "support from simtabi as well").
	SimtabiBuildType = "https://simtabi.com/sange/imprimatur/buildtypes/manifest/v1"
	// BuilderID is the provenance builder id under events.source sange.sh,
	// the default, and the only one written before 2026-11-17.
	BuilderID = "https://sange.sh/imprimatur"
	// SimtabiBuilderID is the builder id under events.source simtabi.com
	// (owner, 2026-11-17).
	SimtabiBuilderID = "https://simtabi.com/sange/imprimatur"
	AttestationExt   = ".intoto.jsonl"
	sshNamespace     = "in-toto"
	statementPrefix  = "DSSEv1"
)

// BuildTypes are the build types Verify accepts: an attestation made under
// either events.source setting, or before the setting existed, verifies.
var BuildTypes = []string{BuildType, SimtabiBuildType}

// BuilderIDs are the builder ids Verify accepts, for the same reason as
// BuildTypes.
var BuilderIDs = []string{BuilderID, SimtabiBuilderID}

// BuilderIDFor is the builder id an attestation is written with under an
// events.source setting: the setting's base itself (events.Base), and false
// for an unknown setting.
func BuilderIDFor(setting string) (string, bool) {
	return events.Base(setting)
}

// BuildTypeFor is the build type an attestation is written with under an
// events.source setting: BuildType for "" or "sange.sh", SimtabiBuildType
// for "simtabi.com", and false for anything else.
func BuildTypeFor(setting string) (string, bool) {
	base, ok := events.Base(setting)
	if !ok {
		return "", false
	}
	return base + "/buildtypes/manifest/v1", true
}

// Attestation signs and verifies in-toto attestations through an inner
// backend.
type Attestation struct {
	H     Host
	Spec  profile.AttestationSpec
	Inner Backend
}

func newAttestation(h Host, p profile.Profile) (Backend, error) {
	a := &Attestation{H: h, Spec: *p.Platforms.Attestations}
	switch a.Spec.Signer {
	case "checksums":
		c := p.Platforms.Checksums
		if c == nil {
			return nil, contract.New(contract.Usage, "attestations signed by the checksum key need platforms.checksums")
		}
		if c.Kind == "ssh" {
			spec := *c
			spec.Namespace = sshNamespace
			a.Inner = &SSH{H: h, Spec: spec}
			return a, nil
		}
		inner, err := For(h, p, profile.Checksums)
		if err != nil {
			return nil, err
		}
		a.Inner = inner
	case "cosign":
		inner, err := For(h, p, profile.Containers)
		if err != nil {
			return nil, err
		}
		a.Inner = inner
	default:
		return nil, contract.New(contract.Usage, "attestation signer %q is not checksums or cosign", a.Spec.Signer)
	}
	return a, nil
}

// Subject is one in-toto subject.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// Statement is an in-toto Statement v1.
type Statement struct {
	Type          string     `json:"_type"`
	Subject       []Subject  `json:"subject"`
	PredicateType string     `json:"predicateType"`
	Predicate     Provenance `json:"predicate"`
}

// Provenance is the SLSA provenance v1 predicate imprimatur records.
type Provenance struct {
	BuildDefinition struct {
		BuildType            string               `json:"buildType"`
		ExternalParameters   map[string]string    `json:"externalParameters"`
		InternalParameters   map[string]string    `json:"internalParameters,omitempty"`
		ResolvedDependencies []ResourceDescriptor `json:"resolvedDependencies,omitempty"`
	} `json:"buildDefinition"`
	RunDetails struct {
		Builder struct {
			ID string `json:"id"`
		} `json:"builder"`
	} `json:"runDetails"`
}

// ResourceDescriptor is an in-toto resource descriptor.
type ResourceDescriptor struct {
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest"`
}

// Envelope is a DSSE envelope.
type Envelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []EnvelopeEntry `json:"signatures"`
}

// EnvelopeEntry is one DSSE signature.
type EnvelopeEntry struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// PAE is DSSE's pre-authentication encoding of a payload.
func PAE(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("%s %d %s %d %s", statementPrefix, len(payloadType), payloadType, len(payload), payload))
}

// NewStatement builds the statement for a checksum file's entries.
func NewStatement(lines [][2]string, b Build) Statement {
	st := Statement{Type: StatementType, PredicateType: ProvenanceType, Subject: []Subject{}}
	for _, l := range lines {
		st.Subject = append(st.Subject, Subject{Name: l[1], Digest: map[string]string{"sha256": strings.ToLower(l[0])}})
	}
	bd := &st.Predicate.BuildDefinition
	bd.BuildType = BuildType
	bd.ExternalParameters = map[string]string{"commit": b.Commit, "tree": b.Tree}
	if b.Repo != "" {
		bd.ExternalParameters["repository"] = b.Repo
	}
	if b.ManifestDigest != "" {
		bd.InternalParameters = map[string]string{"buildManifestDigest": b.ManifestDigest}
	}
	dep := ResourceDescriptor{Digest: map[string]string{"gitCommit": b.Commit, "gitTree": b.Tree}}
	if b.Repo != "" {
		dep.URI = "git+" + b.Repo
	}
	bd.ResolvedDependencies = []ResourceDescriptor{dep}
	st.Predicate.RunDetails.Builder.ID = BuilderID
	return st
}

// sigSuffix is the file name the inner backend writes its signature to,
// after the signed file's own name.
func (a *Attestation) sigSuffix() string {
	switch a.Inner.(type) {
	case *Minisign:
		return ".minisig"
	case *Cosign:
		return ".sigstore.json"
	}
	return ".sig"
}

func (a *Attestation) keyID(signer string) string {
	return a.Spec.Signer + ":" + signer
}

// Capability is the inner signer's, as in-toto.
func (a *Attestation) Capability(h Host) Capability {
	c := a.Inner.Capability(h)
	c.Platform, c.Kind, c.Backend, c.Supported = profile.Attestations, "in-toto", a.Spec.Signer, true
	return c
}

// Certificate is the inner signer's key.
func (a *Attestation) Certificate(ctx context.Context, p profile.Profile) CertEntry {
	e := a.Inner.Certificate(ctx, p)
	e.Platform = profile.Attestations
	return e
}

// Preflight is the inner signer's.
func (a *Attestation) Preflight(ctx context.Context, p profile.Profile) error {
	return Preflight(ctx, a.Inner, p)
}

// Sign writes art.Path + .intoto.jsonl: a signed statement over the
// checksum file art names.
func (a *Attestation) Sign(ctx context.Context, art Artifact, p profile.Profile) (Signature, error) {
	if art.Build == nil || art.Build.Commit == "" {
		return Signature{}, contract.New(contract.SignFailed, "an in-toto attestation needs the build's commit; nothing was attested")
	}
	buildType, ok := BuildTypeFor(a.H.EventsSource)
	builderID, _ := BuilderIDFor(a.H.EventsSource)
	if !ok {
		return Signature{}, contract.New(contract.Usage, "events.source %q is not sange.sh or simtabi.com; nothing was attested", a.H.EventsSource)
	}
	lines, err := readSums(art.Path)
	if err != nil {
		return Signature{}, contract.Wrap(contract.SignFailed, err, "read %s", art.Rel)
	}
	st := NewStatement(lines, *art.Build)
	st.Predicate.BuildDefinition.BuildType = buildType
	st.Predicate.RunDetails.Builder.ID = builderID
	payload, err := json.Marshal(st)
	if err != nil {
		return Signature{}, err
	}
	dir, err := os.MkdirTemp("", "impr-intoto-")
	if err != nil {
		return Signature{}, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	pae := filepath.Join(dir, "statement")
	if err := os.WriteFile(pae, PAE(PayloadType, payload), 0o600); err != nil {
		return Signature{}, err
	}
	sig, err := a.Inner.Sign(ctx, Artifact{Path: pae, Rel: art.Rel + AttestationExt}, p)
	if err != nil {
		return Signature{}, err
	}
	raw, err := os.ReadFile(pae + a.sigSuffix()) //nolint:gosec // G304: the inner signer's output in impr's temp dir
	if err != nil {
		return Signature{}, contract.Wrap(contract.SignFailed, err, "the %s signer wrote no signature", a.Spec.Signer)
	}
	env := Envelope{PayloadType: PayloadType, Payload: base64.StdEncoding.EncodeToString(payload),
		Signatures: []EnvelopeEntry{{KeyID: a.keyID(sig.Signer), Sig: base64.StdEncoding.EncodeToString(raw)}}}
	line, err := json.Marshal(env)
	if err != nil {
		return Signature{}, err
	}
	out := art.Path + AttestationExt
	if err := artifact.WriteFile(out, append(line, '\n'), 0o644); err != nil {
		return Signature{}, err
	}
	if err := a.Verify(ctx, art, p); err != nil {
		return Signature{}, err
	}
	return Signature{Kind: "in-toto", Signer: sig.Signer, Outputs: []Output{{Path: out, Kind: "in-toto"}}}, nil
}

// Verify checks art.Path + .intoto.jsonl: the envelope is signed by exactly
// the pinned signer, its statement names exactly the checksum file's
// entries, and, when the build is known, exactly its commit and tree.
func (a *Attestation) Verify(ctx context.Context, art Artifact, p profile.Profile) error {
	name := art.Rel + AttestationExt
	b, err := os.ReadFile(art.Path + AttestationExt) //nolint:gosec // G304: resolved under the signing root
	if err != nil {
		return contract.New(contract.VerifyFailed, "%s is missing", name)
	}
	dec := json.NewDecoder(bytes.NewReader(bytes.TrimSpace(b)))
	dec.DisallowUnknownFields()
	var env Envelope
	if err := dec.Decode(&env); err != nil || dec.More() {
		return contract.New(contract.VerifyFailed, "%s is not one DSSE envelope", name)
	}
	if env.PayloadType != PayloadType || len(env.Signatures) != 1 {
		return contract.New(contract.VerifyFailed, "%s must carry an in-toto payload and exactly one signature", name)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return contract.New(contract.VerifyFailed, "%s: the payload is not base64", name)
	}
	raw, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return contract.New(contract.VerifyFailed, "%s: the signature is not base64", name)
	}
	if !strings.HasPrefix(env.Signatures[0].KeyID, a.Spec.Signer+":") {
		return contract.New(contract.VerifyFailed, "%s was signed by the %s signer, not the profile's %s", name, strings.SplitN(env.Signatures[0].KeyID, ":", 2)[0], a.Spec.Signer)
	}
	dir, err := os.MkdirTemp("", "impr-intoto-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	pae := filepath.Join(dir, "statement")
	if err := os.WriteFile(pae, PAE(env.PayloadType, payload), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(pae+a.sigSuffix(), raw, 0o600); err != nil {
		return err
	}
	if err := a.Inner.Verify(ctx, Artifact{Path: pae, Rel: name}, p); err != nil {
		return contract.Wrap(contract.VerifyFailed, err, "%s: the envelope's signature", name)
	}

	// The signature holds; now the statement must say what the files are.
	sd := json.NewDecoder(bytes.NewReader(payload))
	sd.DisallowUnknownFields()
	var st Statement
	if err := sd.Decode(&st); err != nil {
		return contract.New(contract.VerifyFailed, "%s: the statement is not one imprimatur writes: %v", name, err)
	}
	if st.Type != StatementType || st.PredicateType != ProvenanceType || !slices.Contains(BuildTypes, st.Predicate.BuildDefinition.BuildType) {
		return contract.New(contract.VerifyFailed, "%s: not an in-toto v1 statement with SLSA provenance v1", name)
	}
	if !slices.Contains(BuilderIDs, st.Predicate.RunDetails.Builder.ID) {
		return contract.New(contract.VerifyFailed, "%s: builder %q is not imprimatur's", name, st.Predicate.RunDetails.Builder.ID)
	}
	lines, err := readSums(art.Path)
	if err != nil {
		return contract.Wrap(contract.VerifyFailed, err, "read %s", art.Rel)
	}
	want := NewStatement(lines, Build{}).Subject
	if !slices.EqualFunc(st.Subject, want, func(x, y Subject) bool {
		return x.Name == y.Name && len(x.Digest) == 1 && x.Digest["sha256"] == y.Digest["sha256"]
	}) {
		return contract.New(contract.VerifyFailed, "%s names other files or digests than %s", name, art.Rel)
	}
	if bl := art.Build; bl != nil {
		ext := st.Predicate.BuildDefinition.ExternalParameters
		if ext["commit"] != bl.Commit || ext["tree"] != bl.Tree {
			return contract.New(contract.VerifyFailed, "%s attests commit %s, not the signed build's %s", name, ext["commit"], bl.Commit)
		}
	}
	return nil
}

func readSums(path string) ([][2]string, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: resolved under the signing root
	if err != nil {
		return nil, err
	}
	lines, err := artifact.ParseChecksums(b)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, fmt.Errorf("the checksum file lists no files")
	}
	return lines, nil
}
