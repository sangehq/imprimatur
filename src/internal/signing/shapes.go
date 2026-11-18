// Package signing runs the contract's signing and verification over a build
// manifest (SD-075 chain of custody): it signs exactly the files the manifest
// lists, after checking each one's digest, with one profile's pinned identity,
// and writes impr-manifest.json naming the profile, that identity and the
// digest of every file before and after signing.
package signing

import (
	"time"

	"github.com/sangehq/imprimatur/src/internal/profile"
)

// ManifestSchema identifies impr-manifest.json.
const ManifestSchema = "imprimatur.manifest/v1"

// ManifestFile is the name of the per-run record written beside the build
// manifest.
const ManifestFile = "impr-manifest.json"

// SumsFile is the checksum file a run writes beside the build manifest when
// it signs checksums or containers.
const SumsFile = "SHA256SUMS"

// SignedArtifact is one entry of impr-manifest.json.
type SignedArtifact struct {
	Path         string `json:"path"`
	InputSHA256  string `json:"inputSha256"`
	OutputSHA256 string `json:"outputSha256"`
	Platform     string `json:"platform"`
	Kind         string `json:"kind"`
	Signer       string `json:"signer"`
	SignerID     string `json:"signerId,omitempty"` // the profile's windows signer, when it lists several
	Timestamp    string `json:"timestamp,omitempty"`
	Notarization string `json:"notarization,omitempty"`
}

// Manifest is impr-manifest.json.
type Manifest struct {
	Schema              string                 `json:"schema"`
	Signer              string                 `json:"signer"` // "imprimatur <version>"
	Profile             string                 `json:"profile"`
	Purpose             profile.Purpose        `json:"purpose"`
	Identity            profile.PinnedIdentity `json:"identity"`
	IdentityDigest      string                 `json:"identityDigest"`
	Commit              string                 `json:"commit"`
	Tree                string                 `json:"tree"`
	Repo                string                 `json:"repo,omitempty"`
	BuildManifestDigest string                 `json:"buildManifestDigest"`
	Artifacts           []SignedArtifact       `json:"artifacts"`
	Outputs             []SignedArtifact       `json:"outputs"`
	Skipped             []string               `json:"skipped,omitempty"`
	// Uncovered are the build manifest's files no requested platform signs or
	// lists (old bug 11): with checksums requested there are none.
	Uncovered []string `json:"uncovered,omitempty"`
	// Approvals records who approved the run, when the profile or the
	// repository requires approval.
	Approvals []RecordedApproval `json:"approvals,omitempty"`
	SignedAt  time.Time          `json:"signedAt"`
}

// RecordedApproval is one approval a run was signed under.
type RecordedApproval struct {
	Mode     string `json:"mode"`               // signed | confirm
	Approver string `json:"approver,omitempty"` // signed: the approver's name
	SHA256   string `json:"sha256,omitempty"`   // signed: the approval document's digest
}

// Result is `impr sign --json`.
type Result struct {
	Contract       int      `json:"contract"`
	OK             bool     `json:"ok"`
	Manifest       Manifest `json:"manifest"`
	ManifestPath   string   `json:"manifestPath"`
	ManifestSHA256 string   `json:"manifestSha256"`
	Skipped        []string `json:"skipped,omitempty"`
	Uncovered      []string `json:"uncovered,omitempty"`
	// DryRun, Plan and Problems are set by impr sign --dry-run only.
	DryRun   bool          `json:"dryRun,omitempty"`
	Plan     []PlannedStep `json:"plan,omitempty"`
	Problems []string      `json:"problems,omitempty"`
}

// Verified is one entry of a verify result.
type Verified struct {
	Path     string   `json:"path"`
	SHA256   string   `json:"sha256"`
	Platform string   `json:"platform"`
	OK       bool     `json:"ok"`
	Found    string   `json:"found,omitempty"`
	Problems []string `json:"problems,omitempty"`
	SignerID string   `json:"signerId,omitempty"`
}

// VerifyResult is `impr verify --json`.
type VerifyResult struct {
	Contract  int        `json:"contract"`
	OK        bool       `json:"ok"`
	Profile   string     `json:"profile"`
	Artifacts []Verified `json:"artifacts"`
}
