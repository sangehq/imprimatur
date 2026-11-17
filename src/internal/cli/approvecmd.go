package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sangehq/imprimatur/src/internal/approval"
	"github.com/sangehq/imprimatur/src/internal/artifact"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

var approveFlags = flagSpec{"json": boolFlag, "manifest": stringFlag, "profile": stringFlag, "purpose": stringFlag,
	"approver": stringFlag, "key": stringFlag, "expires": stringFlag, "out": stringFlag}

// ApproveResult is `impr approve --json`.
type ApproveResult struct {
	Contract  int               `json:"contract"`
	OK        bool              `json:"ok"`
	Approval  approval.Approval `json:"approval"`
	Path      string            `json:"path"`
	Signature string            `json:"signature"`
	SHA256    string            `json:"sha256"`
}

// cmdApprove signs an approval for one signing run: the build manifest
// named, with its commit and tree, for one profile and purpose. The approver
// runs it on their own machine with their own key; the signer then passes
// the file to impr sign --approval.
func cmdApprove(ctx context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, approveFlags)
	if err != nil {
		return 0, err
	}
	for _, f := range []string{"manifest", "profile", "purpose", "approver", "key"} {
		if p.str(f) == "" {
			return 0, contract.New(contract.Usage, "--%s is required", f).
				WithFix("impr approve --manifest build/build-manifest.json --profile acme-release --purpose release --approver alice --key ~/.ssh/id_ed25519")
		}
	}
	if !profile.Purpose(p.str("purpose")).Valid() {
		return 0, contract.New(contract.Usage, "--purpose is release, test or internal")
	}
	ttl := 24 * time.Hour
	if v := p.str("expires"); v != "" {
		if ttl, err = time.ParseDuration(v); err != nil {
			return 0, contract.New(contract.Usage, "--expires is a duration such as 4h or 72h")
		}
	}
	bm, err := artifact.ReadManifest(p.str("manifest"))
	if err != nil {
		return 0, err
	}
	ap, err := approval.New(p.str("approver"), approval.Run{Profile: p.str("profile"), Purpose: p.str("purpose"),
		Commit: bm.Commit, Tree: bm.Tree, BuildManifestDigest: bm.Digest}, a.Now(), ttl)
	if err != nil {
		return 0, err
	}
	data, sig, err := approval.Sign(ctx, a.host().Runner, ap, p.str("key"))
	if err != nil {
		return 0, err
	}
	out := p.str("out")
	if out == "" {
		out = filepath.Join(bm.Dir, fmt.Sprintf("impr-approval-%s.json", ap.Approver))
	}
	if err := artifact.WriteFile(out, data, 0o644); err != nil {
		return 0, err
	}
	if err := artifact.WriteFile(out+".sig", sig, 0o644); err != nil {
		_ = os.Remove(out)
		return 0, err
	}
	sum := sha256.Sum256(data)
	a.bus().Emit(ctx, "approval.created", ap.Profile, map[string]any{"approver": ap.Approver, "profile": ap.Profile, "purpose": ap.Purpose,
		"commit": ap.Commit, "expiresAt": ap.ExpiresAt, "sha256": hex.EncodeToString(sum[:])})
	if p.on("json") {
		a.json(ApproveResult{Contract: contract.Version, OK: true, Approval: ap, Path: out, Signature: out + ".sig", SHA256: hex.EncodeToString(sum[:])})
		return 0, nil
	}
	a.say("approve   %s approves %s for %s at %.12s, until %s", ap.Approver, ap.Profile, ap.Purpose, ap.Commit, ap.ExpiresAt.Format(time.RFC3339))
	a.say("wrote     %s and %s.sig; pass them to impr sign --approval %s", out, out, out)
	return 0, nil
}
