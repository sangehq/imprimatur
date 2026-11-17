package signing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/sangehq/imprimatur/src/internal/approval"
	"github.com/sangehq/imprimatur/src/internal/artifact"
	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// approve enforces approval before anything is signed, in the profile's
// mode, and returns what to record.
func (s *Service) approve(ctx context.Context, p profile.Profile, o SignOptions, bm artifact.Loaded) ([]RecordedApproval, error) {
	mode := p.ApprovalMode()
	if mode == "" {
		mode = profile.ApprovalSigned // the repository required it; the profile names no mode
	}
	if mode == profile.ApprovalConfirm {
		if s.Confirm == nil {
			return nil, contract.New(contract.SignFailed, "signing profile %s needs a typed confirmation, and this run has no terminal to ask; nothing was signed", p.Name).
				WithDetails("The REST API, CI and piped runs cannot confirm.").
				WithFix("run impr sign at a terminal, or set the profile's approval to signed: impr profile edit " + p.Name + " --set approval=signed")
		}
		want := bm.Commit
		if len(want) > 12 {
			want = want[:12]
		}
		if !s.Confirm("approve signing "+bm.Commit+" with "+p.Name+" for "+o.Purpose+": type the first 12 characters of the commit", want) {
			return nil, contract.New(contract.SignFailed, "not confirmed; nothing was signed")
		}
		s.logf("approve   confirmed at the terminal")
		return []RecordedApproval{{Mode: profile.ApprovalConfirm}}, nil
	}
	var files []approval.File
	for _, path := range o.Approvals {
		f, err := approval.Read(path)
		if err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	run := approval.Run{Profile: p.Name, Purpose: o.Purpose, Commit: bm.Commit, Tree: bm.Tree, BuildManifestDigest: bm.Digest}
	who, err := approval.Check(ctx, s.Host.Runner, s.Approvals, run, s.Host.Now(), files)
	if err != nil {
		return nil, err
	}
	var out []RecordedApproval
	var names []string
	for _, acc := range who {
		sum := sha256.Sum256(files[acc.File].Data)
		out = append(out, RecordedApproval{Mode: profile.ApprovalSigned, Approver: acc.Approver, SHA256: hex.EncodeToString(sum[:])})
		names = append(names, acc.Approver)
	}
	s.logf("approve   %d approval(s): %v", len(out), names)
	return out, nil
}
