package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/artifact"
	gobuild "github.com/sangehq/imprimatur/src/internal/build"
	"github.com/sangehq/imprimatur/src/internal/contract"
)

// LooseManifest is the build manifest impr writes for files named on the
// command line, next to the impr-manifest.json it signs them into.
const LooseManifest = "impr-loose-manifest.json"

// noCommit stands for "not in a git work tree", for test and internal
// signatures only: a signature never claims a commit that does not exist.
var noCommit = strings.Repeat("0", 40)

// looseManifest turns `impr sign FILE...` into a manifest-bound run (design
// ID-10): every file must be under the signing root, the manifest binds them
// to HEAD's commit and tree, and the run then goes through the same checks as
// a manifest from a build stage. A release needs a clean git work tree;
// outside one, only test and internal purposes sign, against noCommit.
func (a *App) looseManifest(ctx context.Context, p parsed) (path, commit, tree string, err error) {
	root, err := filepath.Abs(orDefault(p.str("root"), "."))
	if err != nil {
		return "", "", "", err
	}
	type entry struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	var arts []entry
	seen := map[string]bool{}
	for _, f := range p.pos {
		abs, err := filepath.Abs(f)
		if err != nil {
			return "", "", "", err
		}
		rel, err := filepath.Rel(root, abs)
		if err != nil || strings.HasPrefix(rel, "..") {
			return "", "", "", contract.New(contract.Usage, "%s is not under the signing root %s", f, root).WithFix("impr sign FILE... --root DIR")
		}
		rel = filepath.ToSlash(rel)
		full, err := artifact.Resolve(root, rel)
		if err != nil {
			return "", "", "", contract.Wrap(contract.Usage, err, "cannot sign %s", f)
		}
		if seen[rel] {
			continue
		}
		seen[rel] = true
		sum, err := artifact.SHA256(full)
		if err != nil {
			return "", "", "", err
		}
		arts = append(arts, entry{Path: rel, SHA256: sum})
	}
	b := gobuild.Builder{Runner: a.host().Runner}
	commit, tree, dirty, gerr := b.TrackedCommit(ctx, root)
	switch {
	case gerr != nil && p.str("purpose") == "release":
		return "", "", "", contract.New(contract.SignFailed, "loose files are signed for a release only inside a git work tree; nothing was signed").
			WithDetails(gerr.Error())
	case gerr != nil:
		commit, tree = noCommit, noCommit
		a.say("sign      not a git work tree: the record names no commit")
	case dirty && p.str("purpose") == "release":
		return "", "", "", contract.New(contract.SignFailed, "the work tree has uncommitted changes, so a release signature would name the wrong commit; nothing was signed")
	}
	data, err := json.MarshalIndent(map[string]any{"schema": "sange.build-manifest/v1", "commit": commit, "tree": tree,
		"version": "", "artifacts": arts}, "", "  ")
	if err != nil {
		return "", "", "", err
	}
	path = filepath.Join(root, LooseManifest)
	if err := artifact.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return "", "", "", err
	}
	return path, commit, tree, nil
}
