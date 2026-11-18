package signing

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/sangehq/imprimatur/src/internal/contract"
)

// Security review R7 (I-01): in a git work tree, a release's commit must be in
// the checkout with the tree the build manifest names, and --repo must be one
// of the checkout's remotes, so a signer cannot record a commit or an allowed
// repository the build did not come from.
func TestReleaseIsBoundToTheCheckout(t *testing.T) {
	rel := "build/windows/tool_amd64.exe"
	svc, signed, root, manifest := setupMulti(t, map[string]uint16{rel: 0x8664})
	p, _, err := svc.Store.Get("acme")
	if err != nil {
		t.Fatal(err)
	}
	p.Purpose = append(p.Purpose, "release")
	p.AllowedRepos = []string{"github.com/acme/*"}
	if err := svc.Store.Save(p, true); err != nil {
		t.Fatal(err)
	}
	commit, tree := strings.Repeat("1", 40), strings.Repeat("2", 40)
	git := GitState{Tree: tree, Remotes: []string{"git@github.com:acme/tool.git", "https://example.com/mirror/tool"}}
	svc.Git = func(_ context.Context, _, c string) (GitState, error) {
		if c != commit {
			return GitState{}, nil
		}
		return git, nil
	}
	sign := func(repo string) error {
		_, err := svc.Sign(context.Background(), SignOptions{Root: root, Manifest: manifest, Commit: commit, Tree: tree, Repo: repo,
			Profile: "acme", Purpose: "release", Platforms: []string{"windows"}, Strict: true})
		return err
	}
	// Another allowed repository than the checkout's.
	if err := sign("https://github.com/acme/other"); contract.CodeOf(err) != contract.SignFailed || !strings.Contains(err.Error(), "remote") {
		t.Fatalf("--repo is not a remote of the checkout: %v", err)
	}
	// The checkout has the commit, but with another tree.
	git.Tree = strings.Repeat("4", 40)
	if err := sign("https://github.com/acme/tool"); contract.CodeOf(err) != contract.SignFailed || !strings.Contains(err.Error(), "tree") {
		t.Fatalf("a commit whose tree is not --tree: %v", err)
	}
	// The checkout does not have the commit at all.
	git.Tree = tree
	svc.Git = func(context.Context, string, string) (GitState, error) { return GitState{Remotes: git.Remotes}, nil }
	if err := sign("https://github.com/acme/tool"); contract.CodeOf(err) != contract.SignFailed || !strings.Contains(err.Error(), "not in the checkout") {
		t.Fatalf("a commit the checkout does not have: %v", err)
	}
	if len(signed) != 0 {
		t.Fatalf("files were signed: %v", signed)
	}
	svc.Git = func(context.Context, string, string) (GitState, error) { return git, nil }
	if err := sign("ssh://git@github.com/acme/tool.git"); err != nil {
		t.Fatalf("the checkout's own commit and remote: %v", err)
	}
	// Outside a git work tree the binding cannot be checked, so a release is
	// refused (owner decision D-S1, ID-28).
	svc.Git = func(context.Context, string, string) (GitState, error) {
		return GitState{}, errors.New("not a git work tree")
	}
	if err := sign("https://github.com/acme/tool"); contract.CodeOf(err) != contract.SignFailed || !strings.Contains(err.Error(), "git work tree") {
		t.Fatalf("a release outside a work tree: %v", err)
	}
}
