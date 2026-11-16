package cli

import (
	"bufio"
	"context"
	"fmt"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/artifact"
	"github.com/sangehq/imprimatur/src/internal/profile"
)

// menuEntries are the menu's keys, labels and the command line each runs.
// Entries with a nil line run a guided flow instead.
var menuEntries = []struct {
	key, label string
	line       []string
}{
	{"d", "doctor: profiles and what this host can sign", []string{"doctor"}},
	{"p", "signing profiles", []string{"profile", "list"}},
	{"c", "certificates and keys, with expiry", []string{"cert", "list"}},
	{"s", "sign a build manifest", nil},
	{"v", "verify a signed manifest", nil},
	{"e", "recent events", []string{"events", "tail", "--limit", "20"}},
	{"g", "configuration (layers and values)", []string{"config", "path"}},
	{"w", "webhooks", []string{"webhooks", "list"}},
	{"k", "hooks", []string{"hooks", "list"}},
	{"i", "where impr and its files are", []string{"path"}},
	{"h", "help", []string{"help"}},
	{"q", "quit", nil},
}

// menu is the interactive menu, for a person at a terminal: each entry runs
// the same command the CLI does, so nothing here is reachable only by menu.
func (a *App) menu(ctx context.Context) int {
	in := bufio.NewScanner(a.Stdin)
	ask := func(prompt string) (string, bool) {
		_, _ = fmt.Fprint(a.Stderr, prompt)
		if !in.Scan() {
			return "", false
		}
		return strings.TrimSpace(in.Text()), true
	}
	for {
		a.say("\nimpr %s", version)
		for _, e := range menuEntries {
			a.say("  %s  %s", e.key, e.label)
		}
		choice, ok := ask("> ")
		if !ok || choice == "q" {
			return 0
		}
		found := false
		for _, e := range menuEntries {
			if e.key != choice {
				continue
			}
			found = true
			switch {
			case e.line != nil:
				a.Run(ctx, e.line)
			case e.key == "s":
				a.menuSign(ctx, ask)
			case e.key == "v":
				a.menuVerify(ctx, ask)
			}
		}
		if !found {
			a.say("menu      %q is not an entry", choice)
		}
	}
}

// menuSign walks through one signing run: the build manifest, the profile,
// the purpose, and an explicit "yes" after showing what will be signed. The
// commit and tree come from the manifest the person just confirmed.
func (a *App) menuSign(ctx context.Context, ask func(string) (string, bool)) {
	manifest, ok := ask("build manifest (path): ")
	if !ok || manifest == "" {
		return
	}
	bm, err := artifact.ReadManifest(manifest)
	if err != nil {
		a.say("menu      %v", err)
		return
	}
	a.say("menu      commit %s, tree %s, %d file(s)", bm.Commit, bm.Tree, len(bm.Artifacts))
	def := ""
	if s, err := a.store(); err == nil {
		if idx, _, err := s.LoadIndex(); err == nil {
			def = idx.Default
		}
	}
	name, ok := ask(fmt.Sprintf("signing profile [%s]: ", def))
	if !ok {
		return
	}
	if name == "" {
		name = def
	}
	if !profile.ValidName(name) {
		a.say("menu      %q is not a profile name", name)
		return
	}
	purpose, ok := ask("purpose (release, test or internal): ")
	if !ok || (purpose != "release" && purpose != "test" && purpose != "internal") {
		a.say("menu      a purpose is required; nothing was signed")
		return
	}
	repo := ""
	if purpose == "release" {
		if repo, ok = ask("repository URL (a release names it): "); !ok || repo == "" {
			a.say("menu      a release needs the repository; nothing was signed")
			return
		}
	}
	root, _ := ask("signing root [.]: ")
	if root == "" {
		root = "."
	}
	a.say("menu      sign %d file(s) of commit %s with profile %s for %s?", len(bm.Artifacts), bm.Commit, name, purpose)
	if yes, ok := ask("type yes to sign: "); !ok || yes != "yes" {
		a.say("menu      nothing was signed")
		return
	}
	args := []string{"sign", "--manifest", manifest, "--commit", bm.Commit, "--tree", bm.Tree, "--profile", name,
		"--purpose", purpose, "--root", root, "--strict"}
	if repo != "" {
		args = append(args, "--repo", repo)
	}
	a.say("menu      exit %d", a.Run(ctx, args))
}

func (a *App) menuVerify(ctx context.Context, ask func(string) (string, bool)) {
	signed, ok := ask("impr-manifest.json (path): ")
	if !ok || signed == "" {
		return
	}
	name, ok := ask("signing profile: ")
	if !ok || !profile.ValidName(name) {
		a.say("menu      a profile is required")
		return
	}
	root, _ := ask("signing root [.]: ")
	if root == "" {
		root = "."
	}
	a.say("menu      exit %d", a.Run(ctx, []string{"verify", "--signed", signed, "--profile", name, "--root", root, "--strict"}))
}
