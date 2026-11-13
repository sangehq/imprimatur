package guardtest

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The workflows are read as text, line by line: the module carries no YAML
// dependency, and these checks need only indentation and keys.

func indentOf(line string) int { return len(line) - len(strings.TrimLeft(line, " ")) }

func isBlankOrComment(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#")
}

var keyLine = regexp.MustCompile(`^\s*['"]?([A-Za-z_][A-Za-z0-9_-]*)['"]?\s*:`)

// onBlock returns the lines of the top-level `on:` block and its inline value,
// if it has one (`on: push` or `on: [push, pull_request]`).
func onBlock(text string) (block []string, inline string, found bool) {
	lines := strings.Split(text, "\n")
	head := regexp.MustCompile(`^['"]?on['"]?\s*:\s*(.*)$`)
	for i, line := range lines {
		m := head.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		inline = strings.TrimSpace(m[1])
		if strings.HasPrefix(inline, "#") {
			inline = ""
		}
		for _, l := range lines[i+1:] {
			if !isBlankOrComment(l) && indentOf(l) == 0 {
				break
			}
			block = append(block, l)
		}
		return block, inline, true
	}
	return nil, "", false
}

// triggers lists the event names under `on:`.
func triggers(text string) []string {
	block, inline, found := onBlock(text)
	if !found {
		return nil
	}
	var names []string
	if inline != "" {
		for _, n := range strings.Split(strings.Trim(inline, "[]"), ",") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		return names
	}
	level := -1
	for _, l := range block {
		if isBlankOrComment(l) {
			continue
		}
		if level < 0 {
			level = indentOf(l)
		}
		if indentOf(l) == level {
			if m := keyLine.FindStringSubmatch(l); m != nil {
				names = append(names, m[1])
			}
		}
	}
	sort.Strings(names)
	return names
}

var cronLine = regexp.MustCompile(`^\s*-?\s*cron\s*:\s*['"]?([^'"#]+?)['"]?\s*(#.*)?$`)

// crons lists the cron expressions under `on:`.
func crons(text string) []string {
	block, _, _ := onBlock(text)
	var out []string
	for _, l := range block {
		if m := cronLine.FindStringSubmatch(l); m != nil {
			out = append(out, strings.TrimSpace(m[1]))
		}
	}
	return out
}

var number = regexp.MustCompile(`^[0-9]+$`)

// weekly reports whether a cron expression fires once a week: a fixed minute
// and hour, every day of the month and month, one day of the week.
func weekly(expr string) bool {
	f := strings.Fields(expr)
	return len(f) == 5 && number.MatchString(f[0]) && number.MatchString(f[1]) &&
		f[2] == "*" && f[3] == "*" && regexp.MustCompile(`^[0-6]$`).MatchString(f[4])
}

// ciProblems checks ci.yml's triggers.
func ciProblems(text string) []string {
	var problems []string
	names := triggers(text)
	if len(names) == 0 {
		problems = append(problems, "no triggers found under on:")
	}
	for _, n := range names {
		if n == "push" || n == "pull_request_target" {
			problems = append(problems, "ci.yml triggers on "+n)
		}
	}
	for _, want := range []string{"pull_request", "workflow_dispatch", "schedule"} {
		if !slices.Contains(names, want) {
			problems = append(problems, "ci.yml does not trigger on "+want)
		}
	}
	c := crons(text)
	if len(c) != 1 {
		problems = append(problems, "ci.yml has "+strconv.Itoa(len(c))+" cron schedules; want exactly one weekly")
	}
	for _, e := range c {
		if !weekly(e) {
			problems = append(problems, "cron '"+e+"' is not weekly")
		}
	}
	return problems
}

// releaseTagFilters are the push filters release.yml carries: a final version
// tag and a pre-release one. The src/vX.Y.Z module alias matches neither.
var releaseTagFilters = []string{"v[0-9]+.[0-9]+.[0-9]+", "v[0-9]+.[0-9]+.[0-9]+-*"}

var (
	sharedReleaseCall = regexp.MustCompile(`(?m)^\s*uses\s*:\s*simtabi/\.github/\.github/workflows/go-release\.yml@[0-9a-f]{40}\s*(#.*)?$`)
	tagFromInput      = regexp.MustCompile(`(?m)^\s*tag\s*:\s*\$\{\{\s*inputs\.tag\s*\|\|\s*github\.ref_name\s*\}\}\s*$`)
	neverCancelled    = regexp.MustCompile(`(?m)^\s*cancel-in-progress\s*:\s*false\s*(#.*)?$`)
	listItem          = regexp.MustCompile(`^\s*-\s*['"]?([^'"#]+?)['"]?\s*(#.*)?$`)
	stepsKey          = regexp.MustCompile(`(?m)^\s*steps\s*:`)
)

// childBlock returns the lines nested under the first line in block whose key
// is name.
func childBlock(block []string, name string) ([]string, bool) {
	for i, l := range block {
		m := keyLine.FindStringSubmatch(l)
		if m == nil || m[1] != name {
			continue
		}
		var out []string
		for _, c := range block[i+1:] {
			if isBlankOrComment(c) {
				continue
			}
			if indentOf(c) <= indentOf(l) {
				break
			}
			out = append(out, c)
		}
		return out, true
	}
	return nil, false
}

// releaseProblems checks release.yml: it runs on a pushed version tag or on a
// dispatch naming one, on no branch, and its one job calls the shared
// go-release.yml pinned to a commit, passing the tag through.
func releaseProblems(text string) []string {
	var problems []string
	names := triggers(text)
	if strings.Join(names, ",") != "push,workflow_dispatch" {
		problems = append(problems, "release.yml triggers on "+strings.Join(names, ", ")+"; want exactly push (version tags) and workflow_dispatch")
	}
	block, _, _ := onBlock(text)

	push, _ := childBlock(block, "push")
	var tags []string
	for _, l := range push {
		if m := keyLine.FindStringSubmatch(l); m != nil && m[1] != "tags" {
			problems = append(problems, "release.yml's push trigger filters on "+m[1]+"; it runs on version tags only")
		}
		if m := listItem.FindStringSubmatch(l); m != nil {
			tags = append(tags, strings.TrimSpace(m[1]))
		}
	}
	if !slices.Equal(tags, releaseTagFilters) {
		problems = append(problems, "release.yml's push tags are "+strings.Join(tags, ", ")+"; want "+strings.Join(releaseTagFilters, ", "))
	}

	dispatch, _ := childBlock(block, "workflow_dispatch")
	input, ok := childBlock(dispatch, "tag")
	if !ok {
		problems = append(problems, "release.yml's workflow_dispatch has no tag input")
	} else if !slices.ContainsFunc(input, regexp.MustCompile(`^\s*required\s*:\s*true\s*(#.*)?$`).MatchString) {
		problems = append(problems, "release.yml's tag input is not required: true")
	}

	if !neverCancelled.MatchString(text) {
		problems = append(problems, "release.yml's concurrency does not say cancel-in-progress: false")
	}
	if !sharedReleaseCall.MatchString(text) {
		problems = append(problems, "release.yml does not call simtabi/.github's go-release.yml pinned to a commit")
	}
	if !tagFromInput.MatchString(text) {
		problems = append(problems, "release.yml does not pass tag: ${{ inputs.tag || github.ref_name }}")
	}
	if stepsKey.MatchString(text) {
		problems = append(problems, "release.yml has steps of its own; the shared workflow does the work")
	}
	return problems
}

// bannedGoReleaserBlocks publish somewhere other than the GitHub release. The
// list is the one simtabi/.github's go-release.yml refuses.
var bannedGoReleaserBlocks = []string{
	"brews", "homebrew_casks", "scoops", "winget", "chocolateys", "aurs", "aur_sources",
	"snapcrafts", "flatpaks", "nix", "dockers", "dockers_v2", "docker_manifests", "docker_signs",
	"kos", "krews", "npms", "cloudsmiths", "furies", "publishers", "blobs", "uploads", "artifactories",
}

var topKey = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.*)$`)

// goreleaserProblems checks src/.goreleaser.yaml publishes on the GitHub
// release only and writes its scratch output outside build/.
func goreleaserProblems(text string) []string {
	var problems []string
	dist := ""
	for _, l := range strings.Split(text, "\n") {
		m := topKey.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		if slices.Contains(bannedGoReleaserBlocks, m[1]) {
			problems = append(problems, "src/.goreleaser.yaml has a "+m[1]+" block; binaries ship on the GitHub release only")
		}
		if m[1] == "dist" {
			dist = strings.Trim(strings.TrimSpace(strings.SplitN(m[2], "#", 2)[0]), `"'`)
		}
	}
	if dist == "" || dist == "build" || strings.HasPrefix(dist, "build/") {
		problems = append(problems, "src/.goreleaser.yaml's dist is "+strconv.Quote(dist)+"; it must be a scratch directory outside build/")
	}
	return problems
}

// goreleaserTargets returns the builds' targets as "goos goarch [goarm]",
// the form build/targets.txt uses.
func goreleaserTargets(text string) []string {
	var out []string
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if m := keyLine.FindStringSubmatch(l); m == nil || m[1] != "targets" {
			continue
		}
		for _, c := range lines[i+1:] {
			if isBlankOrComment(c) {
				continue
			}
			m := listItem.FindStringSubmatch(c)
			if m == nil || indentOf(c) < indentOf(l) {
				break
			}
			f := strings.Split(strings.TrimSpace(m[1]), "_")
			if len(f) < 2 {
				out = append(out, m[1])
				continue
			}
			target := f[0] + " " + f[1]
			if f[1] == "arm" && len(f) > 2 {
				target += " " + f[2]
			}
			out = append(out, target)
		}
	}
	sort.Strings(out)
	return out
}

// targetsFile returns build/targets.txt's targets, normalised to single spaces.
func targetsFile(text string) []string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if isBlankOrComment(l) {
			continue
		}
		out = append(out, strings.Join(strings.Fields(l), " "))
	}
	sort.Strings(out)
	return out
}

var (
	usesLine     = regexp.MustCompile(`^\s*-?\s*uses\s*:\s*['"]?([^\s'"#]+)['"]?\s*(#.*)?$`)
	majorTag     = regexp.MustCompile(`^v[0-9]+$`)
	fullSHA      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	releaseNote  = regexp.MustCompile(`^#\s*v?[0-9]+\.[0-9]+\.[0-9]+\s*$`)
	floatsOwners = map[string]bool{"actions": true, "docker": true, "github": true}
	// An org's shared workflows live in its .github repository, which tags its
	// releases (simtabi/.github v1.0.0 onward), so a pin names the release tag of
	// the commit, `# vX.Y.Z`: that is the comment Dependabot reads and rewrites.
	reusableWorkflow = regexp.MustCompile(`^[A-Za-z0-9_.-]+/\.github/\.github/workflows/[^/]+\.ya?ml$`)
	sharedReleaseTag = regexp.MustCompile(`^#\s*v[0-9]+\.[0-9]+\.[0-9]+$`)
)

// pinProblem returns why an action reference has the wrong form, or "".
// actions/*, docker/* and github/* float on a major tag; every other action is
// a 40-hex commit SHA followed by a `# x.y.z` comment; an org's shared workflow
// (owner/.github/.github/workflows/*.yml) is a 40-hex commit SHA followed by a
// `# vX.Y.Z` comment naming its release tag.
func pinProblem(ref, comment string) string {
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
		return ""
	}
	action, version, ok := strings.Cut(ref, "@")
	if !ok {
		return ref + " has no @ref"
	}
	owner, _, _ := strings.Cut(action, "/")
	if reusableWorkflow.MatchString(action) {
		if !fullSHA.MatchString(version) {
			return ref + ": a shared workflow is pinned to a 40-hex commit SHA"
		}
		if !sharedReleaseTag.MatchString(strings.TrimSpace(comment)) {
			return ref + ": a shared-workflow pin is followed by a `# vX.Y.Z` comment naming its release tag"
		}
		return ""
	}
	if floatsOwners[owner] {
		if !majorTag.MatchString(version) {
			return ref + ": first-party actions float on a major tag (vN)"
		}
		return ""
	}
	if !fullSHA.MatchString(version) {
		return ref + ": third-party actions are pinned to a 40-hex commit SHA"
	}
	if !releaseNote.MatchString(strings.TrimSpace(comment)) {
		return ref + ": a SHA pin is followed by a `# x.y.z` release comment"
	}
	return ""
}

func workflowFiles(t *testing.T) []string {
	t.Helper()
	dir := filepath.Join(repoRoot(t), ".github", "workflows")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		if name := e.Name(); !e.IsDir() && (strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml")) {
			files = append(files, filepath.Join(dir, name))
		}
	}
	return files
}

// TestCIHasNoPushTriggerAndOneWeeklyCron: CI runs on pull requests, dispatch
// and one weekly schedule; a push trigger runs after the change has landed.
func TestCIHasNoPushTriggerAndOneWeeklyCron(t *testing.T) {
	text := readFile(t, filepath.Join(repoRoot(t), ".github", "workflows", "ci.yml"))
	for _, p := range ciProblems(text) {
		t.Error(p)
	}
	atLeast(t, "ci.yml triggers", len(triggers(text)), 3)
}

// TestReleaseRunsOnAVersionTagOrOnRequest: a pushed vX.Y.Z tag, or a dispatch
// naming one, publishes through the shared go-release.yml; nothing else does.
func TestReleaseRunsOnAVersionTagOrOnRequest(t *testing.T) {
	text := readFile(t, filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	for _, p := range releaseProblems(text) {
		t.Error(p)
	}
	atLeast(t, "release.yml triggers", len(triggers(text)), 2)
}

// TestGoReleaserPublishesOnTheGitHubReleaseOnly: no block in the GoReleaser
// config publishes anywhere else, and its output stays out of build/.
func TestGoReleaserPublishesOnTheGitHubReleaseOnly(t *testing.T) {
	text := readFile(t, filepath.Join(repoRoot(t), "src", ".goreleaser.yaml"))
	for _, p := range goreleaserProblems(text) {
		t.Error(p)
	}
	atLeast(t, "top-level GoReleaser keys", len(regexp.MustCompile(`(?m)^[a-z_]+\s*:`).FindAllString(text, -1)), 8)
}

// TestGoReleaserBuildsTheTargetsList: the release builds exactly the targets
// `make cross` builds, so the published asset names stay the same.
func TestGoReleaserBuildsTheTargetsList(t *testing.T) {
	root := repoRoot(t)
	got := goreleaserTargets(readFile(t, filepath.Join(root, "src", ".goreleaser.yaml")))
	want := targetsFile(readFile(t, filepath.Join(root, "build", "targets.txt")))
	if !slices.Equal(got, want) {
		t.Errorf("src/.goreleaser.yaml targets %v; build/targets.txt lists %v", got, want)
	}
	atLeast(t, "release targets", len(got), 10)
}

// TestActionPinForm checks every `uses:` in every workflow.
func TestActionPinForm(t *testing.T) {
	files := workflowFiles(t)
	refs := 0
	for _, f := range files {
		for i, line := range strings.Split(readFile(t, f), "\n") {
			m := usesLine.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			refs++
			if p := pinProblem(m[1], m[2]); p != "" {
				t.Errorf("%s:%d: %s", filepath.Base(f), i+1, p)
			}
		}
	}
	atLeast(t, "workflow files", len(files), 2)
	atLeast(t, "action references", refs, 5)
}

// TestWorkflowGuardsCanFail is the standing negative control: each check
// rejects a known-bad sample.
func TestWorkflowGuardsCanFail(t *testing.T) {
	pushCI := "on:\n  push:\n    branches: [main]\n  pull_request:\n  workflow_dispatch:\n  schedule:\n    - cron: '0 6 * * 1'\njobs: {}\n"
	if len(ciProblems(pushCI)) == 0 {
		t.Error("ciProblems accepted a push trigger")
	}
	inlinePush := "on: [push, pull_request]\njobs: {}\n"
	if len(ciProblems(inlinePush)) == 0 {
		t.Error("ciProblems accepted an inline push trigger")
	}
	dailyCI := "on:\n  pull_request:\n  workflow_dispatch:\n  schedule:\n    - cron: '0 6 * * *'\njobs: {}\n"
	if len(ciProblems(dailyCI)) == 0 {
		t.Error("ciProblems accepted a daily cron")
	}
	twoCrons := "on:\n  pull_request:\n  workflow_dispatch:\n  schedule:\n    - cron: '0 6 * * 1'\n    - cron: '0 6 * * 4'\njobs: {}\n"
	if len(ciProblems(twoCrons)) == 0 {
		t.Error("ciProblems accepted two crons")
	}

	// The hand-written, confirmed-dispatch release this replaced must fail.
	oldRelease := "on:\n  workflow_dispatch:\n    inputs:\n      confirm:\n        required: true\njobs:\n  r:\n    steps:\n      - run: exit 1\n"
	if len(releaseProblems(oldRelease)) == 0 {
		t.Error("releaseProblems accepted a dispatch-only release with no shared call")
	}
	good := readFile(t, filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	for name, bad := range map[string]string{
		"a branch push":        strings.Replace(good, "    tags:\n", "    branches: [main]\n    tags:\n", 1),
		"a schedule":           strings.Replace(good, "  workflow_dispatch:\n", "  schedule:\n    - cron: '0 6 * * 1'\n  workflow_dispatch:\n", 1),
		"a loose tag filter":   strings.Replace(good, "'v[0-9]+.[0-9]+.[0-9]+-*'", "'v*'", 1),
		"an optional tag":      strings.Replace(good, "required: true", "required: false", 1),
		"a cancelled run":      strings.Replace(good, "cancel-in-progress: false", "cancel-in-progress: true", 1),
		"a branch-pinned call": regexp.MustCompile(`go-release\.yml@[0-9a-f]{40}`).ReplaceAllString(good, "go-release.yml@main"),
		"a tag not passed":     strings.Replace(good, "tag: ${{ inputs.tag || github.ref_name }}", "tag: ${{ github.ref_name }}", 1),
		"steps of its own":     good + "    steps:\n      - run: make cross\n",
	} {
		if bad == good {
			t.Errorf("the %s sample did not change release.yml", name)
			continue
		}
		if len(releaseProblems(bad)) == 0 {
			t.Errorf("releaseProblems accepted %s", name)
		}
	}

	gr := readFile(t, filepath.Join(repoRoot(t), "src", ".goreleaser.yaml"))
	for name, bad := range map[string]string{
		"a Homebrew tap": gr + "brews:\n  - name: impr\n",
		"a Docker image": gr + "dockers_v2:\n  - images: [x]\n",
		"dist in build/": strings.Replace(gr, "dist: .cache/goreleaser", "dist: build/dist", 1),
		"no dist":        strings.Replace(gr, "dist: .cache/goreleaser", "", 1),
	} {
		if bad == gr {
			t.Errorf("the %s sample did not change src/.goreleaser.yaml", name)
			continue
		}
		if len(goreleaserProblems(bad)) == 0 {
			t.Errorf("goreleaserProblems accepted %s", name)
		}
	}
	extra := strings.Replace(gr, "      - linux_arm_7\n", "      - linux_arm_7\n      - linux_arm_6\n", 1)
	if extra == gr || slices.Equal(goreleaserTargets(extra), goreleaserTargets(gr)) {
		t.Error("goreleaserTargets did not see an added target")
	}

	for _, c := range []struct{ ref, comment string }{
		{"actions/checkout@v7.0.1", ""},
		{"actions/checkout@" + strings.Repeat("a", 40), "# 7.0.1"},
		{"golangci/golangci-lint-action@v9", ""},
		{"golangci/golangci-lint-action@" + strings.Repeat("a", 40), ""},
		{"golangci/golangci-lint-action@" + strings.Repeat("a", 40), "# v9"},
		{"simtabi/.github/.github/workflows/go-release.yml@main", ""},
		{"simtabi/.github/.github/workflows/go-release.yml@" + strings.Repeat("a", 40), ""},
		{"simtabi/.github/.github/workflows/go-release.yml@" + strings.Repeat("a", 40), "# v1"},
		{"simtabi/.github/.github/workflows/go-release.yml@" + strings.Repeat("a", 40), "# 1.0.0"},
		{"simtabi/.github/.github/workflows/go-release.yml@" + strings.Repeat("a", 40), "# simtabi/.github#30"},
	} {
		if pinProblem(c.ref, c.comment) == "" {
			t.Errorf("pinProblem accepted %s %s", c.ref, c.comment)
		}
	}
	for _, c := range []struct{ ref, comment string }{
		{"actions/checkout@v7", ""},
		{"github/codeql-action/init@v4", ""},
		{"golangci/golangci-lint-action@" + strings.Repeat("a", 40), "# 9.3.0"},
		{"simtabi/.github/.github/workflows/go-release.yml@" + strings.Repeat("a", 40), "# v1.0.0"},
	} {
		if p := pinProblem(c.ref, c.comment); p != "" {
			t.Errorf("pinProblem rejected %s %s: %s", c.ref, c.comment, p)
		}
	}
}
