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

// releaseProblems checks release.yml: dispatch-only, a required confirm input,
// and a first step that refuses without confirm=release-go on a v[0-9]* tag.
func releaseProblems(text string) []string {
	var problems []string
	names := triggers(text)
	if len(names) != 1 || names[0] != "workflow_dispatch" {
		problems = append(problems, "release.yml triggers on "+strings.Join(names, ", ")+"; want workflow_dispatch only")
	}

	// inputs.confirm with required: true.
	block, _, _ := onBlock(text)
	confirmAt, required := -1, false
	for _, l := range block {
		if isBlankOrComment(l) {
			continue
		}
		if confirmAt >= 0 {
			if indentOf(l) <= confirmAt {
				break
			}
			if regexp.MustCompile(`^\s*required\s*:\s*true\s*(#.*)?$`).MatchString(l) {
				required = true
			}
			continue
		}
		if m := keyLine.FindStringSubmatch(l); m != nil && m[1] == "confirm" {
			confirmAt = indentOf(l)
		}
	}
	if confirmAt < 0 {
		problems = append(problems, "release.yml has no confirm input")
	} else if !required {
		problems = append(problems, "release.yml's confirm input is not required: true")
	}

	// The first step of the job.
	step := firstStep(text)
	if step == "" {
		problems = append(problems, "release.yml has no steps")
	} else {
		for _, want := range []string{"refs/tags/v[0-9]*", "exit 1"} {
			if !strings.Contains(step, want) {
				problems = append(problems, "release.yml's first step does not check "+want)
			}
		}
		// The confirmation must be compared, not merely mentioned in a message.
		if !regexp.MustCompile(`!=\s*"?release-go"?`).MatchString(step) {
			problems = append(problems, "release.yml's first step does not refuse unless confirm is release-go")
		}
		if regexp.MustCompile(`(?m)^\s*-?\s*uses\s*:`).MatchString(step) {
			problems = append(problems, "release.yml's first step is an action, not the refusal")
		}
	}
	return problems
}

// firstStep returns the text of the first step under the first `steps:` key.
func firstStep(text string) string {
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if !regexp.MustCompile(`^\s*steps\s*:\s*$`).MatchString(l) {
			continue
		}
		var step []string
		itemIndent := -1
		for _, s := range lines[i+1:] {
			if isBlankOrComment(s) {
				if itemIndent >= 0 {
					step = append(step, s)
				}
				continue
			}
			if itemIndent < 0 {
				if !strings.HasPrefix(strings.TrimSpace(s), "- ") {
					return ""
				}
				itemIndent = indentOf(s)
				step = append(step, s)
				continue
			}
			if indentOf(s) < itemIndent || (indentOf(s) == itemIndent && strings.HasPrefix(strings.TrimSpace(s), "-")) {
				break
			}
			step = append(step, s)
		}
		return strings.Join(step, "\n")
	}
	return ""
}

var (
	usesLine     = regexp.MustCompile(`^\s*-?\s*uses\s*:\s*['"]?([^\s'"#]+)['"]?\s*(#.*)?$`)
	majorTag     = regexp.MustCompile(`^v[0-9]+$`)
	fullSHA      = regexp.MustCompile(`^[0-9a-f]{40}$`)
	releaseNote  = regexp.MustCompile(`^#\s*v?[0-9]+\.[0-9]+\.[0-9]+\s*$`)
	floatsOwners = map[string]bool{"actions": true, "docker": true, "github": true}
)

// pinProblem returns why an action reference has the wrong form, or "".
// actions/*, docker/* and github/* float on a major tag; every other action is
// a 40-hex commit SHA followed by a `# x.y.z` comment.
func pinProblem(ref, comment string) string {
	if strings.HasPrefix(ref, "./") || strings.HasPrefix(ref, "docker://") {
		return ""
	}
	action, version, ok := strings.Cut(ref, "@")
	if !ok {
		return ref + " has no @ref"
	}
	owner, _, _ := strings.Cut(action, "/")
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

// TestReleaseIsConfirmedDispatchOnly: pushing a tag publishes nothing.
func TestReleaseIsConfirmedDispatchOnly(t *testing.T) {
	text := readFile(t, filepath.Join(repoRoot(t), ".github", "workflows", "release.yml"))
	for _, p := range releaseProblems(text) {
		t.Error(p)
	}
	atLeast(t, "release.yml triggers", len(triggers(text)), 1)
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

	tagRelease := "on:\n  push:\n    tags: ['v*']\n  workflow_dispatch:\n    inputs:\n      confirm:\n        required: true\njobs:\n  r:\n    steps:\n      - run: |\n          [ \"$C\" != release-go ] && exit 1\n          case \"$GITHUB_REF\" in refs/tags/v[0-9]*) ;; *) exit 1;; esac\n"
	if len(releaseProblems(tagRelease)) == 0 {
		t.Error("releaseProblems accepted a tag push trigger")
	}
	optional := strings.Replace(strings.Replace(tagRelease, "  push:\n    tags: ['v*']\n", "", 1), "required: true", "required: false", 1)
	if ps := releaseProblems(optional); len(ps) != 1 {
		t.Errorf("releaseProblems on an optional confirm: want 1 problem, got %v", ps)
	}
	checkoutFirst := strings.Replace(strings.Replace(tagRelease, "  push:\n    tags: ['v*']\n", "", 1), "      - run: |", "      - uses: actions/checkout@v7\n      - run: |", 1)
	if len(releaseProblems(checkoutFirst)) == 0 {
		t.Error("releaseProblems accepted a first step that is not the refusal")
	}

	for _, c := range []struct{ ref, comment string }{
		{"actions/checkout@v7.0.1", ""},
		{"actions/checkout@" + strings.Repeat("a", 40), "# 7.0.1"},
		{"golangci/golangci-lint-action@v9", ""},
		{"golangci/golangci-lint-action@" + strings.Repeat("a", 40), ""},
		{"golangci/golangci-lint-action@" + strings.Repeat("a", 40), "# v9"},
	} {
		if pinProblem(c.ref, c.comment) == "" {
			t.Errorf("pinProblem accepted %s %s", c.ref, c.comment)
		}
	}
	for _, c := range []struct{ ref, comment string }{
		{"actions/checkout@v7", ""},
		{"github/codeql-action/init@v4", ""},
		{"golangci/golangci-lint-action@" + strings.Repeat("a", 40), "# 9.3.0"},
	} {
		if p := pinProblem(c.ref, c.comment); p != "" {
			t.Errorf("pinProblem rejected %s %s: %s", c.ref, c.comment, p)
		}
	}
}

func TestReleaseGuardNeedsTheComparison(t *testing.T) {
	mentioned := "on:\n  workflow_dispatch:\n    inputs:\n      confirm:\n        required: true\njobs:\n  r:\n    steps:\n      - run: |\n          if [ \"$C\" != anything ]; then echo \"confirm must be release-go\"; exit 1; fi\n          case \"$GITHUB_REF\" in refs/tags/v[0-9]*) ;; *) exit 1;; esac\n"
	if len(releaseProblems(mentioned)) == 0 {
		t.Error("releaseProblems accepted a step that only mentions release-go")
	}
}
