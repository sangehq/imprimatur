package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"
)

func fixedEnv() Env {
	n := 0
	return Env{Now: func() time.Time { return time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC) },
		NewID: func() string { n++; return fmt.Sprintf("id-%d", n) }, InstallID: "0123456789abcdef"}
}

func TestNewBuildsACloudEventOfACataloguedType(t *testing.T) {
	ev, err := fixedEnv().New("signing.run.started", "github.com/acme/tool", map[string]any{"runId": "r1"})
	if err != nil {
		t.Fatal(err)
	}
	if ev.SpecVersion != "1.0" || ev.Type != "sh.sange.imprimatur.signing.run.started" || ev.Source != "https://sange.sh/imprimatur/install/0123456789abcdef" ||
		ev.DataContentType != "application/json" || ev.Class != ClassInternal || ev.Short() != "signing.run.started" {
		t.Fatalf("%+v", ev)
	}
	if _, err := fixedEnv().New("signing.run.invented", "", map[string]any{}); err == nil {
		t.Fatal("an uncatalogued type was accepted")
	}
	if _, err := fixedEnv().New("signing.run.started", "", []int{1}); err == nil {
		t.Fatal("non-object data was accepted")
	}
}

// Every catalogued type is a valid CloudEvents type under the prefix, and
// every one has a class. The count is asserted so an emptied map fails.
func TestCatalogueShape(t *testing.T) {
	if len(Catalogue) < 15 {
		t.Fatalf("catalogue has %d types, want at least 15", len(Catalogue))
	}
	re := regexp.MustCompile(`^[a-z0-9.-]+$`)
	for short, class := range Catalogue {
		if !re.MatchString(TypePrefix+short) || (class != ClassInternal && class != ClassLocal) {
			t.Errorf("%s: class %q", short, class)
		}
		// Every catalogued type can actually be built: a catalogue entry New
		// refuses would be dropped with only a warning at emit time.
		if _, err := fixedEnv().New(short, "s", map[string]any{}); err != nil {
			t.Errorf("%s cannot be emitted: %v", short, err)
		}
	}
}

func TestLogChainsAndDetectsTampering(t *testing.T) {
	l := Log{Dir: filepath.Join(t.TempDir(), "events")}
	bus := &Bus{Env: fixedEnv(), Sinks: []Sink{l}, Warn: func(f string, a ...any) { t.Fatalf(f, a...) }}
	for i := 0; i < 3; i++ {
		bus.Emit(context.Background(), "verification.run.completed", "p", map[string]any{"n": i})
	}
	n, err := l.Verify()
	if err != nil || n != 3 {
		t.Fatalf("verify: %d %v", n, err)
	}
	files, _ := l.files()
	if len(files) != 1 {
		t.Fatalf("files %v", files)
	}
	if st, _ := os.Stat(files[0]); st.Mode().Perm() != 0o600 {
		t.Fatalf("log mode %v", st.Mode().Perm())
	}
	b, _ := os.ReadFile(files[0])
	tampered := bytes.Replace(b, []byte(`"n":1`), []byte(`"n":9`), 1)
	if err := os.WriteFile(files[0], tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Verify(); err == nil {
		t.Fatal("an edited line was not detected")
	}
	// Removing a line is detected too.
	lines := bytes.SplitAfter(b, []byte("\n"))
	if err := os.WriteFile(files[0], append(lines[0], lines[2]...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Verify(); err == nil {
		t.Fatal("a removed line was not detected")
	}
	var ev Event
	_ = json.Unmarshal(lines[1], &ev)
	if ev.Prev == "" {
		t.Fatal("the second event carries no imprprev")
	}
}

func TestInstallIDIsStableAndPrivate(t *testing.T) {
	dir := t.TempDir()
	a, err := InstallID(dir)
	if err != nil || !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(a) {
		t.Fatalf("%q %v", a, err)
	}
	b, _ := InstallID(dir)
	if a != b {
		t.Fatal("install id changed")
	}
	if st, _ := os.Stat(filepath.Join(dir, "install-id")); st.Mode().Perm() != 0o600 {
		t.Fatal("install-id is not 0600")
	}
}

func TestMatches(t *testing.T) {
	for glob, want := range map[string]bool{"*": true, "signing.*": true, "sh.sange.imprimatur.signing.*": true, "cert.*": false, "signing.run.failed": false} {
		if got := Matches(glob, "sh.sange.imprimatur.signing.run.started"); got != want {
			t.Errorf("%s: %v", glob, got)
		}
	}
}

// The newest line has no successor to chain to it; the head file catches an
// edit to it.
func TestLogDetectsAnEditedNewestLine(t *testing.T) {
	l := Log{Dir: filepath.Join(t.TempDir(), "events")}
	bus := &Bus{Env: fixedEnv(), Sinks: []Sink{l}}
	bus.Emit(context.Background(), "verification.run.completed", "p", map[string]any{"n": 1})
	bus.Emit(context.Background(), "verification.run.completed", "p", map[string]any{"n": 2})
	files, _ := l.files()
	b, _ := os.ReadFile(files[0])
	if err := os.WriteFile(files[0], bytes.Replace(b, []byte(`"n":2`), []byte(`"n":3`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Verify(); err == nil {
		t.Fatal("an edited newest line was not detected")
	}
}
