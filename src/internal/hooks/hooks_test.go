package hooks

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/events"
	"github.com/sangehq/imprimatur/src/internal/execx"
)

// script writes an executable shell script and returns its path and pin.
func script(t *testing.T, body string) (string, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script hooks are a Unix test")
	}
	p := filepath.Join(t.TempDir(), "hook.sh")
	b := []byte("#!/bin/sh\n" + body + "\n")
	if err := os.WriteFile(p, b, 0o700); err != nil { //nolint:gosec // G306: a test hook must be executable
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return p, hex.EncodeToString(s[:])
}

func sampleEvent(t *testing.T) events.Event {
	t.Helper()
	ev, err := events.Env{Now: time.Now, NewID: events.NewID, InstallID: "0123456789abcdef"}.New("signing.run.started", "s", map[string]any{"runId": "r"})
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestCheckPinnedRefusals(t *testing.T) {
	p, pin := script(t, "exit 0")
	if _, err := execx.CheckPinned(p, pin); err != nil {
		t.Fatalf("a good pin: %v", err)
	}
	cases := map[string]func() (string, string){
		"relative path": func() (string, string) { return "hook.sh", pin },
		"wrong pin":     func() (string, string) { return p, strings.Repeat("0", 64) },
		"no pin":        func() (string, string) { return p, "" },
		"symlink": func() (string, string) {
			l := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(p, l); err != nil {
				t.Fatal(err)
			}
			return l, pin
		},
		"group-writable": func() (string, string) {
			q, qp := script(t, "exit 0")
			if err := os.Chmod(q, 0o770); err != nil { //nolint:gosec // G302: the group-writable case under test
				t.Fatal(err)
			}
			return q, qp
		},
	}
	for name, mk := range cases {
		path, pn := mk()
		if _, err := execx.CheckPinned(path, pn); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestPreHookVetoAndSecretFreeEnvironment(t *testing.T) {
	t.Setenv("IMPR_RELEASE_KEY", "very-secret")
	out := filepath.Join(t.TempDir(), "seen")
	p, pin := script(t, `env > "`+out+`.env"; cat > "`+out+`"; exit 7`)
	ev := sampleEvent(t)

	r := &Runner{Hooks: []config.Hook{{Name: "gate", Phase: config.PhasePreSign, Exec: p, SHA256: pin, Veto: true}}}
	err := r.Pre(context.Background(), config.PhasePreSign, ev)
	var v *Vetoed
	if err == nil || !strings.Contains(err.Error(), "exit 7") {
		t.Fatalf("veto: %v", err)
	}
	_ = v
	env, _ := os.ReadFile(out + ".env")
	if strings.Contains(string(env), "very-secret") || !strings.Contains(string(env), "IMPR_EVENT_TYPE=sh.sange.imprimatur.signing.run.started") {
		t.Fatalf("hook environment:\n%s", env)
	}
	var got events.Event
	if b, _ := os.ReadFile(out); json.Unmarshal(b, &got) != nil || got.ID != ev.ID {
		t.Fatalf("stdin did not carry the event: %s", b)
	}

	// Without veto, a non-zero exit is a warning, not a refusal.
	r.Hooks[0].Veto = false
	warned := false
	r.Warn = func(string, ...any) { warned = true }
	if err := r.Pre(context.Background(), config.PhasePreSign, ev); err != nil || !warned {
		t.Fatalf("non-veto: %v warned=%v", err, warned)
	}

	// A pre-hook that cannot run (its file changed after pinning) stops the run.
	if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil { //nolint:gosec // G306: a test hook must be executable
		t.Fatal(err)
	}
	if err := r.Pre(context.Background(), config.PhasePreSign, ev); err == nil {
		t.Fatal("a re-written hook ran")
	}
}

func TestEventHookRunsOnlyForMatchingTypes(t *testing.T) {
	out := filepath.Join(t.TempDir(), "count")
	p, pin := script(t, `echo x >> "`+out+`"`)
	r := &Runner{Hooks: []config.Hook{{Name: "n", Phase: config.PhaseEvent, On: []string{"verification.*"}, Exec: p, SHA256: pin}}}
	_ = r.Write(context.Background(), sampleEvent(t)) // signing.run.started: no match
	ev, _ := events.Env{Now: time.Now, NewID: events.NewID, InstallID: "0123456789abcdef"}.New("verification.run.completed", "p", map[string]any{})
	_ = r.Write(context.Background(), ev)
	b, _ := os.ReadFile(out)
	if strings.Count(string(b), "x") != 1 {
		t.Fatalf("hook ran %d times, want 1", strings.Count(string(b), "x"))
	}
}

func TestConfigRefusesUnsafeHooks(t *testing.T) {
	dir := t.TempDir()
	write := func(s string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, config.File), []byte(s), mode); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(filepath.Join(dir, config.File), mode)
	}
	pin := strings.Repeat("a", 64)
	for name, body := range map[string]string{
		"relative exec":   `{"schema":"imprimatur.config/v1","hooks":[{"name":"a","phase":"pre-sign","exec":"x.sh","sha256":"` + pin + `"}]}`,
		"no pin":          `{"schema":"imprimatur.config/v1","hooks":[{"name":"a","phase":"pre-sign","exec":"/x.sh"}]}`,
		"unknown field":   `{"schema":"imprimatur.config/v1","hookz":[]}`,
		"veto on event":   `{"schema":"imprimatur.config/v1","hooks":[{"name":"a","phase":"event","veto":true,"exec":"/x.sh","sha256":"` + pin + `"}]}`,
		"misspelt filter": `{"schema":"imprimatur.config/v1","hooks":[{"name":"a","phase":"event","on":["signin.*"],"exec":"/x.sh","sha256":"` + pin + `"}]}`,
	} {
		write(body, 0o600)
		if _, err := config.Load(dir); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	write(`{"schema":"imprimatur.config/v1"}`, 0o600)
	if _, err := config.Load(dir); err != nil {
		t.Fatalf("a valid config: %v", err)
	}
	if runtime.GOOS != "windows" {
		write(`{"schema":"imprimatur.config/v1"}`, 0o666)
		if _, err := config.Load(dir); err == nil {
			t.Error("a world-writable config.json was accepted")
		}
	}
}

func TestConfigToolPinsAndPolicy(t *testing.T) {
	dir := t.TempDir()
	gpgPath := filepath.ToSlash(filepath.Join(t.TempDir(), "gpg"))
	good := `{"schema":"imprimatur.config/v1","policy":{"gpgFullFingerprint":true},"tools":{"gpg":{"path":"` + gpgPath + `","sha256":"` + strings.Repeat("a", 64) + `"}}}`
	if err := os.WriteFile(filepath.Join(dir, config.File), []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(dir)
	if err != nil || !c.Policy.RequireFullGPG() || c.Tools["gpg"].Path != gpgPath {
		t.Fatalf("%+v %v", c, err)
	}
	for name, body := range map[string]string{
		"unknown tool":  `{"schema":"imprimatur.config/v1","tools":{"curl":{"path":"/usr/bin/curl","sha256":"` + strings.Repeat("a", 64) + `"}}}`,
		"relative path": `{"schema":"imprimatur.config/v1","tools":{"gpg":{"path":"gpg","sha256":"` + strings.Repeat("a", 64) + `"}}}`,
		"no digest":     `{"schema":"imprimatur.config/v1","tools":{"gpg":{"path":"` + gpgPath + `"}}}`,
	} {
		if err := os.WriteFile(filepath.Join(dir, config.File), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Load(dir); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// The full-fingerprint policy is on unless a config turns it off explicitly.
func TestFullGPGPolicyDefaultsOn(t *testing.T) {
	off := false
	if !(config.Policy{}).RequireFullGPG() || (config.Policy{GPGFullFingerprint: &off}).RequireFullGPG() {
		t.Fatal("policy.gpgFullFingerprint: unset must mean on, false must mean off")
	}
}
