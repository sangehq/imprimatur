package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCertInstallCheckPrintsOnly(t *testing.T) {
	h := newHarness(t)
	if code, _, errOut := h.impr("cert", "install-check"); code != 1 || !strings.Contains(errOut, "never installs") {
		t.Fatalf("without --print: %d %s", code, errOut)
	}
	exe := filepath.Join(t.TempDir(), "bin", "impr & co")
	for kind, want := range map[string]string{"systemd": "OnCalendar=daily", "launchd": "<string>cert</string>", "task": "<DaysInterval>1</DaysInterval>"} {
		code, out, errOut := h.impr("cert", "install-check", "--print", "--exe", exe, "--for", kind)
		if code != 0 || !strings.Contains(out, want) || !strings.Contains(errOut, "installed nothing") {
			t.Fatalf("%s: %d %s %s", kind, code, out, errOut)
		}
		if kind != "systemd" {
			wellFormedXML(t, out)
		}
	}
}

func TestDailyExpiryCheckIsOptInAndOnceADay(t *testing.T) {
	h := newHarness(t)
	soon := h.now.Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	sshProfile(t, h, "acme-release", "platforms.checksums.notAfter="+soon)
	stamp := filepath.Join(h.env["IMPR_STATE_DIR"], "notify", "last-expiry-check")

	h.ok("doctor")
	if _, err := os.Stat(stamp); !os.IsNotExist(err) {
		t.Fatal("the daily check ran without notify.checkOnCommand")
	}
	h.ok("config", "set", "notify.checkOnCommand", "true")
	h.ok("doctor")
	first, err := os.ReadFile(stamp)
	if err != nil {
		t.Fatalf("the daily check did not run: %v", err)
	}
	if ev := h.ok("events", "tail", "--json", "--type", "cert.*"); !strings.Contains(ev, "cert.expiring") {
		t.Fatalf("no expiry event: %s", ev)
	}
	h.now = h.now.Add(time.Hour)
	h.ok("doctor")
	if again, _ := os.ReadFile(stamp); string(again) != string(first) {
		t.Fatal("the check ran twice in one day")
	}
	h.now = h.now.Add(24 * time.Hour)
	h.ok("doctor")
	if again, _ := os.ReadFile(stamp); string(again) == string(first) {
		t.Fatal("the check did not run again the next day")
	}
}

func TestAnInterruptedRunExits130AndRestoresSignals(t *testing.T) {
	h := newHarness(t)
	var errOut strings.Builder
	a := &App{Stdout: &strings.Builder{}, Stderr: &errOut, Getenv: func(k string) string { return h.env[k] }, GOOS: h.os, Home: t.TempDir(),
		User: "tester", Runner: h.run, Now: func() time.Time { return h.now }}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	restored := make(chan struct{})
	if code := a.RunInterruptible(ctx, func() { close(restored) }, []string{"doctor"}); code != InterruptedExit {
		t.Fatalf("exit %d, want %d", code, InterruptedExit)
	}
	select {
	case <-restored:
	case <-time.After(5 * time.Second):
		t.Fatal("the default signal handling was not restored")
	}
	if !strings.Contains(errOut.String(), "interrupted") {
		t.Fatalf("no interrupted message: %s", errOut.String())
	}
}
