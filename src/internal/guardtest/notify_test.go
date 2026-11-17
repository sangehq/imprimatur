package guardtest

import (
	"regexp"
	"sort"
	"testing"
)

// notifierCalls finds code that shows a desktop notification itself instead
// of through go-notifykit (estate rule: Go programs notify through it).
var notifierCalls = regexp.MustCompile(`osascript|terminal-notifier|notify-send|ToastNotification`)

func ownNotifiers(files map[string]string) []string {
	var out []string
	for rel, src := range files {
		if notifierCalls.MatchString(src) {
			out = append(out, rel)
		}
	}
	sort.Strings(out)
	return out
}

// TestNotificationsGoThroughNotifykit: no impr source calls a platform
// notifier directly.
func TestNotificationsGoThroughNotifykit(t *testing.T) {
	files := sources(t)
	atLeast(t, "Go source files", len(files), 20)
	if got := ownNotifiers(files); len(got) > 0 {
		t.Errorf("these call a desktop notifier directly; use internal/notify (go-notifykit): %v", got)
	}
}

func TestNotifyGuardCanFail(t *testing.T) {
	bad := map[string]string{"internal/x/x.go": "package x\nvar cmd = \"osascript\"\n"}
	if got := ownNotifiers(bad); len(got) != 1 {
		t.Fatal("the guard missed a direct osascript call")
	}
}
