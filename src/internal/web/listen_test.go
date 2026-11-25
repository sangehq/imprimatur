package web

import (
	"errors"
	"net"
	"strconv"
	"syscall"
	"testing"
)

type fakeListener struct{ net.Listener }

// fakeListen binds nothing: taken ports answer EADDRINUSE.
func fakeListen(taken map[int]bool, tried *[]string) ListenFunc {
	return func(_, addr string) (net.Listener, error) {
		*tried = append(*tried, addr)
		_, p, _ := net.SplitHostPort(addr)
		n, _ := strconv.Atoi(p)
		if taken[n] {
			return nil, &net.OpError{Op: "listen", Err: syscall.EADDRINUSE}
		}
		return fakeListener{}, nil
	}
}

// The default port falls back to the next free one, then to any free port; a
// pinned port fails when taken (owner decision 2026-11-25).
func TestListenFallsBackUnlessPinned(t *testing.T) {
	if DefaultPort != 7823 {
		t.Fatalf("DefaultPort is %d; imprimatur's is 7823 (authama 7822, sange 7821)", DefaultPort)
	}
	var tried []string
	if _, err := Listen(fakeListen(map[int]bool{7823: true, 7824: true}, &tried), "127.0.0.1", 7823, false, DefaultPortAttempts); err != nil {
		t.Fatal(err)
	}
	if tried[len(tried)-1] != "127.0.0.1:7825" {
		t.Fatalf("tried %v", tried)
	}
	tried = nil
	all := map[int]bool{}
	for p := 7823; p < 7823+DefaultPortAttempts; p++ {
		all[p] = true
	}
	if _, err := Listen(fakeListen(all, &tried), "127.0.0.1", 7823, false, DefaultPortAttempts); err != nil || tried[len(tried)-1] != "127.0.0.1:0" {
		t.Fatalf("a full range did not take any free port: %v %v", err, tried)
	}
	tried = nil
	_, err := Listen(fakeListen(map[int]bool{7900: true}, &tried), "127.0.0.1", 7900, true, DefaultPortAttempts)
	if err == nil || len(tried) != 1 || !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("a pinned, taken port: %v after %v", err, tried)
	}
}

func TestAllowedHostsAreThisMachineAtThePort(t *testing.T) {
	got := AllowedHosts(7823)
	want := []string{"127.0.0.1:7823", "localhost:7823", "[::1]:7823"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v, want %v", got, want)
		}
	}
}
