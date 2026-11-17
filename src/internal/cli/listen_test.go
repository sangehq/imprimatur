//go:build !windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// shortState is a state folder short enough for a Unix socket path.
func shortState(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "is")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

// W2: impr serve's transports: the private Unix socket (0700 folder, 0600
// socket, a stale socket replaced, anything else refused), the default
// (the socket here), and a TCP port.
func TestServeListeners(t *testing.T) {
	state := shortState(t)
	ln, addr, err := listen(state, "unix")
	if errors.Is(err, syscall.EPERM) || (err != nil && strings.Contains(err.Error(), "operation not permitted")) {
		t.Skip("binding a socket is not permitted here (a sandbox); run outside it")
	}
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(state, "server", "impr.sock")
	if addr != "unix:"+sock {
		t.Fatalf("addr %s", addr)
	}
	for p, want := range map[string]os.FileMode{filepath.Dir(sock): 0o700, sock: 0o600} {
		if st, err := os.Stat(p); err != nil || st.Mode().Perm() != want {
			t.Errorf("%s: %v %v, want %o", p, st.Mode().Perm(), err, want)
		}
	}
	_ = ln.Close()
	// A socket left by an earlier run is replaced; the default is the socket.
	ln, addr, err = listen(state, "")
	if err != nil || !strings.HasPrefix(addr, "unix:") {
		t.Fatalf("default: %s %v", addr, err)
	}
	_ = ln.Close()
	_ = os.Remove(sock)
	if err := os.WriteFile(sock, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := listen(state, "unix"); err == nil || !strings.Contains(err.Error(), "is not a socket") {
		t.Fatalf("a file in the socket's place: %v", err)
	}
	tl, taddr, err := listen(state, "127.0.0.1:0")
	if err != nil || !strings.HasPrefix(taddr, "tcp:127.0.0.1:") {
		t.Fatalf("tcp: %s %v", taddr, err)
	}
	_ = tl.Close()
}
