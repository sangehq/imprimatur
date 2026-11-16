package cli

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestPeerListenerRefusesAnotherUser: on Linux a connection whose peer uid
// is not the server's is closed and reported; one from the same user goes
// through. The other user is simulated by telling the listener it runs as
// someone else.
func TestPeerListenerRefusesAnotherUser(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("peer credentials are read on Linux only")
	}
	sock := filepath.Join(t.TempDir(), "s.sock")
	raw, err := net.Listen("unix", sock)
	if err != nil {
		t.Skipf("cannot listen on a Unix socket here: %v", err)
	}
	defer func() { _ = raw.Close() }()
	refusedUID := make(chan int, 4)
	accept := func(uid int) (net.Conn, error) {
		ln := peerListener{Listener: raw, uid: uid, refused: func(u int) { refusedUID <- u }}
		type res struct {
			c   net.Conn
			err error
		}
		ch := make(chan res, 1)
		go func() { c, err := ln.Accept(); ch <- res{c, err} }()
		c, err := net.Dial("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = c.Close() }()
		select {
		case r := <-ch:
			return r.c, r.err
		case <-time.After(300 * time.Millisecond):
			return nil, nil // still waiting: the connection was refused
		}
	}
	if c, err := accept(os.Getuid()); err != nil || c == nil {
		t.Fatalf("the same user was refused: %v", err)
	}
	if c, _ := accept(os.Getuid() + 1); c != nil {
		t.Fatal("another user's connection was accepted")
	}
	select {
	case u := <-refusedUID:
		if u != os.Getuid() {
			t.Fatalf("refused uid %d, want %d", u, os.Getuid())
		}
	case <-time.After(time.Second):
		t.Fatal("the refusal was not reported")
	}
}
