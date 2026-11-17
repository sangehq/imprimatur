//go:build windows

package cli

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// dialPipe opens the pipe as a client does: ERROR_PIPE_BUSY means every
// instance is taken for the moment (the server makes the next one as it
// accepts), so a client waits and tries again, as .NET's
// NamedPipeClientStream and go-winio's DialPipe do.
func dialPipe(path string) (net.Conn, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL, 0, nil,
			windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
		if err == nil {
			return pipeConn{File: os.NewFile(uintptr(h), path), addr: pipeAddr(path)}, nil
		}
		if !errors.Is(err, windows.ERROR_PIPE_BUSY) || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNamedPipeServesOnlyItsOwner(t *testing.T) {
	ln, where, err := listenDefault(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path, ok := strings.CutPrefix(where, "pipe:")
	if !ok || !strings.HasPrefix(path, `\\.\pipe\imprimatur-`) {
		t.Fatalf("where %q", where)
	}

	// A second server cannot take the name while this one holds it.
	if _, err := listenPipe(path); err == nil {
		t.Fatal("a second listener took the pipe")
	}

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }),
		ReadHeaderTimeout: 5 * time.Second}
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	// The DACL is protected and holds one entry: the current user.
	c, err := dialPipe(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(c.(pipeConn).Fd()), windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	// SDDL may print a well-known account by alias ("LA" for the built-in
	// Administrator a CI runner uses), so compare the SIDs, not the text.
	sddl := sd.String()
	if !strings.HasPrefix(sddl, "D:P") || strings.Count(sddl, "(A;") != 1 || !strings.HasSuffix(sddl, ")") {
		t.Fatalf("pipe DACL %s: want one protected allow entry", sddl)
	}
	trustee := sddl[strings.LastIndex(sddl, ";")+1 : len(sddl)-1]
	sid, err := windows.StringToSid(trustee)
	if err != nil || !sid.Equals(user.User.Sid) {
		t.Fatalf("pipe DACL %s grants %q, not the current user %s (%v)", sddl, trustee, user.User.Sid, err)
	}
	_ = c.Close()

	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		DialContext: func(context.Context, string, string) (net.Conn, error) { return dialPipe(path) }}}
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for range 6 { // concurrent clients: each gets its own instance
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get("http://impr/v1/health")
			if err != nil {
				errs <- err
				return
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if string(b) != "ok" {
				errs <- errors.New("body " + string(b))
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	_ = srv.Close()
	select {
	case err := <-served:
		if !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("closing the listener did not stop Accept")
	}
}
