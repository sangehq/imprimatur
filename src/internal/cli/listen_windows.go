//go:build windows

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// listenDefault is the transport when server.listen is unset: on Windows, a
// named pipe only the user impr runs as can open (design §7). Unix socket
// modes mean nothing on Windows, so "unix" is used only when set.
func listenDefault(state string) (net.Listener, string, error) {
	p := pipePath(state)
	ln, err := listenPipe(p)
	if err != nil {
		return nil, "", err
	}
	return ln, "pipe:" + p, nil
}

// pipePath names the pipe after the state directory, so two installs (or two
// users) never share one.
func pipePath(state string) string {
	h := sha256.Sum256([]byte(strings.ToLower(state)))
	return `\\.\pipe\imprimatur-` + hex.EncodeToString(h[:8])
}

// ownerOnlySDDL is a protected DACL with one entry: full access for sid.
func ownerOnlySDDL(sid string) string { return "D:P(A;;GA;;;" + sid + ")" }

const pipeBuffer = 64 << 10

type pipeListener struct {
	path  string
	sa    *windows.SecurityAttributes
	stop  windows.Handle // signalled by Close
	mu    sync.Mutex
	next  windows.Handle // the instance the next Accept waits on
	once  sync.Once
	close error
}

// listenPipe creates the first instance with FILE_FLAG_FIRST_PIPE_INSTANCE,
// so a pipe another process already holds under this name is an error, not a
// server that hands requests to it.
func listenPipe(path string) (*pipeListener, error) {
	tok := windows.GetCurrentProcessToken()
	user, err := tok.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read the current user: %w", err)
	}
	sd, err := windows.SecurityDescriptorFromString(ownerOnlySDDL(user.User.Sid.String()))
	if err != nil {
		return nil, fmt.Errorf("build the pipe's security descriptor: %w", err)
	}
	sa := &windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(*sa))
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return nil, err
	}
	l := &pipeListener{path: path, sa: sa, stop: stop}
	h, err := l.instance(true)
	if err != nil {
		_ = windows.CloseHandle(stop)
		return nil, err
	}
	l.next = h
	return l, nil
}

func (l *pipeListener) instance(first bool) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(l.path)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.PIPE_ACCESS_DUPLEX | windows.FILE_FLAG_OVERLAPPED)
	if first {
		flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
	}
	mode := uint32(windows.PIPE_TYPE_BYTE | windows.PIPE_READMODE_BYTE | windows.PIPE_WAIT | windows.PIPE_REJECT_REMOTE_CLIENTS)
	h, err := windows.CreateNamedPipe(name, flags, mode, windows.PIPE_UNLIMITED_INSTANCES, pipeBuffer, pipeBuffer, 0, l.sa)
	if err != nil {
		if first && errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return 0, fmt.Errorf("%s is already in use (another impr serve, or another program holding the name): %w", l.path, err)
		}
		return 0, fmt.Errorf("create %s: %w", l.path, err)
	}
	return h, nil
}

// Accept waits for a client on the pending instance, then makes the next
// one, so a client never finds the pipe missing between connections. A
// client that connected and left before Accept ran (ERROR_NO_DATA) is
// dropped and Accept waits again: returning that error stopped the server,
// so any local client could take impr serve down (found on Windows
// 2026-11-17).
func (l *pipeListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for {
		if l.next == 0 {
			h, err := l.instance(false)
			if err != nil {
				return nil, err
			}
			l.next = h
		}
		h := l.next
		err := l.connect(h)
		if errors.Is(err, windows.ERROR_NO_DATA) {
			_ = windows.DisconnectNamedPipe(h)
			_ = windows.CloseHandle(h)
			l.next = 0
			continue
		}
		if err != nil {
			return nil, err
		}
		l.next = 0
		if nh, err := l.instance(false); err == nil {
			l.next = nh
		}
		// The handle is overlapped, so os.NewFile hands it to the runtime's I/O
		// completion port: reads and writes run concurrently, and deadlines work.
		return pipeConn{File: os.NewFile(uintptr(h), l.path), addr: pipeAddr(l.path)}, nil
	}
}

// connect waits for a client on instance h, or for Close.
func (l *pipeListener) connect(h windows.Handle) error {
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return err
	}
	defer func() { _ = windows.CloseHandle(ev) }()
	ov := &windows.Overlapped{HEvent: ev}
	err = windows.ConnectNamedPipe(h, ov)
	switch {
	case err == nil, errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		return nil
	case errors.Is(err, windows.ERROR_IO_PENDING):
		w, werr := windows.WaitForMultipleObjects([]windows.Handle{ev, l.stop}, false, windows.INFINITE)
		if werr != nil {
			return werr
		}
		if w != windows.WAIT_OBJECT_0 {
			_ = windows.CancelIoEx(h, ov)
			var n uint32
			_ = windows.GetOverlappedResult(h, ov, &n, true)
			return net.ErrClosed
		}
		var n uint32
		return windows.GetOverlappedResult(h, ov, &n, false)
	default:
		return err
	}
}

// Close stops Accept and closes the pending instance.
func (l *pipeListener) Close() error {
	l.once.Do(func() {
		l.close = windows.SetEvent(l.stop)
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.next != 0 {
			_ = windows.CloseHandle(l.next)
			l.next = 0
		}
	})
	return l.close
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr(l.path) }

type pipeAddr string

func (pipeAddr) Network() string  { return "pipe" }
func (a pipeAddr) String() string { return string(a) }

// pipeConn is a pipe instance as a net.Conn.
type pipeConn struct {
	*os.File
	addr pipeAddr
}

func (c pipeConn) LocalAddr() net.Addr  { return c.addr }
func (c pipeConn) RemoteAddr() net.Addr { return c.addr }
