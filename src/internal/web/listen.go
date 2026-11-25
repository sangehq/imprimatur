package web

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
)

// DefaultPort is where the web UI listens unless --port pins another: one
// fixed port per sange project, so none collide (authama 7822, sange 7821;
// owner decision 2026-11-25).
const DefaultPort = 7823

// DefaultPortAttempts bounds how far past a taken default port Listen looks.
const DefaultPortAttempts = 20

// ListenFunc is net.Listen's signature, so the fallback is tested without
// binding a socket.
type ListenFunc func(network, address string) (net.Listener, error)

// Listen binds host:port. Unpinned, a taken port moves to the next one up, for
// attempts ports in all, and then to any free port: the caller prints the
// address actually bound. Pinned (--port), a taken port is an error, because
// serving elsewhere would leave whatever was pointed at that port talking to
// something else. Any error but "address in use" stops at once.
func Listen(listen ListenFunc, host string, port int, pinned bool, attempts int) (net.Listener, error) {
	if listen == nil {
		listen = net.Listen
	}
	if attempts < 1 || pinned || port == 0 {
		attempts = 1
	}
	var first error
	for i := 0; i < attempts; i++ {
		p := port + i
		if p > 65535 {
			break
		}
		ln, err := listen("tcp", net.JoinHostPort(host, strconv.Itoa(p)))
		if err == nil {
			return ln, nil
		}
		if first == nil {
			first = err
		}
		if !IsAddrInUse(err) {
			return nil, err
		}
		if pinned {
			return nil, fmt.Errorf("port %d is already in use; pick another with --port, or leave --port out to take the next free one: %w", p, err)
		}
	}
	if attempts > 1 {
		if ln, err := listen("tcp", net.JoinHostPort(host, "0")); err == nil {
			return ln, nil
		}
	}
	return nil, fmt.Errorf("ports %d-%d are all in use: %w", port, port+attempts-1, first)
}

// IsAddrInUse reports whether a listen error means the port is taken.
func IsAddrInUse(err error) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	// Windows reports WSAEADDRINUSE, which does not unwrap to EADDRINUSE.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address already in use") || strings.Contains(msg, "only one usage of each socket address")
}

// AllowedHosts are the Host header values a loopback web UI answers: this
// machine's three spellings at the bound port. A page on evil.example that
// rebinds its name to 127.0.0.1 still sends Host: evil.example.
func AllowedHosts(port int) []string {
	p := strconv.Itoa(port)
	return []string{net.JoinHostPort("127.0.0.1", p), net.JoinHostPort("localhost", p), net.JoinHostPort("::1", p)}
}
