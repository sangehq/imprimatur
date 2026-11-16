//go:build !linux

package cli

import (
	"errors"
	"net"
)

var errPeerUnsupported = errors.New("peer credentials are not read on this platform")

// peerUID is not available from the standard library here (macOS needs
// LOCAL_PEERCRED from golang.org/x/sys), so the socket's file modes are the
// check.
func peerUID(*net.UnixConn) (int, error) { return -1, errPeerUnsupported }
