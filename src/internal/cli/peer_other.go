//go:build !linux && !darwin

package cli

import (
	"errors"
	"net"
)

var errPeerUnsupported = errors.New("peer credentials are not read on this platform")

// peerUID is not read here, so the socket's file modes are the check. On
// Windows impr serves a named pipe by default, whose DACL is the check.
func peerUID(*net.UnixConn) (int, error) { return -1, errPeerUnsupported }
