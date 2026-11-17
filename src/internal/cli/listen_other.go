//go:build !windows

package cli

import "net"

// listenDefault is the transport when server.listen is unset: the Unix
// socket.
func listenDefault(state string) (net.Listener, string, error) { return listenUnix(state) }
