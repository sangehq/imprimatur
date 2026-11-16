package cli

import (
	"errors"
	"net"
)

// peerListener drops each Unix-socket connection whose peer is not the user
// impr runs as (design §7), on the platforms where the standard library can
// read the peer's uid (peerUID). Elsewhere the socket's 0700 directory and
// 0600 mode are the whole check.
type peerListener struct {
	net.Listener
	uid     int
	refused func(uid int)
}

// Accept returns the next connection from the same user, closing others.
func (l peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uc, ok := c.(*net.UnixConn)
		if !ok {
			return c, nil
		}
		uid, err := peerUID(uc)
		if errors.Is(err, errPeerUnsupported) || (err == nil && uid == l.uid) {
			return c, nil
		}
		_ = c.Close()
		if l.refused != nil {
			l.refused(uid)
		}
	}
}
