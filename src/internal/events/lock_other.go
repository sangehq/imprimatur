//go:build !(darwin || linux || freebsd || openbsd || netbsd || dragonfly || windows)

package events

import "os"

// Elsewhere only writers in one process are serialised.
func lockFile(*os.File) error   { return nil }
func unlockFile(*os.File) error { return nil }
