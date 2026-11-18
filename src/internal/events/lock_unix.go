//go:build darwin || linux || freebsd || openbsd || netbsd || dragonfly

package events

import (
	"os"
	"syscall"
)

func lockFile(f *os.File) error   { return syscall.Flock(int(f.Fd()), syscall.LOCK_EX) } //nolint:gosec // G115: a file descriptor fits an int
func unlockFile(f *os.File) error { return syscall.Flock(int(f.Fd()), syscall.LOCK_UN) } //nolint:gosec // G115: a file descriptor fits an int
