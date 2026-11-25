//go:build !windows

package cli

// osUserPath is nil off Windows: there impr only says what to add to PATH.
func osUserPath() userPathStore { return nil }
