//go:build !windows

package secrets

import "errors"

var errNoCredManager = errors.New("the Windows Credential Manager exists only on Windows")

func credWrite(string, string) error  { return errNoCredManager }
func credRead(string) (string, error) { return "", errNoCredManager }
