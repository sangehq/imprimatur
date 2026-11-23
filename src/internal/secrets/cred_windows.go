//go:build windows

package secrets

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The Windows Credential Manager, through advapi32: a generic credential per
// secret, readable by this user only (ID-33).
var (
	advapi32   = windows.NewLazySystemDLL("advapi32.dll")
	credWriteW = advapi32.NewProc("CredWriteW")
	credReadW  = advapi32.NewProc("CredReadW")
	credFree   = advapi32.NewProc("CredFree")
)

const (
	credTypeGeneric         = 1
	credPersistLocalMachine = 2
)

type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        windows.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

func credWrite(target, value string) error {
	t, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	blob := []byte(value)
	c := credential{Type: credTypeGeneric, TargetName: t, CredentialBlobSize: uint32(len(blob)), Persist: credPersistLocalMachine} //nolint:gosec // G115: a value capped well below 4 GiB
	if len(blob) > 0 {
		c.CredentialBlob = &blob[0]
	}
	if r, _, e := credWriteW.Call(uintptr(unsafe.Pointer(&c)), 0); r == 0 { //nolint:gosec // G103: the documented Win32 call
		return e
	}
	return nil
}

func credRead(target string) (string, error) {
	t, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return "", err
	}
	var p *credential
	if r, _, e := credReadW.Call(uintptr(unsafe.Pointer(t)), credTypeGeneric, 0, uintptr(unsafe.Pointer(&p))); r == 0 { //nolint:gosec // G103: the documented Win32 call
		return "", e
	}
	defer credFree.Call(uintptr(unsafe.Pointer(p))) //nolint:errcheck,gosec // G103: frees what CredReadW allocated
	if p.CredentialBlobSize == 0 || p.CredentialBlob == nil {
		return "", errors.New("empty credential")
	}
	return string(unsafe.Slice(p.CredentialBlob, p.CredentialBlobSize)), nil //nolint:gosec // G103: the blob CredReadW returned
}
