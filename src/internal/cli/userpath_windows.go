//go:build windows

package cli

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// regUserPath is the user's PATH in HKCU\Environment, as the PowerShell
// line's [Environment]::SetEnvironmentVariable('Path', …, 'User') edited it.
type regUserPath struct{}

func osUserPath() userPathStore { return regUserPath{} }

// Get reads the value unexpanded, so %USERPROFILE%-style entries stay so.
func (regUserPath) Get() (string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer func() { _ = k.Close() }()
	v, _, err := k.GetStringValue("Path")
	if errors.Is(err, registry.ErrNotExist) {
		return "", nil
	}
	return v, err
}

// Set writes the value as REG_EXPAND_SZ and tells running programs the
// environment changed (WM_SETTINGCHANGE), so new terminals see it.
func (regUserPath) Set(v string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer func() { _ = k.Close() }()
	if err := k.SetExpandStringValue("Path", v); err != nil {
		return err
	}
	env, err := windows.UTF16PtrFromString("Environment")
	if err != nil {
		return nil
	}
	const hwndBroadcast, wmSettingChange, smtoAbortIfHung = 0xffff, 0x001A, 0x0002
	proc := windows.NewLazySystemDLL("user32.dll").NewProc("SendMessageTimeoutW")
	_, _, _ = proc.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)), smtoAbortIfHung, 5000, 0) //nolint:gosec // G103: the documented way to pass a string to SendMessageTimeoutW
	return nil
}
