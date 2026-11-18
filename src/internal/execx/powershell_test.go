package execx

import (
	"encoding/base64"
	"errors"
	"slices"
	"testing"
	"unicode/utf16"
)

// decodeCommand reads a PowerShell -EncodedCommand (base64 of UTF-16LE).
func decodeCommand(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw)%2 != 0 {
		t.Fatalf("not an encoded command: %v", err)
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i]) | uint16(raw[2*i+1])<<8
	}
	return string(utf16.Decode(u))
}

// Old security finding 16: impr runs exactly one PowerShell form, its own
// Test-AppLockerPolicy script passed inline (-EncodedCommand), which
// execution policy does not govern, so there is no -ExecutionPolicy Bypass
// and no script file to swap between a check and the run. Values reach the
// script only through the environment, never as code.
func TestOnlyImprsPowerShellScriptRuns(t *testing.T) {
	args := PowerShellArgs()
	if slices.Contains(args, "-ExecutionPolicy") || slices.Contains(args, "Bypass") || slices.Contains(args, "-File") {
		t.Fatalf("the form still bypasses execution policy or runs a file: %v", args)
	}
	if got := decodeCommand(t, args[len(args)-1]); got != TestAppLockerScript {
		t.Fatalf("the encoded command is not impr's script:\n%s", got)
	}
	if err := Check(Cmd{Tool: "powershell", Args: args}); err != nil {
		t.Fatalf("the one allowed form was refused: %v", err)
	}
	other := base64.StdEncoding.EncodeToString([]byte("R\x00e\x00m\x00o\x00v\x00e\x00"))
	for name, c := range map[string]Cmd{
		"another encoded command": {Tool: "powershell", Args: append(args[:len(args)-1:len(args)-1], other)},
		"-Command":                {Tool: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-Command", "Get-Process"}},
		"the old -File form":      {Tool: "powershell", Args: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", "x.ps1"}},
		"an extra argument":       {Tool: "powershell", Args: append(append([]string{}, args...), "-x")},
	} {
		if err := Check(c); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: want refused, got %v", name, err)
		}
	}
}
