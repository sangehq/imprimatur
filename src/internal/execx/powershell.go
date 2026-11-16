package execx

import (
	"bytes"
	"fmt"
	"os"
	"slices"
	"strings"
)

// TestAppLockerScript is the only PowerShell impr runs: Test-AppLockerPolicy
// over the files given, answered as one JSON array. Paths and the user reach
// it as -File parameters, never as code, so nothing a caller passes is
// evaluated.
const TestAppLockerScript = `param(
  [Parameter(Mandatory=$true)][string]$PolicyPath,
  [Parameter(Mandatory=$true)][string]$User,
  [Parameter(Mandatory=$true, ValueFromRemainingArguments=$true)][string[]]$Path
)
$ErrorActionPreference = 'Stop'
$results = @(Test-AppLockerPolicy -XmlPolicy $PolicyPath -Path $Path -User $User | ForEach-Object {
  [pscustomobject]@{ path = [string]$_.FilePath; decision = [string]$_.PolicyDecision; rule = [string]$_.MatchingRule }
})
ConvertTo-Json -InputObject $results -Compress -Depth 3
`

// powershellPrefix is the fixed start of the one PowerShell form: no profile,
// no prompts, impr's own script file.
var powershellPrefix = []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"}

// checkPowerShell allows exactly: the prefix, a script file whose bytes are
// TestAppLockerScript, -PolicyPath P, -User U, then one or more -Path values.
// No value may start with "-", so none can bind as another parameter.
func checkPowerShell(args []string) error {
	n := len(powershellPrefix)
	// prefix, script, -PolicyPath P -User U -Path, and at least one file
	if len(args) < n+1+5+1 || !slices.Equal(args[:n], powershellPrefix) {
		return fmt.Errorf("powershell %s: %w (only impr's Test-AppLockerPolicy script)", strings.Join(args, " "), ErrNotAllowed)
	}
	b, err := os.ReadFile(args[n]) //nolint:gosec // G304: the script impr wrote; its bytes are checked here
	if err != nil || !bytes.Equal(b, []byte(TestAppLockerScript)) {
		return fmt.Errorf("powershell: %w: the script is not impr's Test-AppLockerPolicy script", ErrNotAllowed)
	}
	rest := args[n+1:]
	if rest[0] != "-PolicyPath" || rest[2] != "-User" || rest[4] != "-Path" {
		return fmt.Errorf("powershell: %w: parameters must be -PolicyPath, -User, then -Path and the files", ErrNotAllowed)
	}
	for _, v := range append([]string{rest[1], rest[3]}, rest[5:]...) {
		if v == "" || strings.HasPrefix(v, "-") {
			return fmt.Errorf("powershell: %w: %q could bind as a parameter", ErrNotAllowed, v)
		}
	}
	return nil
}
