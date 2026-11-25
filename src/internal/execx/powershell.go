package execx

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"unicode/utf16"
)

// TestAppLockerScript is the only PowerShell impr runs: Test-AppLockerPolicy
// over the files given, answered as one JSON array. Its inputs arrive only as
// environment variables (PowerShellEnv), read as strings and never as code.
const TestAppLockerScript = `$ErrorActionPreference = 'Stop'
[string[]]$paths = $env:IMPR_TAL_PATHS -split "` + "`" + `n"
$results = @(Test-AppLockerPolicy -XmlPolicy $env:IMPR_TAL_POLICY -Path $paths -User $env:IMPR_TAL_USER | ForEach-Object {
  [pscustomobject]@{ path = [string]$_.FilePath; decision = [string]$_.PolicyDecision; rule = [string]$_.MatchingRule }
})
ConvertTo-Json -InputObject $results -Compress -Depth 3
`

// PowerShellArgs is the one PowerShell command line (old security finding
// 16): no profile, no prompts, and impr's script inline as -EncodedCommand,
// which execution policy does not govern, so there is no -ExecutionPolicy
// Bypass and no script file that could be swapped after it was checked.
func PowerShellArgs() []string {
	return []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", encodeCommand(TestAppLockerScript)}
}

// PowerShellEnv carries the script's inputs: the policy file, the user and the
// files one per line (a Windows path holds no line break; one that does is
// refused), so no value is ever parsed as PowerShell.
func PowerShellEnv(policy, user string, files []string) ([]string, error) {
	for _, v := range append([]string{policy, user}, files...) {
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("%q holds a line break", v)
		}
	}
	return []string{"IMPR_TAL_POLICY=" + policy, "IMPR_TAL_USER=" + user, "IMPR_TAL_PATHS=" + strings.Join(files, "\n")}, nil
}

// encodeCommand is PowerShell's -EncodedCommand form: base64 of UTF-16LE.
func encodeCommand(script string) string {
	u := utf16.Encode([]rune(script))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// checkPowerShell allows exactly PowerShellArgs or CompileCIPolicyArgs.
func checkPowerShell(args []string) error {
	if !slices.Equal(args, PowerShellArgs()) && !slices.Equal(args, CompileCIPolicyArgs()) {
		return fmt.Errorf("powershell %s: %w (only impr's Test-AppLockerPolicy and ConvertFrom-CIPolicy scripts)", strings.Join(args, " "), ErrNotAllowed)
	}
	return nil
}

// CompileCIPolicyScript compiles the WDAC policy impr rules wrote into a .cip
// with ConvertFrom-CIPolicy, which proves Windows accepts it (O-183). Its
// inputs arrive as environment variables (CompileCIPolicyEnv), never as code.
// It prints "compiled", or "skipped" where this Windows has no ConfigCI
// module (Home editions); a policy that does not compile is an error.
const CompileCIPolicyScript = `$ErrorActionPreference = 'Stop'
if (-not (Get-Command ConvertFrom-CIPolicy -ErrorAction SilentlyContinue)) { 'skipped'; exit 0 }
ConvertFrom-CIPolicy -XmlFilePath $env:IMPR_CIP_XML -BinaryFilePath $env:IMPR_CIP_OUT | Out-Null
'compiled'
`

// CompileCIPolicyArgs is the PowerShell command line for CompileCIPolicyScript,
// in the same form as PowerShellArgs.
func CompileCIPolicyArgs() []string {
	return []string{"-NoProfile", "-NonInteractive", "-EncodedCommand", encodeCommand(CompileCIPolicyScript)}
}

// CompileCIPolicyEnv carries the policy and the .cip paths.
func CompileCIPolicyEnv(xmlPath, cipPath string) ([]string, error) {
	for _, v := range []string{xmlPath, cipPath} {
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("%q holds a line break", v)
		}
	}
	return []string{"IMPR_CIP_XML=" + xmlPath, "IMPR_CIP_OUT=" + cipPath}, nil
}
