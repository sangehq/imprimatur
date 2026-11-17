package execx

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestOnlyImprsPowerShellScriptRuns(t *testing.T) {
	dir := t.TempDir()
	ours := filepath.Join(dir, "ours.ps1")
	other := filepath.Join(dir, "other.ps1")
	if err := os.WriteFile(ours, []byte(TestAppLockerScript), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("Remove-Item -Recurse C:\\"), 0o600); err != nil {
		t.Fatal(err)
	}
	form := func(script string, tail ...string) Cmd {
		return Cmd{Tool: "powershell", Args: append([]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", script}, tail...)}
	}
	ok := []string{"-PolicyPath", `C:\p.xml`, "-User", "Everyone", "-Path", `C:\a.exe`, `C:\b.dll`}
	if err := Check(form(ours, ok...)); err != nil {
		t.Fatalf("the one allowed form was refused: %v", err)
	}
	for name, c := range map[string]Cmd{
		"another script":          form(other, ok...),
		"a missing script":        form(filepath.Join(dir, "none.ps1"), ok...),
		"-Command":                {Tool: "powershell", Args: []string{"-Command", "Get-Process"}},
		"a value binding a param": form(ours, "-PolicyPath", `C:\p.xml`, "-User", "Everyone", "-Path", "-User"),
		"parameters reordered":    form(ours, "-User", "Everyone", "-PolicyPath", `C:\p.xml`, "-Path", `C:\a.exe`),
		"no files":                form(ours, "-PolicyPath", `C:\p.xml`, "-User", "Everyone", "-Path"),
	} {
		if err := Check(c); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("%s: want refused, got %v", name, err)
		}
	}
}
