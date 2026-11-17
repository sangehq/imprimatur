package cli

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/execx"
)

var toolsFlags = flagSpec{"json": boolFlag, "strict": boolFlag}

// ToolRow is one tool in `impr tools list --json`.
type ToolRow struct {
	Name    string `json:"name"`
	Why     string `json:"why"`
	Path    string `json:"path,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Pinned  bool   `json:"pinned"`
	Problem string `json:"problem,omitempty"`
}

// toolRows is every allow-listed tool: where it is, its sha256, and whether
// it is pinned (impr tools list, impr doctor).
func (a *App) toolRows() []ToolRow {
	r := a.runner()
	pins := map[string]execx.Pin{}
	if o, ok := r.(execx.OS); ok && o.Pins != nil {
		pins = o.Pins
	}
	rows := []ToolRow{}
	for _, name := range execx.Names() {
		row := ToolRow{Name: name, Why: execx.Allowed[name]}
		if pin, ok := pins[name]; ok {
			row.Pinned, row.Path = true, pin.Path
			if sum, err := execx.CheckPinned(pin.Path, pin.SHA256); err != nil {
				row.Problem = err.Error()
			} else {
				row.SHA256 = sum
			}
		} else if path, err := r.LookPath(name); err == nil {
			row.Path = path
			row.SHA256, _ = execx.CheckPinned(path, "")
		}
		rows = append(rows, row)
	}
	return rows
}

func cmdTools(_ context.Context, a *App, args []string) (int, error) {
	p, err := parse(args, toolsFlags)
	if err != nil {
		return 0, err
	}
	sub := "list"
	if len(p.pos) > 0 {
		sub = p.pos[0]
	}
	switch sub {
	case "list":
		rows := a.toolRows()
		if p.on("json") {
			a.json(map[string]any{"contract": contract.Version, "tools": rows})
			return 0, nil
		}
		for _, t := range rows {
			state := "not found"
			switch {
			case t.Problem != "":
				state = "REFUSED: " + t.Problem
			case t.Pinned:
				state = "pinned " + t.SHA256[:12]
			case t.Path != "":
				state = "unpinned, from PATH"
			}
			a.say("%-13s %-40s %s", t.Name, t.Path, state)
		}
		return 0, nil
	case "pin":
		if len(p.pos) != 2 {
			return 0, contract.New(contract.Usage, "impr tools pin NAME prints the pin for the tool PATH finds")
		}
		name := p.pos[1]
		if _, ok := execx.Allowed[name]; !ok {
			return 0, contract.New(contract.Usage, "%s is not a tool impr runs", name)
		}
		path, err := execx.OS{}.LookPath(name) // PATH, not a pin: pin what is installed
		if err != nil {
			return 0, contract.Wrap(contract.Unavailable, err, "%s is not on PATH", name)
		}
		if real, err := filepath.EvalSymlinks(path); err == nil {
			path = real
		}
		sum, _ := execx.CheckPinned(path, "")
		if sum == "" {
			return 0, contract.New(contract.Usage, "%s cannot be pinned (not a regular file, or writable by others)", path)
		}
		value := fmt.Sprintf(`{"path":%q,"sha256":%q}`, path, sum)
		_, _ = fmt.Fprintln(a.Stdout, value)
		a.say("tools     to pin it: impr config set tools.%s '%s'", name, value)
		return 0, nil
	}
	return 0, contract.New(contract.Usage, "unknown tools subcommand %q", sub).WithFix("impr tools list", "impr tools pin NAME")
}
