// Package project reads a repository's own .imprimatur/project.json. The
// repository is not trusted, so the file can only tighten what impr does
// (design §2.3): pin the signing profile, narrow the purposes and platforms,
// and require --strict and --repo. A field that would loosen anything, or add
// a program to run, does not exist here, and an unknown field is refused.
package project

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Path is the file's place under a signing root.
const Path = ".imprimatur/project.json"

// Schema identifies the file.
const Schema = "imprimatur.project/v1"

// Project is the tighten-only project file.
type Project struct {
	Schema      string   `json:"schema"`
	Profile     string   `json:"profile,omitempty"`   // the only signing profile allowed here
	Purposes    []string `json:"purposes,omitempty"`  // the only purposes allowed here
	Platforms   []string `json:"platforms,omitempty"` // the only platforms allowed here
	Strict      bool     `json:"strict,omitempty"`    // every sign and verify runs as --strict
	RequireRepo bool     `json:"requireRepo,omitempty"`
}

// Load reads root/.imprimatur/project.json. A missing file is an empty
// project (no restrictions). A symlink, anything over 64 KiB, an unknown
// field or a bad value is an error: a file meant to restrict must never be
// half-read.
func Load(root string) (Project, bool, error) {
	p := filepath.Join(root, filepath.FromSlash(Path))
	st, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		return Project{}, false, nil
	}
	if err != nil {
		return Project{}, false, err
	}
	if !st.Mode().IsRegular() || st.Size() > 64<<10 {
		return Project{}, false, fmt.Errorf("%s must be a regular file under 64 KiB", Path)
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: the signing root's own project file
	if err != nil {
		return Project{}, false, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var pr Project
	if err := dec.Decode(&pr); err != nil {
		return Project{}, false, fmt.Errorf("%s: %w (it can only set profile, purposes, platforms, strict and requireRepo)", Path, err)
	}
	if dec.More() {
		return Project{}, false, fmt.Errorf("%s holds more than one JSON object", Path)
	}
	if pr.Schema != Schema {
		return Project{}, false, fmt.Errorf("%s: schema must be %q", Path, Schema)
	}
	for _, pu := range pr.Purposes {
		if pu != "release" && pu != "test" && pu != "internal" {
			return Project{}, false, fmt.Errorf("%s: %q is not a purpose", Path, pu)
		}
	}
	return pr, true, nil
}

// CheckSign applies the project's restrictions to a signing run and returns
// the reasons it is refused, or none.
func (pr Project) CheckSign(profile, purpose, repo string, platforms []string, strict bool) []string {
	var out []string
	if pr.Profile != "" && profile != pr.Profile {
		out = append(out, fmt.Sprintf("this repository signs only with profile %s, not %s", pr.Profile, profile))
	}
	if len(pr.Purposes) > 0 && !slices.Contains(pr.Purposes, purpose) {
		out = append(out, fmt.Sprintf("this repository allows purposes %s, not %s", strings.Join(pr.Purposes, ", "), purpose))
	}
	if len(pr.Platforms) > 0 {
		for _, pl := range platforms {
			if !slices.Contains(pr.Platforms, pl) {
				out = append(out, fmt.Sprintf("this repository allows platforms %s, not %s", strings.Join(pr.Platforms, ", "), pl))
			}
		}
	}
	if pr.Strict && !strict {
		out = append(out, "this repository requires --strict")
	}
	if pr.RequireRepo && repo == "" {
		out = append(out, "this repository requires --repo")
	}
	return out
}

// CheckVerify applies the restrictions that matter to verification.
func (pr Project) CheckVerify(profile string, strict bool) []string {
	var out []string
	if pr.Profile != "" && profile != pr.Profile {
		out = append(out, fmt.Sprintf("this repository verifies only with profile %s, not %s", pr.Profile, profile))
	}
	if pr.Strict && !strict {
		out = append(out, "this repository requires --strict")
	}
	return out
}
