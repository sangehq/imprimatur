package execx

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// Fake is a Runner for tests: it applies the same allow-list, records every
// call, and answers from handlers. It can do no more than the real runner: a
// tool that is not on the list is refused, and a tool not marked installed is
// not found.
type Fake struct {
	mu        sync.Mutex
	Installed map[string]bool
	// Handle answers a call; nil answers exit 0 with no output.
	Handle func(c Cmd) Result
	Calls  []Cmd
}

// NewFake returns a fake with the named tools installed.
func NewFake(tools ...string) *Fake {
	f := &Fake{Installed: map[string]bool{}}
	for _, t := range tools {
		f.Installed[t] = true
	}
	return f
}

// LookPath resolves an installed, allowed tool to a fake absolute path.
func (f *Fake) LookPath(tool string) (string, error) {
	if _, ok := Allowed[tool]; !ok {
		return "", fmt.Errorf("%q: %w", tool, ErrNotAllowed)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.Installed[tool] {
		return "", fmt.Errorf("%s: %w", tool, ErrNotFound)
	}
	return "/fake/bin/" + tool, nil
}

// Run records the call and answers it.
func (f *Fake) Run(_ context.Context, c Cmd) (Result, error) {
	if err := Check(c); err != nil {
		return Result{}, err
	}
	p, err := f.LookPath(c.Tool)
	if err != nil {
		return Result{}, err
	}
	f.mu.Lock()
	f.Calls = append(f.Calls, c)
	h := f.Handle
	f.mu.Unlock()
	r := Result{}
	if h != nil {
		r = h(c)
	}
	r.Path = p
	return r, nil
}

// Called reports whether a call to tool with an argument containing sub was made.
func (f *Fake) Called(tool, sub string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.Calls {
		if c.Tool == tool && strings.Contains(strings.Join(c.Args, " "), sub) {
			return true
		}
	}
	return false
}
