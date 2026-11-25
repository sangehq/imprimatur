package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"path"
	"slices"
	"sort"
	"strings"
)

// assetSet is the embedded assets, each with a content hash for its
// fingerprinted, immutable URL.
type assetSet struct {
	files  map[string][]byte // path below assets/
	hashes map[string]string // the first 12 hex characters of a sha256
	sprite template.HTML
}

func loadAssets() (*assetSet, error) {
	a := &assetSet{files: map[string][]byte{}, hashes: map[string]string{}}
	err := fs.WalkDir(assetFS, "assets", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := assetFS.ReadFile(p)
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(p, "assets/")
		sum := sha256.Sum256(body)
		a.files[name] = body
		a.hashes[name] = hex.EncodeToString(sum[:])[:12]
		return nil
	})
	if err != nil {
		return nil, err
	}
	// The ES modules import each other by relative path, so app.js and
	// everything under js/ share one fingerprint taken over all of them; so do
	// app.css and the fonts its @font-face rules load.
	a.shareHash(func(n string) bool { return n == "app.js" || strings.HasPrefix(n, "js/") })
	a.shareHash(func(n string) bool { return n == "app.css" || strings.HasPrefix(n, "vendor/fonts/") })
	sprite, ok := a.files["vendor/tabler-icons.svg"]
	if !ok {
		return nil, fmt.Errorf("web: the icon sprite is not embedded")
	}
	// The sprite is vendored, checked against MANIFEST.sha256 by a test, and
	// holds no script: it is inlined so <use href="#..."> stays in the page.
	a.sprite = template.HTML(sprite) //nolint:gosec // G203: a vendored, hash-checked file, see above
	return a, nil
}

// shareHash gives every asset in a group one fingerprint, over all of their
// names and bytes.
func (a *assetSet) shareHash(in func(string) bool) {
	var names []string
	for name := range a.files {
		if in(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	group := sha256.New()
	for _, name := range names {
		group.Write([]byte(name))
		group.Write(a.files[name])
	}
	h := hex.EncodeToString(group.Sum(nil))[:12]
	for _, name := range names {
		a.hashes[name] = h
	}
}

// url is an asset's fingerprinted URL. An asset that does not exist fails the
// template, which the page tests turn into a failure, not a broken page.
func (a *assetSet) url(name string) (string, error) {
	h, ok := a.hashes[name]
	if !ok {
		return "", fmt.Errorf("no embedded asset %q", name)
	}
	return "/assets/" + h + "/" + name, nil
}

// serveAsset answers /assets/{hash}/{path...}. A stale hash is a 404, never
// the current file: an immutable URL must not change content.
func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("path")
	body, ok := s.assets.files[name]
	if !ok || r.PathValue("hash") != s.assets.hashes[name] {
		s.renderError(w, r, http.StatusNotFound, "Not found", "There is no such file here.")
		return
	}
	switch path.Ext(name) {
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	case ".woff2":
		w.Header().Set("Content-Type", "font/woff2")
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(body)
}

// iconHTML is a Tabler icon from the inline sprite. Icons are decorative:
// each sits beside text, or in a control with an aria-label, that says the
// same thing.
func iconHTML(name string) template.HTML {
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return ""
		}
	}
	if name == "" {
		return ""
	}
	return template.HTML(`<svg class="icon" aria-hidden="true" focusable="false"><use href="#tabler-` + name + `"></use></svg>`) //nolint:gosec // G203: name is [a-z0-9-] only
}

// pageSet is every page template, each parsed once over the layout and the
// partials.
type pageSet map[string]*template.Template

func parsePages(a *assetSet) (pageSet, error) {
	funcs := template.FuncMap{
		"asset":  a.url,
		"sprite": func() template.HTML { return a.sprite },
		"icon":   iconHTML,
		"empty":  func(icon, title, text string) emptyState { return emptyState{icon, title, text} },
		"confirm": func(id, form, title, text, label string) confirmModal {
			return confirmModal{ID: id, Form: form, Title: title, Text: text, Label: label}
		},
		"join":      strings.Join,
		"platforms": platformNames,
	}
	base, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/partials/*.html")
	if err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(templateFS, "templates")
	if err != nil {
		return nil, err
	}
	ps := pageSet{}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "layout.html" || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		t, err := base.Clone()
		if err != nil {
			return nil, err
		}
		if _, err := t.ParseFS(templateFS, "templates/"+e.Name()); err != nil {
			return nil, err
		}
		ps[strings.TrimSuffix(e.Name(), ".html")] = t
	}
	return ps, nil
}

// emptyState is a list with nothing in it yet.
type emptyState struct{ Icon, Title, Text string }

// confirmModal asks before a destructive action: the form's own button opens
// it, and its danger button submits the form with confirm=yes.
type confirmModal struct{ ID, Form, Title, Text, Label string }

// view is what every page template receives.
type view struct {
	Title string
	// Nav names the page, for the menu's active entry.
	Nav string
	// Authed is a signed-in session; TokenOnly one that signed in with an
	// API token, which reaches the secrets page only.
	Authed, TokenOnly bool
	// Owner is the one-time link's session, which reaches everything; Reach
	// is what a token sign-in may use (see Can).
	Owner bool
	Reach []string
	// ConfigOff says why this session may not change configuration, with
	// the fix; "" when it may. Forms then show disabled.
	ConfigOff string
	CSRF      string
	Version   string
	// User and Host are who the server runs as and where; Year is the
	// footer's.
	User, Host string
	Year       int
	// Panel asks for the page's content alone, for the side panel.
	Panel bool
	// Flash is a message from the change before this page (PRG), shown as a
	// toast; FlashBad marks a failure.
	Flash    string
	FlashBad bool
	Data     any
}

// Can reports whether the page's session may use scope, so a page shows only
// the links and forms it can follow.
func (v view) Can(scope string) bool { return v.Owner || slices.Contains(v.Reach, scope) }

func (s *Server) newView(r *http.Request, nav, title string, data any) view {
	v := view{Title: title, Nav: nav, Version: s.opts.Version, User: s.opts.User, Host: s.opts.Host,
		Year: s.opts.Now().Year(), Panel: r.Header.Get(panelHeader) == "1", Data: data}
	s.fillSession(r, &v)
	return v
}

// panelHeader marks a request from the side panel: the page's content is
// rendered alone.
const panelHeader = "X-Impr-Panel"

// render executes a page into a buffer first, so a template error is a clean
// 500 instead of half a page.
func (s *Server) render(w http.ResponseWriter, status int, page string, v view) {
	t, ok := s.pages[page]
	if !ok {
		http.Error(w, "no such page template: "+page, http.StatusInternalServerError)
		return
	}
	frame := "layout"
	if v.Panel {
		frame = "panel"
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, frame, v); err != nil {
		if s.opts.Log != nil {
			s.opts.Log("web       template %s: %v", page, err)
		}
		http.Error(w, "the page could not be drawn", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Add("Vary", panelHeader)
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

type errorData struct {
	Status           int
	Heading, Message string
}

// renderError answers with a styled error page in the layout.
func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, heading, message string) {
	s.render(w, status, "error", s.newView(r, "", heading, errorData{status, heading, message}))
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, http.StatusNotFound, "Not found", "There is no page at this address.")
}
