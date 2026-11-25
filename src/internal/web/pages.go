package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/secrets"
	"github.com/sangehq/imprimatur/src/internal/server"
	"github.com/sangehq/imprimatur/src/internal/tabler"
)

// Every page reads through Options.Run with --json, the bridge the API uses,
// and every write is one impr command line built from checked fields. No page
// has an implementation of its own.

// cmdError is a command's own error document: {"error":{"message":...}}.
type cmdError struct {
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// runJSON runs an impr command with --json and decodes its document into v
// (nil to ignore it). A command's error document becomes the error, with its
// message; a run that printed no document is an error unless it succeeded.
func (s *Server) runJSON(r *http.Request, v any, args ...string) error {
	if s.opts.Run == nil {
		return errors.New("this server runs no commands")
	}
	code, out := s.opts.Run(r.Context(), append(slices.Clone(args), "--json"))
	out = bytes.TrimSpace(out)
	if json.Valid(out) {
		var e cmdError
		if json.Unmarshal(out, &e) == nil && e.Error != nil {
			return errors.New(e.Error.Message)
		}
		if v != nil {
			return json.Unmarshal(out, v)
		}
		return nil
	}
	if code != 0 {
		return fmt.Errorf("impr %s ended with exit code %d", args[0], code)
	}
	return nil
}

// page renders a page; a read that failed shows its message on the page.
func (s *Server) page(w http.ResponseWriter, r *http.Request, tmpl, nav, title string, data any) {
	s.render(w, http.StatusOK, tmpl, s.newView(r, nav, title, data))
}

// done ends a change: the message is left for the page it goes to, which is
// then fetched (POST, redirect, GET). From the side panel the answer names
// the page instead, and the whole window goes there.
func (s *Server) done(w http.ResponseWriter, r *http.Request, to, msg string, bad bool) {
	if sess := sessionFrom(r.Context()); sess != nil {
		sess.setFlash(msg, bad)
	}
	if r.Header.Get(panelHeader) == "1" {
		w.Header().Set("X-Impr-Location", to)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

// refuse answers a form whose fields did not pass the checks, without
// running anything.
func (s *Server) refuse(w http.ResponseWriter, r *http.Request, msg string) {
	s.renderError(w, r, http.StatusBadRequest, "Not done", msg)
}

// confirmed reports whether a destructive form says confirm=yes. Without it
// the server asks on a page of its own (the modal asks first when the script
// runs), so nothing is destroyed unasked.
func (s *Server) confirmed(w http.ResponseWriter, r *http.Request, title, text, label string) bool {
	if r.PostFormValue("confirm") == "yes" {
		return true
	}
	s.render(w, http.StatusOK, "confirm_page", s.newView(r, "", title, confirmPage{Title: title, Text: text, Label: label, Action: r.URL.Path}))
	return false
}

type confirmPage struct{ Title, Text, Label, Action string }

// ---- checks -------------------------------------------------------------------

var (
	tokenIDRe = regexp.MustCompile(`^tok_[0-9a-f]{12}$`)
	daysRe    = regexp.MustCompile(`^[0-9]{1,4}$`)
)

// plainText is a short value with no control characters that cannot be read
// as an option.
func plainText(v string, maxLen int) bool {
	if v == "" || len(v) > maxLen || strings.HasPrefix(v, "-") {
		return false
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// ---- overview, doctor -----------------------------------------------------------

type doctorDoc struct {
	OK             bool     `json:"ok"`
	Version        string   `json:"version"`
	DefaultProfile string   `json:"defaultProfile"`
	Problems       []string `json:"problems"`
	Notes          []string `json:"notes"`
	Profiles       []struct {
		Name  string   `json:"name"`
		Valid bool     `json:"valid"`
		Ready []string `json:"ready"`
	} `json:"profiles"`
	Tools []struct {
		Name   string `json:"name"`
		Why    string `json:"why"`
		Path   string `json:"path"`
		Pinned bool   `json:"pinned"`
	} `json:"tools"`
	Capabilities map[string]bool `json:"capabilities"`
}

type eventRow struct {
	ID      string    `json:"id"`
	Type    string    `json:"type"`
	Subject string    `json:"subject"`
	Time    time.Time `json:"time"`
	Data    struct {
		Command  string `json:"command"`
		ExitCode *int   `json:"exitCode"`
		User     string `json:"user"`
	} `json:"data"`
}

// Short is the type without imprimatur's prefix.
func (e eventRow) Short() string {
	return strings.TrimPrefix(e.Type, "com.simtabi.sange.imprimatur.")
}

// When is the time as the pages show it.
func (e eventRow) When() string { return e.Time.UTC().Format("2006-01-02 15:04:05 UTC") }

type overviewData struct {
	Doctor                                    doctorDoc
	Profiles, Certs, Tokens, Webhooks, Secret int
	Events                                    []eventRow
	Err                                       string
}

// overview is GET /: the doctor's verdict, counts, and the newest events.
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	var d overviewData
	var errs []string
	note := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	note(s.runJSON(r, &d.Doctor, "doctor"))
	var pl profileList
	note(s.runJSON(r, &pl, "profile", "list"))
	d.Profiles = len(pl.Profiles)
	var cl certList
	note(s.runJSON(r, &cl, "cert", "list"))
	d.Certs = len(cl.Certificates)
	// What this session cannot open, the overview does not count: a token
	// sign-in under server.web.tokenAccess scopes sees its own reach.
	sess := sessionFrom(r.Context())
	if s.can(sess, "admin") {
		var tl tokenList
		note(s.runJSON(r, &tl, "server", "token", "list"))
		d.Tokens = len(tl.Tokens)
		var wl webhookList
		note(s.runJSON(r, &wl, "webhooks", "list"))
		d.Webhooks = len(wl.Subscriptions)
	}
	if s.opts.ListSecrets != nil && s.can(sess, "secrets") {
		list, err := s.opts.ListSecrets()
		note(err)
		d.Secret = len(list)
	}
	if s.can(sess, "events") {
		var el struct {
			Events []eventRow `json:"events"`
		}
		note(s.runJSON(r, &el, "events", "tail", "--limit=8"))
		d.Events = el.Events
	}
	d.Err = strings.Join(errs, "; ")
	s.page(w, r, "overview", "overview", "Overview", d)
}

type doctorData struct {
	Doctor doctorDoc
	Err    string
}

// doctor is GET /doctor: impr doctor --json.
func (s *Server) doctor(w http.ResponseWriter, r *http.Request) {
	var d doctorData
	if err := s.runJSON(r, &d.Doctor, "doctor"); err != nil {
		d.Err = err.Error()
	}
	s.page(w, r, "doctor", "doctor", "Doctor", d)
}

// ---- profiles -------------------------------------------------------------------

type profileList struct {
	Profiles []struct {
		Name      string                     `json:"name"`
		Scope     string                     `json:"scope"`
		Owner     string                     `json:"owner"`
		Purpose   []string                   `json:"purpose"`
		Platforms map[string]json.RawMessage `json:"platforms"`
	} `json:"profiles"`
}

type profilesData struct {
	List    profileList
	Default string
	Err     string
}

// PlatformNames is a profile's platforms, sorted.
func platformNames(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// profiles is GET /profiles: impr profile list --json, with the default.
func (s *Server) profiles(w http.ResponseWriter, r *http.Request) {
	var d profilesData
	if err := s.runJSON(r, &d.List, "profile", "list"); err != nil {
		d.Err = err.Error()
	}
	var def struct {
		Default string `json:"default"`
	}
	if err := s.runJSON(r, &def, "profile", "default"); err == nil {
		d.Default = def.Default
	}
	s.page(w, r, "profiles", "profiles", "Profiles", d)
}

type capability struct {
	Platform string   `json:"platform"`
	Kind     string   `json:"kind"`
	Backend  string   `json:"backend"`
	Sign     bool     `json:"sign"`
	Verify   bool     `json:"verify"`
	Reason   string   `json:"reason"`
	Tools    []string `json:"tools"`
}

type profileData struct {
	Name         string
	Show         json.RawMessage
	Pretty       string
	Capabilities []capability
	Err          string
}

// profile is GET /profiles/{name}: impr profile show and capabilities.
func (s *Server) profile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !server.ValidName(name) {
		s.renderError(w, r, http.StatusNotFound, "No such profile", "That is not a profile name.")
		return
	}
	d := profileData{Name: name}
	var show map[string]any
	if err := s.runJSON(r, &show, "profile", "show", name); err != nil {
		d.Err = err.Error()
	} else {
		delete(show, "contract")
		b, _ := json.MarshalIndent(show, "", "  ")
		d.Pretty = string(b)
	}
	var caps struct {
		Profiles []struct {
			Platforms map[string]capability `json:"platforms"`
		} `json:"profiles"`
	}
	if err := s.runJSON(r, &caps, "profile", "capabilities", name); err == nil && len(caps.Profiles) > 0 {
		for _, k := range sortedKeys(caps.Profiles[0].Platforms) {
			c := caps.Profiles[0].Platforms[k]
			if c.Platform == "" {
				c.Platform = k
			}
			d.Capabilities = append(d.Capabilities, c)
		}
	}
	s.page(w, r, "profile", "profiles", "Profile "+name, d)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type validateData struct {
	Name string
	OK   bool
	Doc  struct {
		OK       bool `json:"ok"`
		Profiles []struct {
			Name           string   `json:"name"`
			IdentityDigest string   `json:"identityDigest"`
			Problems       []string `json:"problems"`
		} `json:"profiles"`
	}
	Err string
}

// profileValidate is GET /profiles/{name}/validate: impr profile validate. It
// changes nothing, so it is a read, and opens in the side panel.
func (s *Server) profileValidate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !server.ValidName(name) {
		s.renderError(w, r, http.StatusNotFound, "No such profile", "That is not a profile name.")
		return
	}
	d := validateData{Name: name}
	if err := s.runJSON(r, &d.Doc, "profile", "validate", name); err != nil {
		d.Err = err.Error()
	}
	s.page(w, r, "profile_validate", "profiles", "Validate "+name, d)
}

// profileDefault is POST /profiles/{name}/default: impr profile default NAME.
func (s *Server) profileDefault(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !server.ValidName(name) {
		s.refuse(w, r, "That is not a profile name.")
		return
	}
	if err := s.runJSON(r, nil, "profile", "default", name); err != nil {
		s.done(w, r, "/profiles", "The default profile was not changed: "+err.Error(), true)
		return
	}
	s.done(w, r, "/profiles", name+" is now the default signing profile.", false)
}

// profileRemove is POST /profiles/{name}/remove: impr profile rm NAME, after
// a confirmation.
func (s *Server) profileRemove(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !server.ValidName(name) {
		s.refuse(w, r, "That is not a profile name.")
		return
	}
	if !s.confirmed(w, r, "Remove "+name+"?", "The signing profile "+name+" is deleted. Its keys and certificates stay where they are.", "Remove") {
		return
	}
	if err := s.runJSON(r, nil, "profile", "rm", name); err != nil {
		s.done(w, r, "/profiles", name+" was not removed: "+err.Error(), true)
		return
	}
	s.done(w, r, "/profiles", "Removed the profile "+name+".", false)
}

// ---- certificates ---------------------------------------------------------------

type certList struct {
	Certificates []struct {
		Profile    string    `json:"profile"`
		Platform   string    `json:"platform"`
		Subject    string    `json:"subject"`
		Thumbprint string    `json:"thumbprint"`
		NotAfter   time.Time `json:"notAfter"`
		Present    bool      `json:"present"`
		Source     string    `json:"source"`
	} `json:"certificates"`
}

type certsData struct {
	List certList
	Now  time.Time
	Err  string
}

// certs is GET /certs: impr cert list --json.
func (s *Server) certs(w http.ResponseWriter, r *http.Request) {
	d := certsData{Now: s.now()}
	if err := s.runJSON(r, &d.List, "cert", "list"); err != nil {
		d.Err = err.Error()
	}
	s.page(w, r, "certs", "certs", "Certificates", d)
}

type certForm struct {
	Name, Subject, Days, Err string
}

// certNew is GET /certs/new: the test certificate form (a side panel).
func (s *Server) certNew(w http.ResponseWriter, r *http.Request) {
	s.page(w, r, "cert_new", "certs", "Create a test certificate", certForm{Days: "30"})
}

// certCreate is POST /certs: impr cert create --name --subject --days.
func (s *Server) certCreate(w http.ResponseWriter, r *http.Request) {
	f := certForm{Name: strings.TrimSpace(r.PostFormValue("name")), Subject: strings.TrimSpace(r.PostFormValue("subject")), Days: strings.TrimSpace(r.PostFormValue("days"))}
	n, _ := strconv.Atoi(f.Days)
	switch {
	case !server.ValidName(f.Name):
		f.Err = "A name is lower-case letters, digits, . _ and -, starting with a letter or digit."
	case f.Subject != "" && !plainText(f.Subject, 64):
		f.Err = "A subject is up to 64 characters of plain text, like Example Test, or empty for impr's default."
	case !daysRe.MatchString(f.Days) || n < 1 || n > 825:
		f.Err = "Days is a whole number from 1 to 825."
	}
	if f.Err != "" {
		s.render(w, http.StatusBadRequest, "cert_new", s.newView(r, "certs", "Create a test certificate", f))
		return
	}
	var out struct {
		Profile    string `json:"profile"`
		Thumbprint string `json:"thumbprint"`
	}
	args := []string{"cert", "create", "--name=" + f.Name}
	if f.Subject != "" { // empty: impr cert create's own default subject
		args = append(args, "--subject="+f.Subject)
	}
	if err := s.runJSON(r, &out, append(args, "--days="+f.Days)...); err != nil {
		f.Err = err.Error()
		s.render(w, http.StatusBadRequest, "cert_new", s.newView(r, "certs", "Create a test certificate", f))
		return
	}
	s.done(w, r, "/certs", "Created the test certificate "+out.Thumbprint+" and the profile "+out.Profile+". It can never sign a release.", false)
}

// ---- secrets --------------------------------------------------------------------

// maxSecret is the largest secret value or file, as the API's page allowed.
const maxSecret = 64 << 10

type secretsData struct {
	List []server.UISecret
	Err  string
}

// secrets is GET /secrets: the stored secrets, by name and reference.
func (s *Server) secrets(w http.ResponseWriter, r *http.Request) {
	var d secretsData
	if s.opts.ListSecrets != nil {
		list, err := s.opts.ListSecrets()
		if err != nil {
			d.Err = err.Error()
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		d.List = list
	}
	s.page(w, r, "secrets", "secrets", "Secrets", d)
}

type secretForm struct{ Name, Err string }

// secretNew is GET /secrets/new: the form that stores a secret.
func (s *Server) secretNew(w http.ResponseWriter, r *http.Request) {
	s.page(w, r, "secret_new", "secrets", "Store a secret", secretForm{})
}

// secretStore is POST /secrets: the value (or a file, such as an App Store
// Connect .p8 key) goes to PutSecret as data, never to a command line, and
// is never shown back.
func (s *Server) secretStore(w http.ResponseWriter, r *http.Request) {
	f := secretForm{Name: strings.TrimSpace(r.PostFormValue("name"))}
	value := r.PostFormValue("value")
	if file, _, err := r.FormFile("file"); err == nil {
		b, rerr := io.ReadAll(io.LimitReader(file, maxSecret+1))
		_ = file.Close()
		if rerr == nil && len(b) > 0 {
			value = string(b)
		}
	}
	switch {
	case !secrets.ValidName(f.Name):
		f.Err = "A name is A-Z, 0-9 and _, starting with a letter, like IMPR_NOTARY_KEY."
	case len(value) > maxSecret || strings.TrimSpace(value) == "":
		f.Err = "Give a value of at most 64 KiB, or a file."
	case s.opts.PutSecret == nil:
		f.Err = "This server cannot store secrets."
	}
	if f.Err != "" {
		s.render(w, http.StatusBadRequest, "secret_new", s.newView(r, "secrets", "Store a secret", f))
		return
	}
	ref, err := s.opts.PutSecret(r.Context(), f.Name, value)
	if err != nil {
		f.Err = "Not stored: " + err.Error()
		s.render(w, http.StatusBadRequest, "secret_new", s.newView(r, "secrets", "Store a secret", f))
		return
	}
	s.logf("web       stored the secret %s as %s", f.Name, ref)
	s.done(w, r, "/secrets", "Stored "+f.Name+" as "+ref+". A profile names it env://"+f.Name+".", false)
}

// ---- API tokens -----------------------------------------------------------------

type tokenList struct {
	Tokens []struct {
		ID     string   `json:"id"`
		Scopes []string `json:"scopes"`
	} `json:"tokens"`
}

type tokensData struct {
	List tokenList
	Err  string
}

// tokens is GET /tokens: impr server token list --json.
func (s *Server) tokens(w http.ResponseWriter, r *http.Request) {
	var d tokensData
	if err := s.runJSON(r, &d.List, "server", "token", "list"); err != nil {
		d.Err = err.Error()
	}
	s.page(w, r, "tokens", "tokens", "API tokens", d)
}

type tokenForm struct {
	Scopes []string
	Err    string
}

// tokenNew is GET /tokens/new: the scopes to give a new token.
func (s *Server) tokenNew(w http.ResponseWriter, r *http.Request) {
	s.page(w, r, "token_new", "tokens", "Add an API token", tokenForm{Scopes: config.Scopes})
}

// apiTokenRe is what impr server token add prints: impr_ and 32 random bytes.
var apiTokenRe = regexp.MustCompile(`^impr_[A-Za-z0-9_-]{43}$`)

// tokenAdd is POST /tokens: impr server token add --scopes. The token is kept
// in the session for one showing on /tokens/created, and is never logged.
func (s *Server) tokenAdd(w http.ResponseWriter, r *http.Request) {
	scopes := r.PostForm["scopes"]
	bad := len(scopes) == 0
	for _, sc := range scopes {
		if !slices.Contains(config.Scopes, sc) {
			bad = true
		}
	}
	if bad {
		s.render(w, http.StatusBadRequest, "token_new", s.newView(r, "tokens", "Add an API token",
			tokenForm{Scopes: config.Scopes, Err: "Choose at least one scope from the list."}))
		return
	}
	if s.opts.Run == nil {
		s.done(w, r, "/tokens", "Not added: this server runs no commands.", true)
		return
	}
	_, out := s.opts.Run(r.Context(), []string{"server", "token", "add", "--scopes=" + strings.Join(scopes, ","), "--json"})
	tok := strings.TrimSpace(string(out))
	if !apiTokenRe.MatchString(tok) {
		msg := "the token was not added"
		var e cmdError
		if json.Unmarshal(out, &e) == nil && e.Error != nil {
			msg = e.Error.Message
		}
		s.done(w, r, "/tokens", "Not added: "+msg, true)
		return
	}
	if sess := sessionFrom(r.Context()); sess != nil {
		sess.setOnce(tok)
	}
	s.done(w, r, "/tokens/created", "Added a token with the scopes "+strings.Join(scopes, ", ")+". A running API keeps its tokens until it restarts.", false)
}

type createdData struct{ Token string }

// tokenCreated is GET /tokens/created: the new token, shown once.
func (s *Server) tokenCreated(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	tok := ""
	if sess != nil {
		tok = sess.takeOnce()
	}
	if tok == "" {
		http.Redirect(w, r, "/tokens", http.StatusSeeOther)
		return
	}
	s.page(w, r, "token_created", "tokens", "Your new API token", createdData{Token: tok})
}

// tokenRevoke is POST /tokens/{id}/revoke: impr server token revoke ID, after
// a confirmation.
func (s *Server) tokenRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !tokenIDRe.MatchString(id) {
		s.refuse(w, r, "That is not a token id.")
		return
	}
	if !s.confirmed(w, r, "Revoke "+id+"?", "Programs using this token are refused once the API restarts.", "Revoke") {
		return
	}
	if err := s.runJSON(r, nil, "server", "token", "revoke", id); err != nil {
		s.done(w, r, "/tokens", id+" was not revoked: "+err.Error(), true)
		return
	}
	s.done(w, r, "/tokens", "Revoked "+id+". A running API keeps it until it restarts.", false)
}

// ---- webhooks -------------------------------------------------------------------

type webhookList struct {
	Subscriptions []config.Outbound `json:"subscriptions"`
	Pending       int               `json:"pending"`
	Dead          int               `json:"dead"`
}

type delivery struct {
	Subscription string `json:"subscription"`
	EventID      string `json:"eventId"`
	EventType    string `json:"eventType"`
	Attempts     int    `json:"attempts"`
	LastStatus   int    `json:"lastStatus"`
	LastError    string `json:"lastError"`
}

type webhooksData struct {
	// WritesOff says why adding and removing webhooks is off here, and how
	// to turn it on; "" when allowed.
	WritesOff  string
	List       webhookList
	Deliveries struct {
		Pending []delivery `json:"pending"`
		Dead    []delivery `json:"dead"`
	}
	Err string
}

// webhooks is GET /webhooks: impr webhooks list and deliveries --json.
func (s *Server) webhooks(w http.ResponseWriter, r *http.Request) {
	var d webhooksData
	d.WritesOff = s.webhookWritesOff(r)
	if err := s.runJSON(r, &d.List, "webhooks", "list"); err != nil {
		d.Err = err.Error()
	}
	if err := s.runJSON(r, &d.Deliveries, "webhooks", "deliveries"); err != nil && d.Err == "" {
		d.Err = err.Error()
	}
	s.page(w, r, "webhooks", "webhooks", "Webhooks", d)
}

type webhookForm struct {
	WritesOff                   string
	Name, URL, SecretRef, Types string
	AllowPrivate                bool
	Err                         string
}

// webhookNew is GET /webhooks/new.
func (s *Server) webhookNew(w http.ResponseWriter, r *http.Request) {
	s.page(w, r, "webhook_new", "webhooks", "Add a webhook", webhookForm{WritesOff: s.webhookWritesOff(r)})
}

// webhookWritesOff says why this session may not add or remove a webhook,
// with the fix, or "" when it may. A webhook can carry internal events off
// the machine, so by default the web UI needs server.allowAdmin as the API
// does; server.web.webhookAdmin owner lets the one-time link's session do it
// without (owner, 2026-11-25). Test and retry change no configuration and
// are not gated.
func (s *Server) webhookWritesOff(r *http.Request) string {
	sess := sessionFrom(r.Context())
	if s.opts.AllowAdmin || (!s.opts.Web.WebhooksNeedAllowAdmin() && sess != nil && sess.tokenID == "") {
		return ""
	}
	return "Adding and removing webhooks is off: server.allowAdmin is false, as for the API. " +
		"Turn it on with impr config set server.allowAdmin true (or, for this web UI's owner only, impr config set server.web.webhookAdmin owner), then restart impr serve."
}

// webhookAdd is POST /webhooks: the API's own checks (server.WebhookArgs),
// then impr webhooks add.
func (s *Server) webhookAdd(w http.ResponseWriter, r *http.Request) {
	if off := s.webhookWritesOff(r); off != "" {
		s.renderError(w, r, http.StatusForbidden, "Webhook changes are off", off)
		return
	}
	f := webhookForm{Name: strings.TrimSpace(r.PostFormValue("name")), URL: strings.TrimSpace(r.PostFormValue("url")),
		SecretRef: strings.TrimSpace(r.PostFormValue("secretRef")), Types: strings.TrimSpace(r.PostFormValue("types")),
		AllowPrivate: r.PostFormValue("allowPrivate") == "1"}
	q := server.WebhookRequest{Name: f.Name, URL: f.URL, SecretRef: f.SecretRef, AllowPrivate: f.AllowPrivate}
	for _, t := range strings.Split(f.Types, ",") {
		if t = strings.TrimSpace(t); t != "" {
			q.Types = append(q.Types, t)
		}
	}
	args, err := server.WebhookArgs(q)
	if err == nil && strings.ContainsAny(f.URL, " \t\r\n") {
		err = errors.New("url is an https URL")
	}
	if err != nil {
		f.Err = err.Error()
		s.render(w, http.StatusBadRequest, "webhook_new", s.newView(r, "webhooks", "Add a webhook", f))
		return
	}
	if err := s.runJSON(r, nil, args...); err != nil {
		f.Err = err.Error()
		s.render(w, http.StatusBadRequest, "webhook_new", s.newView(r, "webhooks", "Add a webhook", f))
		return
	}
	s.done(w, r, "/webhooks", "Added the webhook "+f.Name+".", false)
}

// webhookRemove is POST /webhooks/{name}/remove: impr webhooks rm, after a
// confirmation.
func (s *Server) webhookRemove(w http.ResponseWriter, r *http.Request) {
	if off := s.webhookWritesOff(r); off != "" {
		s.renderError(w, r, http.StatusForbidden, "Webhook changes are off", off)
		return
	}
	name := r.PathValue("name")
	if !server.ValidName(name) {
		s.refuse(w, r, "That is not a webhook name.")
		return
	}
	if !s.confirmed(w, r, "Remove "+name+"?", "impr stops delivering events to this webhook. Deliveries already queued stay until they expire.", "Remove") {
		return
	}
	if err := s.runJSON(r, nil, "webhooks", "rm", name); err != nil {
		s.done(w, r, "/webhooks", name+" was not removed: "+err.Error(), true)
		return
	}
	s.done(w, r, "/webhooks", "Removed the webhook "+name+".", false)
}

// webhookTest is POST /webhooks/{name}/test: impr webhooks test NAME.
func (s *Server) webhookTest(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !server.ValidName(name) {
		s.refuse(w, r, "That is not a webhook name.")
		return
	}
	if err := s.runJSON(r, nil, "webhooks", "test", name); err != nil {
		s.done(w, r, "/webhooks", "The test delivery to "+name+" was not queued: "+err.Error(), true)
		return
	}
	s.done(w, r, "/webhooks", "Queued a test delivery to "+name+"; it shows under the deliveries.", false)
}

// webhookRetry is POST /webhooks/retry: impr webhooks retry, or with all=1,
// retry --all (the dead letters too).
func (s *Server) webhookRetry(w http.ResponseWriter, r *http.Request) {
	args := []string{"webhooks", "retry"}
	if r.PostFormValue("all") == "1" {
		args = append(args, "--all")
	}
	var out struct {
		Tried     int `json:"tried"`
		Delivered int `json:"delivered"`
	}
	if err := s.runJSON(r, &out, args...); err != nil {
		s.done(w, r, "/webhooks", "Not retried: "+err.Error(), true)
		return
	}
	s.done(w, r, "/webhooks", fmt.Sprintf("Sent %d, delivered %d.", out.Tried, out.Delivered), false)
}

// ---- events, audit --------------------------------------------------------------

type eventsData struct {
	Events []eventRow
	Type   string
	Err    string
}

// eventsPage is GET /events: impr events tail --json, filtered by type, with
// the live stream underneath when the script runs.
func (s *Server) eventsPage(w http.ResponseWriter, r *http.Request) {
	d := eventsData{Type: strings.TrimSpace(r.URL.Query().Get("type"))}
	args := []string{"events", "tail", "--limit=100"}
	if d.Type != "" {
		if !server.ValidTypeGlob(d.Type) {
			s.renderError(w, r, http.StatusBadRequest, "Not an event type", "The filter is an event type or a glob such as profile.* (impr events types lists them).")
			return
		}
		args = append(args, "--type="+d.Type)
	}
	var el struct {
		Events []eventRow `json:"events"`
	}
	if err := s.runJSON(r, &el, args...); err != nil {
		d.Err = err.Error()
	}
	// Newest first, as the live rows are added.
	slices.Reverse(el.Events)
	d.Events = el.Events
	s.page(w, r, "events", "events", "Events", d)
}

type auditData struct {
	Records []eventRow
	Verify  struct {
		OK      bool `json:"ok"`
		Checked int  `json:"checked"`
	}
	VerifyErr, Err string
}

// audit is GET /audit: impr audit tail and audit verify --json.
func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	var d auditData
	var tail struct {
		Records []eventRow `json:"records"`
	}
	if err := s.runJSON(r, &tail, "audit", "tail", "--limit=50"); err != nil {
		d.Err = err.Error()
	}
	slices.Reverse(tail.Records)
	d.Records = tail.Records
	if err := s.runJSON(r, &d.Verify, "audit", "verify"); err != nil {
		d.VerifyErr = err.Error()
	}
	s.page(w, r, "audit", "audit", "Audit", d)
}

// ---- about ----------------------------------------------------------------------

type aboutData struct {
	Version string
	Path    struct {
		Config     string `json:"config"`
		State      string `json:"state"`
		InstallDir string `json:"installDir"`
		Installed  bool   `json:"installed"`
		OnPath     bool   `json:"onPath"`
	}
	Companion struct {
		Version        string   `json:"version"`
		Host           string   `json:"host"`
		CapabilityList []string `json:"capabilityList"`
		Commands       []string `json:"commands"`
	}
	Licences []tabler.Licence
	Err      string
}

// about is GET /about: the version, impr path and companion info, and the
// third-party licences the web UI embeds, read from the vendored files.
func (s *Server) about(w http.ResponseWriter, r *http.Request) {
	d := aboutData{Version: s.opts.Version}
	var errs []string
	if err := s.runJSON(r, &d.Path, "path"); err != nil {
		errs = append(errs, err.Error())
	}
	if err := s.runJSON(r, &d.Companion, "companion", "info"); err != nil {
		errs = append(errs, err.Error())
	}
	d.Licences = s.licences()
	d.Err = strings.Join(errs, "; ")
	s.page(w, r, "about", "about", "About", d)
}

// licences pairs each vendored package with its licence text.
func (s *Server) licences() []tabler.Licence {
	vers, err := tabler.ParseVersions(s.assets.files["vendor/TABLER_VERSION"])
	if err != nil {
		return nil
	}
	texts := map[string][]byte{}
	for name, b := range s.assets.files {
		if base, ok := strings.CutPrefix(name, "vendor/LICENSES/"); ok {
			texts[base] = b
		}
	}
	return tabler.Licences(vers, texts)
}
