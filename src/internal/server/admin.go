package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/sangehq/imprimatur/src/internal/contract"
	"github.com/sangehq/imprimatur/src/internal/events"
)

var refRe = regexp.MustCompile(`^(secret|env)://[^\s]+$`)

// WebhookRequest is POST /v1/webhooks: impr webhooks add.
type WebhookRequest struct {
	Name         string   `json:"name"`
	URL          string   `json:"url"`
	Types        []string `json:"types,omitempty"`
	SecretRef    string   `json:"secretRef"`
	AllowPrivate bool     `json:"allowPrivate,omitempty"`
}

func (s *server) profileCapabilities(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.nameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, contract.Usage, "%q is not a profile name", name)
		return
	}
	s.run(w, r, "profile", "capabilities", name)
}

// rules renders allow rules for a request carried in the body: impr rules
// --request, from a private temporary file removed afterwards. The request
// names files by digest; nothing is read from the server's disk.
func (s *server) rules(w http.ResponseWriter, r *http.Request) {
	b, err := readAll(r)
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, contract.Usage, "the body is too large or unreadable")
		return
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err != nil {
		writeErr(w, http.StatusBadRequest, contract.Usage, "the body is not an allow-rules request")
		return
	}
	dir, err := os.MkdirTemp(filepath.Join(s.o.StateDir, "server"), "rules-")
	if err != nil {
		if err = os.MkdirAll(filepath.Join(s.o.StateDir, "server"), 0o700); err == nil {
			dir, err = os.MkdirTemp(filepath.Join(s.o.StateDir, "server"), "rules-")
		}
	}
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, contract.Unavailable, "no private place for the request")
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()
	req := filepath.Join(dir, "request.json")
	if err := os.WriteFile(req, b, 0o600); err != nil {
		writeErr(w, http.StatusServiceUnavailable, contract.Unavailable, "no private place for the request")
		return
	}
	s.run(w, r, "rules", "--strict", "--request="+req)
}

func (s *server) adminAllowed(w http.ResponseWriter) bool {
	if !s.o.Config.Server.AllowAdmin {
		writeErr(w, http.StatusForbidden, contract.Usage, "changing configuration over the API is off (server.allowAdmin)")
		return false
	}
	return true
}

func (s *server) webhookAdd(w http.ResponseWriter, r *http.Request) {
	if !s.adminAllowed(w) {
		return
	}
	var q WebhookRequest
	if err := decode(r, &q); err != nil {
		writeErr(w, http.StatusBadRequest, contract.Usage, "the request is not a webhook: %v", err)
		return
	}
	args, err := WebhookArgs(q)
	if err != nil {
		writeErr(w, http.StatusBadRequest, contract.Usage, "%v", err)
		return
	}
	s.run(w, r, args...)
}

// WebhookArgs checks a webhook and returns its impr webhooks add command line
// (without --json). The API and the web UI both add webhooks through it, so
// both refuse the same requests.
func WebhookArgs(q WebhookRequest) ([]string, error) {
	switch {
	case !ValidName(q.Name):
		return nil, errors.New("name is lower-case letters, digits, . _ -")
	case !strings.HasPrefix(q.URL, "https://") && !strings.HasPrefix(q.URL, "http://"):
		return nil, errors.New("url is an https URL")
	case !refRe.MatchString(q.SecretRef):
		return nil, errors.New("secretRef is a secret:// or env:// reference, never the secret")
	}
	args := []string{"webhooks", "add", q.Name, "--url=" + q.URL, "--secret-ref=" + q.SecretRef}
	for _, t := range q.Types {
		if !ValidTypeGlob(t) {
			return nil, fmt.Errorf("%q is not an event type glob", t)
		}
		args = append(args, "--types="+t)
	}
	if q.AllowPrivate {
		args = append(args, "--allow-private")
	}
	return args, nil
}

// nameRe is a profile or webhook name, as every handler checks one.
var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// ValidName reports whether name is a profile or webhook name the API
// accepts.
func ValidName(name string) bool { return nameRe.MatchString(name) }

// ValidTypeGlob reports whether g is an event type glob that matches a known
// event type, and cannot be read as an option.
func ValidTypeGlob(g string) bool {
	return typeGlobRe.MatchString(g) && !strings.HasPrefix(g, "-") && events.KnownGlob(g)
}

func (s *server) webhookRemove(w http.ResponseWriter, r *http.Request) {
	if !s.adminAllowed(w) {
		return
	}
	name := r.PathValue("name")
	if !s.nameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, contract.Usage, "%q is not a webhook name", name)
		return
	}
	s.run(w, r, "webhooks", "rm", name)
}

func (s *server) webhookTest(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !s.nameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, contract.Usage, "%q is not a webhook name", name)
		return
	}
	s.run(w, r, "webhooks", "test", name)
}
