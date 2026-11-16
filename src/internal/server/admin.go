package server

import (
	"encoding/json"
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
	switch {
	case !s.nameRe.MatchString(q.Name):
		writeErr(w, http.StatusBadRequest, contract.Usage, "name is lower-case letters, digits, . _ -")
		return
	case !strings.HasPrefix(q.URL, "https://") && !strings.HasPrefix(q.URL, "http://"):
		writeErr(w, http.StatusBadRequest, contract.Usage, "url is an https URL")
		return
	case !refRe.MatchString(q.SecretRef):
		writeErr(w, http.StatusBadRequest, contract.Usage, "secretRef is a secret:// or env:// reference, never the secret")
		return
	}
	args := []string{"webhooks", "add", q.Name, "--url=" + q.URL, "--secret-ref=" + q.SecretRef}
	for _, t := range q.Types {
		if !typeGlobRe.MatchString(t) || strings.HasPrefix(t, "-") || !events.KnownGlob(t) {
			writeErr(w, http.StatusBadRequest, contract.Usage, "%q is not an event type glob", t)
			return
		}
		args = append(args, "--types="+t)
	}
	if q.AllowPrivate {
		args = append(args, "--allow-private")
	}
	s.run(w, r, args...)
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
