package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/sangehq/imprimatur/src/internal/config"
	"github.com/sangehq/imprimatur/src/internal/contract"
)

// GitHub's webhook headers.
const (
	ghSignature = "X-Hub-Signature-256"
	ghDelivery  = "X-GitHub-Delivery"
	ghEvent     = "X-GitHub-Event"
)

// ghReplayWindow is how long a GitHub delivery id is remembered. GitHub
// signs no timestamp, so the ledger is the only replay defence, and a
// captured delivery replays once its id is forgotten: 400 days outlasts a
// yearly secret rotation (security review R8). An id is a few dozen bytes.
const ghReplayWindow = 400 * 24 * time.Hour

// minGitHubSecret is the shortest GitHub webhook secret impr accepts.
const minGitHubSecret = 16

// verifyGitHub checks X-Hub-Signature-256 ("sha256=" and the hex HMAC-SHA256
// of the body under the secret), in constant time.
func verifyGitHub(h http.Header, body []byte, secret string) bool {
	got, ok := strings.CutPrefix(h.Get(ghSignature), "sha256=")
	if !ok {
		return false
	}
	sig, err := hex.DecodeString(got)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, []byte(secret))
	_, _ = m.Write(body)
	return hmac.Equal(sig, m.Sum(nil))
}

// GitHubAnswer is what a github endpoint answers when it runs no action.
type GitHubAnswer struct {
	Contract int    `json:"contract"`
	Event    string `json:"event"`
	Delivery string `json:"delivery"`
	Result   string `json:"result"` // pong, recorded or ignored
}

// inboundGitHub serves a github-kind endpoint: verify, refuse replays,
// answer ping, record the delivery, then run the endpoint's action if it has
// one.
func (s *server) inboundGitHub(w http.ResponseWriter, r *http.Request, ep *config.Inbound, body []byte, unauthorized func(string)) {
	secret, err := s.o.Secret(r.Context(), ep.SecretRef)
	if err != nil || len(secret) < minGitHubSecret {
		writeErr(w, http.StatusServiceUnavailable, contract.Unavailable, "the endpoint's secret cannot be read")
		if err == nil {
			s.logf("server    inbound %s: the GitHub secret is shorter than %d characters", ep.Name, minGitHubSecret)
		} else {
			s.logf("server    inbound %s: %v", ep.Name, err)
		}
		return
	}
	if !verifyGitHub(r.Header, body, secret) {
		unauthorized("no valid " + ghSignature)
		return
	}
	delivery, event := r.Header.Get(ghDelivery), r.Header.Get(ghEvent)
	if delivery == "" || event == "" {
		unauthorized("missing " + ghDelivery + " or " + ghEvent)
		return
	}
	// Claimed only after verification, so a forger cannot burn ids.
	if fresh, err := s.replay.claim(ep.Name+"/gh/"+delivery, ghReplayWindow); err != nil {
		writeErr(w, http.StatusServiceUnavailable, contract.Unavailable, "the replay ledger is unavailable, so the delivery was refused")
		return
	} else if !fresh {
		writeErr(w, http.StatusConflict, contract.Usage, "delivery %s was already processed", delivery)
		return
	}
	answer := GitHubAnswer{Contract: contract.Version, Event: event, Delivery: delivery}
	if event == "ping" {
		answer.Result = "pong"
		writeAnswer(w, answer)
		return
	}
	if len(ep.GitHubEvents) > 0 && !slices.Contains(ep.GitHubEvents, event) {
		answer.Result = "ignored"
		writeAnswer(w, answer)
		return
	}
	var payload struct {
		Action     string `json:"action"`
		Repository struct {
			FullName string `json:"full_name"`
		} `json:"repository"`
		Ref string `json:"ref"`
	}
	_ = json.Unmarshal(body, &payload) // a payload impr cannot read is still recorded
	if s.o.Emit != nil {
		s.o.Emit("webhook.inbound.received", ep.Name, map[string]any{"endpoint": ep.Name, "kind": config.InboundGitHub,
			"event": event, "delivery": delivery, "action": payload.Action, "repository": payload.Repository.FullName,
			"ref": payload.Ref, "run": ep.Run})
	}
	switch ep.Run {
	case "":
		answer.Result = "recorded"
		writeAnswer(w, answer)
	case "doctor":
		s.run(w, r, "doctor")
	case "cert.list":
		s.run(w, r, "cert", "list")
	case "profile.list":
		s.run(w, r, "profile", "list")
	default: // config validation refuses anything else
		writeErr(w, http.StatusForbidden, contract.Usage, "action %q cannot run from a GitHub delivery", ep.Run)
	}
}

func writeAnswer(w http.ResponseWriter, a GitHubAnswer) {
	b, _ := json.Marshal(a)
	writeDoc(w, http.StatusOK, b)
}
