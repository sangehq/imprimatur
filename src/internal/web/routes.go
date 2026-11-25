package web

import "net/http"

// routes registers every route, one line each. A test reads this file to
// visit every route, so register a route here and only here. Every GET is a
// read; every POST is a change, behind the same-origin and CSRF checks, that
// runs one impr command and redirects (303) to the page that shows it.
// /remove and /revoke ask first (confirm=yes).
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /assets/{hash}/{path...}", s.serveAsset)
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /signin", s.signinPage)
	mux.HandleFunc("POST /signin", s.signinToken)
	mux.HandleFunc("POST /signout", s.signout)
	mux.HandleFunc("GET /{$}", s.overview)
	mux.HandleFunc("GET /doctor", s.doctor)
	mux.HandleFunc("GET /profiles", s.profiles)
	mux.HandleFunc("GET /profiles/{name}", s.profile)
	mux.HandleFunc("GET /profiles/{name}/validate", s.profileValidate)
	mux.HandleFunc("POST /profiles/{name}/default", s.profileDefault)
	mux.HandleFunc("POST /profiles/{name}/remove", s.profileRemove)
	mux.HandleFunc("GET /certs", s.certs)
	mux.HandleFunc("GET /certs/new", s.certNew)
	mux.HandleFunc("POST /certs", s.certCreate)
	mux.HandleFunc("GET /secrets", s.secrets)
	mux.HandleFunc("GET /secrets/new", s.secretNew)
	mux.HandleFunc("POST /secrets", s.secretStore)
	mux.HandleFunc("GET /tokens", s.tokens)
	mux.HandleFunc("GET /tokens/new", s.tokenNew)
	mux.HandleFunc("POST /tokens", s.tokenAdd)
	mux.HandleFunc("GET /tokens/created", s.tokenCreated)
	mux.HandleFunc("POST /tokens/{id}/revoke", s.tokenRevoke)
	mux.HandleFunc("GET /webhooks", s.webhooks)
	mux.HandleFunc("GET /webhooks/new", s.webhookNew)
	mux.HandleFunc("POST /webhooks", s.webhookAdd)
	mux.HandleFunc("POST /webhooks/{name}/remove", s.webhookRemove)
	mux.HandleFunc("POST /webhooks/{name}/test", s.webhookTest)
	mux.HandleFunc("POST /webhooks/retry", s.webhookRetry)
	mux.HandleFunc("GET /events", s.eventsPage)
	mux.HandleFunc("GET /events/stream", s.eventsStream)
	mux.HandleFunc("GET /audit", s.audit)
	mux.HandleFunc("GET /about", s.about)
	mux.HandleFunc("/", s.notFound)
	return mux
}
