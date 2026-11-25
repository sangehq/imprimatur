package web

import "net/http"

// routes registers every route, one line each. A test reads this file to
// visit every route, so register a route here and only here. Every GET is a
// read; every POST is a change, behind the same-origin and CSRF checks, that
// runs one impr command and redirects (303) to the page that shows it.
// /remove and /revoke ask first (confirm=yes). s.need names the scope a
// session signed in with an API token needs for the route (read, secrets,
// admin, or events as over the API); the one-time link's session reaches all.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /assets/{hash}/{path...}", s.serveAsset)
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /signin", s.signinPage)
	mux.HandleFunc("POST /signin", s.signinToken)
	mux.HandleFunc("POST /signout", s.signout)
	mux.HandleFunc("GET /{$}", s.need("read", s.overview))
	mux.HandleFunc("GET /doctor", s.need("read", s.doctor))
	mux.HandleFunc("GET /profiles", s.need("read", s.profiles))
	mux.HandleFunc("GET /profiles/{name}", s.need("read", s.profile))
	mux.HandleFunc("GET /profiles/{name}/validate", s.need("read", s.profileValidate))
	mux.HandleFunc("POST /profiles/{name}/default", s.need("admin", s.profileDefault))
	mux.HandleFunc("POST /profiles/{name}/remove", s.need("admin", s.profileRemove))
	mux.HandleFunc("GET /certs", s.need("read", s.certs))
	mux.HandleFunc("GET /certs/new", s.need("admin", s.certNew))
	mux.HandleFunc("POST /certs", s.need("admin", s.certCreate))
	mux.HandleFunc("GET /secrets", s.need("secrets", s.secrets))
	mux.HandleFunc("GET /secrets/new", s.need("secrets", s.secretNew))
	mux.HandleFunc("POST /secrets", s.need("secrets", s.secretStore))
	mux.HandleFunc("GET /tokens", s.need("admin", s.tokens))
	mux.HandleFunc("GET /tokens/new", s.need("admin", s.tokenNew))
	mux.HandleFunc("POST /tokens", s.need("admin", s.tokenAdd))
	mux.HandleFunc("GET /tokens/created", s.need("admin", s.tokenCreated))
	mux.HandleFunc("POST /tokens/{id}/revoke", s.need("admin", s.tokenRevoke))
	mux.HandleFunc("GET /webhooks", s.need("admin", s.webhooks))
	mux.HandleFunc("GET /webhooks/new", s.need("admin", s.webhookNew))
	mux.HandleFunc("POST /webhooks", s.need("admin", s.webhookAdd))
	mux.HandleFunc("POST /webhooks/{name}/remove", s.need("admin", s.webhookRemove))
	mux.HandleFunc("POST /webhooks/{name}/test", s.need("admin", s.webhookTest))
	mux.HandleFunc("POST /webhooks/retry", s.need("admin", s.webhookRetry))
	mux.HandleFunc("GET /events", s.need("events", s.eventsPage))
	mux.HandleFunc("GET /events/stream", s.need("events", s.eventsStream))
	mux.HandleFunc("GET /audit", s.need("read", s.audit))
	mux.HandleFunc("GET /about", s.need("read", s.about))
	mux.HandleFunc("/", s.notFound)
	return mux
}
