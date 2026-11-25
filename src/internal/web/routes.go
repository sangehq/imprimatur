package web

import "net/http"

// routes registers every route, one line each. A test reads this file to
// visit every route, so register a route here and only here.
func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /assets/{hash}/{path...}", s.serveAsset)
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("/", s.notFound)
	return mux
}
