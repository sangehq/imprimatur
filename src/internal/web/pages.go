package web

import "net/http"

// overview is GET /: the state of this machine's signing at a glance.
func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "overview", s.newView(r, "overview", "Overview", nil))
}
