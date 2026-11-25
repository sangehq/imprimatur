package web

import "net/http"

// fillSession puts the signed-in session's state into a page's view.
func (s *Server) fillSession(_ *http.Request, _ *view) {}
