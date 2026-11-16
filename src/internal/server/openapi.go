package server

import (
	_ "embed"
	"net/http"
)

// openapiDoc is the OpenAPI 3.1 description of this API. The tests check it
// against the routes Handler registers and the request structs' fields.
//
//go:embed openapi.json
var openapiDoc []byte

// openapi is GET /v1/openapi.json. It needs no token: it describes the API
// and holds nothing about this install.
func (s *server) openapi(w http.ResponseWriter, _ *http.Request) {
	writeDoc(w, http.StatusOK, openapiDoc)
}
