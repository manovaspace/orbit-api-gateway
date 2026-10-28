package httpapi

import (
	"encoding/json"
	"net/http"

	orbittoken "github.com/manovaspace/orbit-auth/token"
)

// ServeJWKS publishes the public access-token verification keys at
// GET /.well-known/jwks.json so product APIs can verify Orbit Auth tokens.
func (s *Server) ServeJWKS(keys orbittoken.KeySet) {
	body, err := json.Marshal(keys.Document())
	if err != nil {
		// Document contains only strings; marshalling cannot fail.
		panic(err)
	}
	s.mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_, _ = w.Write(body)
	})
}
