package httpapi

import (
	"net/http"
	"os"
)

func registerOpenAPIRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/openapi/gateway.yaml", serveRepoFile("openapi/openapi.yaml", "application/yaml"))
	mux.HandleFunc("GET /api/v1/openapi/manifest.json", serveRepoFile("openapi/manifest.json", "application/json"))
}

func serveRepoFile(path, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		b, err := os.ReadFile(path)
		if err != nil {
			http.Error(w, "spec not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
	}
}
