package httpapi

import (
	"net/http"

	"github.com/manovaspace/orbit-api-gateway/internal/application"
)

func registerOpenAPIRoutes(mux *http.ServeMux, svc *application.Service) {
	mux.HandleFunc("GET /api/v1/openapi/gateway.yaml", serveAsset(svc.OpenAPISpec, "application/yaml"))
	mux.HandleFunc("GET /api/v1/openapi/manifest.json", serveAsset(svc.Manifest, "application/json"))
}

// serveAsset serves a committed artifact. A missing file is a 404 with the
// historical "spec not found" body, not a startup failure.
func serveAsset(load func() ([]byte, error), contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		body, err := load()
		if err != nil {
			http.Error(w, "spec not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	}
}
