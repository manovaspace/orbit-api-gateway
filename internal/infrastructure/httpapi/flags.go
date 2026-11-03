package httpapi

import (
	"net/http"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

type featureFlagJSON struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

type flagSetJSON struct {
	Version string            `json:"version"`
	Flags   []featureFlagJSON `json:"flags"`
}

// flags serves the platform flag document. It is public: browsers read flags
// before sign-in, so the route never asks for a bearer token.
func (h *handlers) flags(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache")
	set, err := h.svc.ListFlags(r.Context())
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "flags unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, flagSetJSON{Version: set.Version, Flags: featureFlagsJSON(set.Flags)})
}

func featureFlagsJSON(flags []domain.FeatureFlag) []featureFlagJSON {
	out := make([]featureFlagJSON, 0, len(flags))
	for _, flag := range flags {
		out = append(out, featureFlagJSON{
			Name:        flag.Name,
			Enabled:     flag.Enabled,
			Description: flag.Description,
		})
	}
	return out
}
