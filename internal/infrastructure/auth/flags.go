package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/manovaspace/orbit-api-gateway/internal/domain"
)

// flagsPath is the orbit-auth HTTP route that serves the platform flag
// document.
const flagsPath = "/v1/flags"

// defaultFlagsHTTPClient is the fallback for a Client assembled by hand. The
// constructor installs a per-client client; either way the timeout is shared
// and no request creates its own.
var defaultFlagsHTTPClient = &http.Client{Timeout: 5 * time.Second}

// flagDocument mirrors the JSON document orbit-auth returns. The domain type
// stays free of wire tags; the adapter owns the encoding.
type flagDocument struct {
	Version string            `json:"version"`
	Flags   []flagDescription `json:"flags"`
}

type flagDescription struct {
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

// ListFlags reads the platform flag document from orbit-auth over HTTP.
func (c *Client) ListFlags(ctx context.Context) (domain.FlagSet, error) {
	if strings.TrimSpace(c.AuthHTTPURL) == "" {
		return domain.FlagSet{}, domain.NewError(domain.KindBadGateway, "upstream error")
	}
	url := strings.TrimRight(c.AuthHTTPURL, "/") + flagsPath
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return domain.FlagSet{}, domain.NewError(domain.KindBadGateway, "upstream error")
	}

	client := c.httpClient
	if client == nil {
		client = defaultFlagsHTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return domain.FlagSet{}, domain.NewError(domain.KindBadGateway, "upstream error")
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return domain.FlagSet{}, domain.NewError(domain.KindBadGateway, "upstream error")
	}

	var doc flagDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return domain.FlagSet{}, domain.NewError(domain.KindBadGateway, "upstream error")
	}

	flags := make([]domain.FeatureFlag, 0, len(doc.Flags))
	for _, flag := range doc.Flags {
		flags = append(flags, domain.FeatureFlag{
			Name:        flag.Name,
			Enabled:     flag.Enabled,
			Description: flag.Description,
		})
	}
	return domain.FlagSet{Version: doc.Version, Flags: flags}, nil
}
