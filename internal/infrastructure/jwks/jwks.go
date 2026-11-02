// Package jwks loads the public access-token verification keys the edge
// publishes at /.well-known/jwks.json.
package jwks

import (
	"encoding/json"
	"fmt"

	orbittoken "github.com/manovaspace/orbit-auth/token"
)

// Document is the marshalled JWK set plus the number of keys it holds.
type Document struct {
	body []byte
	keys int
}

// Load reads the PEM key set in dir and marshals it once at startup.
func Load(dir string) (*Document, error) {
	keys, err := orbittoken.LoadKeySet(dir)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(keys.Document())
	if err != nil {
		return nil, fmt.Errorf("jwks: marshal document: %w", err)
	}
	return &Document{body: body, keys: len(keys)}, nil
}

// Body returns the JSON document served to clients.
func (d *Document) Body() []byte { return d.body }

// Keys returns the number of published keys, for the startup log line.
func (d *Document) Keys() int { return d.keys }
