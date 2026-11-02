// Package assets serves the edge's static documents: the embedded installer and
// the committed OpenAPI artifacts read from disk.
package assets

import (
	_ "embed"
	"os"
	"path/filepath"
)

//go:embed install.sh
var installScript []byte

// Files reads the OpenAPI artifacts from a directory at request time, exactly
// as the edge did before the refactor: a missing file is a 404, not a startup
// failure.
type Files struct {
	root string
}

// New returns an assets reader rooted at the directory that holds
// openapi.yaml and manifest.json (the deployment copies it to /app/openapi).
func New(root string) *Files {
	return &Files{root: root}
}

// InstallScript returns the canonical installer.
func (f *Files) InstallScript() []byte { return installScript }

// OpenAPISpec returns the committed OpenAPI artifact.
func (f *Files) OpenAPISpec() ([]byte, error) {
	return os.ReadFile(filepath.Join(f.root, "openapi.yaml"))
}

// Manifest returns the committed discovery manifest.
func (f *Files) Manifest() ([]byte, error) {
	return os.ReadFile(filepath.Join(f.root, "manifest.json"))
}
