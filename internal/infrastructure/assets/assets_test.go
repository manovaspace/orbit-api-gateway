package assets

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestInstallScriptIsEmbedded(t *testing.T) {
	script := New("unused").InstallScript()
	sum := sha256.Sum256(script)
	// The digest of internal/httpapi/install.sh before the refactor. The script
	// is a public artifact: curl https://<edge>/ | bash runs exactly these bytes.
	const want = "f87e363d4ac3ea888dfe28b4b713fbcf38268ef68226f9c02b4537933dafd926"
	if got := hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("installer digest = %s, want %s", got, want)
	}
}

func TestOpenAPIFilesAreReadFromTheRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "openapi.yaml"), []byte("openapi: 3.1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	files := New(dir)
	if body, err := files.OpenAPISpec(); err != nil || string(body) != "openapi: 3.1.0\n" {
		t.Fatalf("spec = %q, %v", body, err)
	}
	if body, err := files.Manifest(); err != nil || string(body) != "{}\n" {
		t.Fatalf("manifest = %q, %v", body, err)
	}
}

func TestMissingArtifactsAreErrors(t *testing.T) {
	files := New(t.TempDir())
	if _, err := files.OpenAPISpec(); err == nil {
		t.Fatal("a missing spec was not an error")
	}
	if _, err := files.Manifest(); err == nil {
		t.Fatal("a missing manifest was not an error")
	}
}
