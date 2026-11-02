// Package ids is the production domain.CodeGenerator adapter.
package ids

import (
	"crypto/rand"
	"fmt"
)

// Generator creates six-digit numeric challenge codes.
type Generator struct{}

// New returns a code generator.
func New() Generator { return Generator{} }

// NewCode returns a zero-padded six-digit code drawn from crypto/rand.
func (Generator) NewCode() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%06d", (int(b[0])<<16|int(b[1])<<8|int(b[2]))%1000000)
}
