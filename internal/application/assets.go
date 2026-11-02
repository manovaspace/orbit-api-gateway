package application

// InstallScript returns the canonical installer the edge serves at /.
func (s *Service) InstallScript() []byte { return s.assets.InstallScript() }

// OpenAPISpec returns the committed OpenAPI artifact.
func (s *Service) OpenAPISpec() ([]byte, error) { return s.assets.OpenAPISpec() }

// Manifest returns the committed discovery manifest.
func (s *Service) Manifest() ([]byte, error) { return s.assets.Manifest() }
