package templates

import (
	"embed"
)

// Templates contains all embedded template files for the WireGuard UI application.
// This provides centralized access to HTML templates and configuration files
// that can be used from anywhere in the codebase, including handlers and utilities.
//
//go:embed *.html *.conf
var Templates embed.FS
