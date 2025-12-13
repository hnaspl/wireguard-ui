package templates

import (
	"embed"
)

// Templates contains all embedded template files
//
//go:embed *.html *.conf
var Templates embed.FS
