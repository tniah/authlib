// Package assets provides shared static files (fonts, CSS) for authlib example servers.
package assets

import "embed"

//go:embed files
var FS embed.FS
