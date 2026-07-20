package web

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var staticFiles embed.FS

// GetStaticFS returns the fs.FS pointing to the static web directory.
func GetStaticFS() (fs.FS, error) {
	return fs.Sub(staticFiles, "static")
}
