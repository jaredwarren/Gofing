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

// GetIconSVG returns the raw SVG string of the application icon.
func GetIconSVG() (string, error) {
	b, err := staticFiles.ReadFile("static/icon.svg")
	return string(b), err
}

// GetIconPNG returns the PNG bytes of the application icon.
func GetIconPNG() ([]byte, error) {
	return staticFiles.ReadFile("static/icon.png")
}

