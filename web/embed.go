package web

import (
	"embed"
	"io/fs"
)

//go:embed static/*
var staticFiles embed.FS

func StaticFS() (fs.FS, error) {
	return fs.Sub(staticFiles, "static")
}

func IconSVG() (string, error) {
	b, err := staticFiles.ReadFile("static/icon.svg")
	return string(b), err
}

func IconPNG() ([]byte, error) {
	return staticFiles.ReadFile("static/icon.png")
}
