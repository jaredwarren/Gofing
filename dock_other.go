//go:build !darwin || !cgo

package main

func setNativeDockIcon(_ []byte) {
	// No-op on non-macOS or non-CGO builds
}

