//go:build !darwin || !cgo

package main

import (
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
)

func runNativeWindow(targetURL string) {
	switch runtime.GOOS {
	case "linux":
		_ = exec.Command("xdg-open", targetURL).Start()
	case "windows":
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL).Start()
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}

func terminateNativeApp() {
	// No-op on non-Darwin platforms
}
