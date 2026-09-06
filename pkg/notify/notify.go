package notify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Show displays a macOS notification with the Gofing icon.
// It prioritizes the native gofing-notify Cocoa helper, and falls back to osascript if not found.
func Show(title, message string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if helperPath, iconPath := findHelperAndIcon(); helperPath != "" {
		var args []string
		if iconPath != "" {
			args = []string{title, message, iconPath}
		} else {
			args = []string{title, message}
		}
		cmd := exec.CommandContext(ctx, helperPath, args...)
		if err := cmd.Run(); err == nil {
			return nil
		}
	}

	return showFallback(ctx, title, message)
}

// FindIconPath returns the resolved absolute path to the application icon image, or empty string.
func FindIconPath() string {
	_, icon := findHelperAndIcon()
	return icon
}

func findHelperAndIcon() (helperPath string, iconPath string) {
	exePath, err := os.Executable()
	if err == nil {
		exeDir := filepath.Dir(exePath)
		// Check next to executable (e.g. inside Gofing.app/Contents/MacOS/)
		h := filepath.Join(exeDir, "gofing-notify")
		if isFile(h) {
			helperPath = h
		}
		// Icon next to executable or in ../Resources
		candidates := []string{
			filepath.Join(exeDir, "..", "Resources", "Gofing.png"),
			filepath.Join(exeDir, "..", "Resources", "Gofing.icns"),
			filepath.Join(exeDir, "build", "Gofing.png"),
			filepath.Join(exeDir, "Gofing.png"),
		}
		for _, c := range candidates {
			if isFile(c) {
				iconPath = c
				break
			}
		}
	}

	// 2. If not found near executable, search current working directory and ancestors (e.g. tests running in subpackages)
	dir, err := os.Getwd()
	if err == nil {
		for i := 0; i < 5; i++ {
			if helperPath == "" {
				h := filepath.Join(dir, "build", "gofing-notify")
				if isFile(h) {
					helperPath = h
				}
			}
			if iconPath == "" {
				candidates := []string{
					filepath.Join(dir, "build", "Gofing.png"),
					filepath.Join(dir, "build", "Gofing.icns"),
					filepath.Join(dir, "web", "static", "icon.png"),
				}
				for _, c := range candidates {
					if isFile(c) {
						iconPath = c
						break
					}
				}
			}
			if helperPath != "" && iconPath != "" {
				break
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}

	// Ensure iconPath is absolute so Cocoa NSImage finds it regardless of CWD
	if iconPath != "" {
		if abs, err := filepath.Abs(iconPath); err == nil {
			iconPath = abs
		}
	}

	return helperPath, iconPath
}

func isFile(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func showFallback(ctx context.Context, title, message string) error {
	script := "display notification " + appleString(message) + " with title " + appleString(title) + ` sound name "default"`
	cmd := exec.CommandContext(ctx, "osascript", "-e", script)
	return cmd.Run()
}

func appleString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	if len(s) > 200 {
		s = s[:197] + "..."
	}
	return `"` + s + `"`
}

