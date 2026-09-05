package notify

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// Show displays a macOS notification via osascript. Timeout-bounded.
func Show(title, message string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	script := "display notification " + appleString(message) + " with title " + appleString(title)
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
