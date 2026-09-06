package notify

import (
	"strings"
	"testing"
)

func TestAppleStringEscapesQuotes(t *testing.T) {
	got := appleString(`Amy's "Mac"`)
	if got != `"Amy's \"Mac\""` {
		t.Fatalf("got %s", got)
	}
}

func TestAppleStringTruncates(t *testing.T) {
	got := appleString(strings.Repeat("a", 250))
	if len(got) > 210 {
		t.Fatalf("too long: %d", len(got))
	}
}

func TestShowNotification(t *testing.T) {
	// Verify Show runs without error and without hanging
	err := Show("Gofing Test", "Unit test notification delivery")
	if err != nil {
		t.Fatalf("Show failed: %v", err)
	}
}

func TestFindHelperAndIcon(t *testing.T) {
	helper, icon := findHelperAndIcon()
	t.Logf("findHelperAndIcon returned helper=%q, icon=%q", helper, icon)
	// Even if run from a different CWD, the function should gracefully not panic
}



