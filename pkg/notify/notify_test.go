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
