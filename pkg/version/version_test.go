package version

import (
	"testing"
)

func TestVersionGetAndString(t *testing.T) {
	origVersion := Version
	origBuildTime := BuildTime
	defer func() {
		Version = origVersion
		BuildTime = origBuildTime
	}()

	Version = "1.2.3"
	BuildTime = "2026-09-10 14:30:00"

	d := Get()
	if d.Version != "1.2.3" {
		t.Errorf("expected version 1.2.3, got %s", d.Version)
	}
	if d.BuildTime != "2026-09-10 14:30:00" {
		t.Errorf("expected build time 2026-09-10 14:30:00, got %s", d.BuildTime)
	}

	str := String()
	expected := "v1.2.3 (2026-09-10 14:30:00)"
	if str != expected {
		t.Errorf("expected %s, got %s", expected, str)
	}
}
