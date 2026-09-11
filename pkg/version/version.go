package version

import "fmt"

var (
	// Version is the semantic version string, set at link time via -ldflags.
	Version = "dev"
	// BuildTime is the compilation timestamp (yyyy-mm-dd hh:mm:ss), set at link time via -ldflags.
	BuildTime = "unknown"
)

// Details holds structured version information for serialization.
type Details struct {
	Version   string `json:"version"`
	BuildTime string `json:"build_time"`
}

// Get returns the current version details.
func Get() Details {
	return Details{
		Version:   Version,
		BuildTime: BuildTime,
	}
}

// String returns a human-readable representation of version and build time.
func String() string {
	return fmt.Sprintf("v%s (%s)", Version, BuildTime)
}
