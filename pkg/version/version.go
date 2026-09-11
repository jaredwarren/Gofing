package version

import "fmt"

var (
	// Version is set at link time via -ldflags.
	Version = "dev"
	// BuildTime is set at link time via -ldflags (yyyy-mm-dd hh:mm:ss).
	BuildTime = "unknown"
)

type Details struct {
	Version   string `json:"version"`
	BuildTime string `json:"build_time"`
}

func Get() Details {
	return Details{
		Version:   Version,
		BuildTime: BuildTime,
	}
}

func String() string {
	return fmt.Sprintf("v%s (%s)", Version, BuildTime)
}
