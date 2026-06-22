// Package version holds the build-time metadata for RedShark (user-facing
// brand). The internal module path remains "redteam-agent"
//
// The values are set via -ldflags at release time:
//
//	-X github.com/xanstomper/redteam-agent/internal/version.Version=v0.1.0
//	-X github.com/xanstomper/redteam-agent/internal/version.Commit=$(git rev-parse --short HEAD)
//	-X github.com/xanstomper/redteam-agent/internal/version.BuildDate=$(date -u +%Y-%m-%dT%H:%M:%SZ)
package version

import "fmt"

// These variables are overridden via ldflags at build time.
var (
	Version   = "0.1.0-scaffold"
	Commit    = "dev"
	BuildDate = "unknown"
)

// String returns a one-line human-readable form of the version metadata.
// User-facing brand is "RedShark".
func String() string {
	return fmt.Sprintf("RedShark %s (commit %s, built %s)", Version, Commit, BuildDate)
}

// Short returns just the version string for the header bar.
func Short() string {
	return fmt.Sprintf("v%s", Version)
}

// BrandName is the user-facing product brand.
const BrandName = "RedShark"
