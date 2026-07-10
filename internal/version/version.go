// Package version holds build metadata injected at link time via -ldflags.
package version

// These values are overridden at build time with:
//
//	-ldflags "-X github.com/t0mer/sophos-exporter/internal/version.Version=... \
//	          -X github.com/t0mer/sophos-exporter/internal/version.Commit=...  \
//	          -X github.com/t0mer/sophos-exporter/internal/version.Date=..."
var (
	// Version is the semantic (YYYY.M.PATCH) release version.
	Version = "dev"
	// Commit is the git commit the binary was built from.
	Commit = "none"
	// Date is the build timestamp (RFC3339).
	Date = "unknown"
)
