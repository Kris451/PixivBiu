package main

// Windows executable resources (the .exe icon + version-info fields) are
// compiled from versioninfo.json + icon.ico into per-arch
// resource_windows_<arch>.syso files. The Go linker auto-embeds the file whose
// GOOS/GOARCH filename suffix matches the target, so Windows builds carry the
// icon while non-Windows builds ignore the .syso entirely.
//
// The .syso files are build artifacts (gitignored); GoReleaser regenerates them
// in a before-hook on every release. Regenerate locally before a manual Windows
// build with: go generate ./cmd/server
//
//go:generate go tool goversioninfo -platform-specific versioninfo.json
