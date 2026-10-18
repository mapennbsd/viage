//go:build !(linux || freebsd || darwin || dragonfly || openbsd)

package main

// The filesystem type cannot be told here, so no directory counts as
// RAM-backed and VIAGE_TMPDIR is refused.
func fsType(path string) string { return "" }

func fdFSType(fd int) string { return "" }
