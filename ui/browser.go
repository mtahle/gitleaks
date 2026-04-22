package ui

import (
	"os/exec"
	"runtime"
)

// openURL opens the given URL in the default web browser.
func openURL(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", url)
	default:
		// Linux / BSD: try xdg-open, then fallback
		cmd = exec.Command("xdg-open", url)
	}
	// Best-effort; ignore errors (headless or unsupported environments).
	_ = cmd.Start()
}
