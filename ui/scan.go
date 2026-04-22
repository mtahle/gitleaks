package ui

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ScanOptions mirrors every flag exposed by the gitleaks CLI that the web UI
// may configure.
type ScanOptions struct {
	// Scan command: "git", "dir", or "stdin"
	Command string `json:"command"`

	// Target path (git repo or directory)
	Target string `json:"target"`

	// ── git flags ──
	Platform  string `json:"platform"`
	Staged    bool   `json:"staged"`
	PreCommit bool   `json:"preCommit"`
	LogOpts   string `json:"logOpts"`

	// ── dir flag ──
	FollowSymlinks bool `json:"followSymlinks"`

	// ── global flags ──
	Config             string   `json:"config"`
	ExitCode           int      `json:"exitCode"`
	BaselinePath       string   `json:"baselinePath"`
	LogLevel           string   `json:"logLevel"`
	Verbose            bool     `json:"verbose"`
	MaxTargetMegabytes int      `json:"maxTargetMegabytes"`
	IgnoreGitleaksAllow bool    `json:"ignoreGitleaksAllow"`
	Redact             int      `json:"redact"`
	EnableRules        []string `json:"enableRules"`
	GitleaksIgnorePath string   `json:"gitleaksIgnorePath"`
	MaxDecodeDepth     int      `json:"maxDecodeDepth"`
	MaxArchiveDepth    int      `json:"maxArchiveDepth"`
	Timeout            int      `json:"timeout"`

	// ── report flags ──
	ReportFormat   string `json:"reportFormat"`
	ReportTemplate string `json:"reportTemplate"`
}

// buildArgs converts ScanOptions into a []string of gitleaks CLI arguments.
// The binary path is NOT included; callers prepend it themselves.
func buildArgs(opts ScanOptions) ([]string, string, error) {
	// Determine command
	cmd := strings.TrimSpace(strings.ToLower(opts.Command))
	if cmd == "" {
		cmd = "git"
	}

	// Create a temp file for JSON findings output so the UI can display them.
	tmpDir := os.TempDir()
	reportPath := filepath.Join(tmpDir, fmt.Sprintf("gitleaks-ui-%d.json", time.Now().UnixNano()))

	args := []string{cmd}

	// ── command-specific flags ──
	switch cmd {
	case "git":
		if opts.Platform != "" {
			args = append(args, "--platform", opts.Platform)
		}
		if opts.Staged {
			args = append(args, "--staged")
		}
		if opts.PreCommit {
			args = append(args, "--pre-commit")
		}
		if opts.LogOpts != "" {
			args = append(args, "--log-opts", opts.LogOpts)
		}
		if opts.Target != "" {
			args = append(args, opts.Target)
		}
	case "dir":
		if opts.FollowSymlinks {
			args = append(args, "--follow-symlinks")
		}
		if opts.Target != "" {
			args = append(args, opts.Target)
		}
	case "stdin":
		// no extra flags
	default:
		return nil, "", fmt.Errorf("unknown command %q, must be git, dir, or stdin", cmd)
	}

	// ── global flags ──
	if opts.Config != "" {
		args = append(args, "--config", opts.Config)
	}
	if opts.ExitCode != 0 {
		args = append(args, "--exit-code", strconv.Itoa(opts.ExitCode))
	}
	if opts.BaselinePath != "" {
		args = append(args, "--baseline-path", opts.BaselinePath)
	}
	if opts.LogLevel != "" && opts.LogLevel != "info" {
		args = append(args, "--log-level", opts.LogLevel)
	}
	if opts.Verbose {
		args = append(args, "--verbose")
	}
	if opts.MaxTargetMegabytes > 0 {
		args = append(args, "--max-target-megabytes", strconv.Itoa(opts.MaxTargetMegabytes))
	}
	if opts.IgnoreGitleaksAllow {
		args = append(args, "--ignore-gitleaks-allow")
	}
	if opts.Redact > 0 {
		args = append(args, fmt.Sprintf("--redact=%d", opts.Redact))
	}
	for _, rule := range opts.EnableRules {
		if rule != "" {
			args = append(args, "--enable-rule", rule)
		}
	}
	if opts.GitleaksIgnorePath != "" {
		args = append(args, "--gitleaks-ignore-path", opts.GitleaksIgnorePath)
	}
	if opts.MaxDecodeDepth > 0 {
		args = append(args, "--max-decode-depth", strconv.Itoa(opts.MaxDecodeDepth))
	}
	if opts.MaxArchiveDepth > 0 {
		args = append(args, "--max-archive-depth", strconv.Itoa(opts.MaxArchiveDepth))
	}
	if opts.Timeout > 0 {
		args = append(args, "--timeout", strconv.Itoa(opts.Timeout))
	}

	// ── report flags ── (always write JSON so findings are loadable)
	args = append(args, "--report-format", "json", "--report-path", reportPath)

	// Suppress the ASCII banner so logs stay clean.
	args = append(args, "--no-banner")

	return args, reportPath, nil
}

// runScan executes gitleaks as a subprocess, streaming output lines to the
// provided channel, and returns any findings from the JSON report file.
// cancel should be the context.CancelFunc that stops the scan on demand.
func runScan(ctx context.Context, binaryPath string, opts ScanOptions, logCh chan<- string) ([]json.RawMessage, error) {
	args, reportPath, err := buildArgs(opts)
	if err != nil {
		return nil, err
	}
	defer os.Remove(reportPath)

	cmd := exec.CommandContext(ctx, binaryPath, args...)

	// Merge stdout + stderr into the log channel.
	pr, pw, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("creating pipe: %w", err)
	}
	cmd.Stdout = pw
	cmd.Stderr = pw

	if startErr := cmd.Start(); startErr != nil {
		_ = pw.Close()
		_ = pr.Close()
		return nil, fmt.Errorf("starting gitleaks: %w", startErr)
	}
	_ = pw.Close()

	// Stream lines to channel.
	scanner := bufio.NewScanner(pr)
	for scanner.Scan() {
		select {
		case logCh <- scanner.Text():
		case <-ctx.Done():
		}
	}
	_ = pr.Close()

	waitErr := cmd.Wait()

	// Read findings (exit code 1 = leaks found is NOT a fatal error here).
	findings, readErr := readFindings(reportPath)
	if readErr != nil {
		// If no report was written it likely means the scan failed early.
		if waitErr != nil {
			return nil, waitErr
		}
		return nil, readErr
	}
	// A non-zero exit code just means leaks were found; don't treat as error.
	return findings, nil
}

// readFindings loads the JSON report file written by gitleaks.
func readFindings(path string) ([]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var findings []json.RawMessage
	if err := json.Unmarshal(data, &findings); err != nil {
		// Empty or malformed output → return empty list.
		return []json.RawMessage{}, nil
	}
	return findings, nil
}
