// Package secrets provides two scanning modes:
//   1) gitleaks (preferred if installed)
//   2) builtin regex heuristics (fallback)
//
// The Scan() API chooses the engine (auto/gitleaks/builtin) and returns a
// stable JSON structure. We keep runtime + network surface small: no git
// history traversal by default (use --no-git), small file size cap, and a
// minimal env to avoid leaking process secrets to the scanner.
package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Finding struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	RuleID    string `json:"rule_id,omitempty"`
	Match     string `json:"match,omitempty"`
	Engine    string `json:"engine"` // "gitleaks" or "builtin"
}

type Result struct {
	Path     string    `json:"path"`
	Findings []Finding `json:"findings"`
	Note     string    `json:"note"`
}

type Engine string

const (
	EngineAuto    Engine = "auto"
	EngineGitleaks       = "gitleaks"
	EngineBuiltin        = "builtin"
)

// Scan runs the selected engine. In auto mode, gitleaks is used if present,
// otherwise we fall back to builtin regex scanning.
func Scan(path string, engine Engine) (Result, error) {
	path = filepath.Clean(path)
	switch engine {
	case EngineAuto:
		if hasGitleaks() {
			return runGitleaks(path)
		}
		return runBuiltin(path)
	case EngineGitleaks:
		if !hasGitleaks() {
			return Result{Path: path, Findings: nil, Note: "gitleaks not found; try --engine builtin"},
				errors.New("gitleaks binary not found in PATH")
		}
		return runGitleaks(path)
	case EngineBuiltin:
		return runBuiltin(path)
	default:
		return Result{Path: path, Findings: nil, Note: "unknown engine"},
			errors.New("unknown engine")
	}
}

// EnsureGitleaksInstalled returns a friendly hint if gitleaks isn’t on PATH.
// Non-fatal: callers typically log this and continue with the builtin engine.
func EnsureGitleaksInstalled() error {
	if _, err := exec.LookPath("gitleaks"); err != nil {
		msg := `
GoThreatScope notice:
  Gitleaks binary not found in PATH.

To enable full secret scanning coverage, install it with:

  go install github.com/gitleaks/gitleaks/v8/cmd/gitleaks@latest

After installation, ensure "$GOPATH/bin" is in your PATH.

Falling back to builtin regex engine.
`
		return fmt.Errorf(strings.TrimSpace(msg))
	}
	return nil
}

func hasGitleaks() bool {
	_, err := exec.LookPath("gitleaks")
	return err == nil
}

// --- Gitleaks path ----------------------------------------------------------
// We use: gitleaks detect --no-git --source <path> --report-format json --report-path -
// Output is typically a JSON array (gitleaks >=8); some setups emit JSON lines.
// We handle both and normalize to []Finding.
func runGitleaks(path string) (Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	args := []string{
		"detect",
		"--no-git",
		"--source", path,
		"--report-format", "json",
		"--report-path", "-", // write JSON to stdout
	}
	cmd := exec.CommandContext(ctx, "gitleaks", args...)
	cmd.Env = minimalEnv()
	out, err := cmd.Output()
	// If gitleaks returns non-zero due to findings, try to parse stdout anyway.

	findings := parseGitleaksJSON(out)
	return Result{
		Path:     path,
		Findings: findings,
		Note:     "scanned with gitleaks",
	}, err
}

func minimalEnv() []string {
	// Keep only PATH to find gitleaks; avoid leaking env secrets to the scanner.
	path := os.Getenv("PATH")
	return []string{"PATH=" + path}
}

// gitleaksEntry matches the subset of gitleaks JSON fields we care about.
type gitleaksEntry struct {
	File        string `json:"File"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	RuleID      string `json:"RuleID"`
	Match       string `json:"Match"`
	Description string `json:"Description"`
}

// parseGitleaksJSON supports both a single JSON array and newline-delimited JSON.
func parseGitleaksJSON(b []byte) []Finding {
	if len(b) == 0 {
		return nil
	}
	var arr []gitleaksEntry
	if json.Unmarshal(b, &arr) == nil {
		return mapGL(arr)
	}
	// Fallback: line-by-line
	lines := strings.Split(string(b), "\n")
	out := make([]Finding, 0, len(lines))
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		var e gitleaksEntry
		if json.Unmarshal([]byte(ln), &e) == nil {
			out = append(out, Finding{
				Path: e.File, StartLine: e.StartLine, EndLine: e.EndLine,
				RuleID: e.RuleID, Match: e.Match, Engine: "gitleaks",
			})
		}
	}
	return out
}

func mapGL(arr []gitleaksEntry) []Finding {
	out := make([]Finding, 0, len(arr))
	for _, e := range arr {
		out = append(out, Finding{
			Path: e.File, StartLine: e.StartLine, EndLine: e.EndLine,
			RuleID: e.RuleID, Match: e.Match, Engine: "gitleaks",
		})
	}
	return out
}

// --- Builtin (simple regex heuristics) --------------------------------------
// Note: these are intentionally conservative and are not a substitute for
// gitleaks’ curated rules. They’re good enough for demos and quick checks.
var builtinRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["']?[A-Za-z0-9/\+=]{20,}["']?`),
	regexp.MustCompile(`(?i)api[_-]?key\s*[:=]\s*["']?[A-Za-z0-9\-_]{8,}["']?`),
	regexp.MustCompile(`(?i)password\s*[:=]\s*["']?[^"'\s]{6,}["']?`),
	regexp.MustCompile(`(?i)xox[baprs]-[A-Za-z0-9-]{10,}`), // Slack tokens (very rough)
}

func runBuiltin(path string) (Result, error) {
	var findings []Finding
	_ = filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		// limit to small-ish text files
		if info.Size() > 512*1024 {
			return nil
		}
		base := strings.ToLower(filepath.Base(p))
		if strings.HasPrefix(base, ".git") || strings.Contains(p, string(os.PathSeparator)+".git"+string(os.PathSeparator)) {
			return nil
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		txt := string(data)
		for _, re := range builtinRegexes {
			if loc := re.FindStringIndex(txt); loc != nil {
				start := lineFromOffset(txt, loc[0])
				end := lineFromOffset(txt, loc[1])
				findings = append(findings, Finding{
					Path: p, StartLine: start, EndLine: end,
					RuleID: "builtin:" + re.String(), Match: txt[loc[0]:loc[1]],
					Engine: "builtin",
				})
			}
		}
		return nil
	})
	return Result{
		Path:     path,
		Findings: findings,
		Note:     "scanned with builtin regex (gitleaks not found)",
	}, nil
}

func lineFromOffset(s string, off int) int {
	if off <= 0 {
		return 1
	}
	cnt := 1
	for i := 0; i < off && i < len(s); i++ {
		if s[i] == '\n' {
			cnt++
		}
	}
	return cnt
}
