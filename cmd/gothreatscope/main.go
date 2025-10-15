// GoThreatScope CLI & MCP entrypoints
//
// This binary serves two roles:
//   1) CLI subcommands for local use:
//        - sbom      : generate a minimal SBOM (heuristic)
//        - vuln      : query osv.dev for issues (incl. malicious packages)
//        - secrets   : scan for secrets (gitleaks if present; builtin fallback)
//        - analyze   : pipeline sbom→vuln→secrets
//      All subcommands persist artifacts per project under:
//        gothreatscope_store/<project_id>/latest/{sbom|vuln|secrets|bundle|metrics}.json
//      and only overwrite artifacts if the content actually changed.
//      A small bounded history is kept at history/<run_id>/ when changes occur.
//
//   2) MCP stdio server (--mcp):
//      Exposes tools (analyzeRepo, scanRepoSBOM, vulnCheck, secretScan) and
//      resources (via pkg/mcp) so IDEs (Cursor/VS Code) can call scans
//      and open the saved artifacts by URI.
//
// Project ID = sha256(absPath)[:12]. History retention controlled by env:
//   GTS_KEEP_HISTORY (default 1).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/anotherik/gothreatscope/pkg/analysis"
	"github.com/anotherik/gothreatscope/pkg/mcp"
	"github.com/anotherik/gothreatscope/pkg/metrics"
	"github.com/anotherik/gothreatscope/pkg/sbom"
	"github.com/anotherik/gothreatscope/pkg/secrets"
	"github.com/anotherik/gothreatscope/pkg/vuln"
)

var (
  version = "dev"      // set by -X main.version
  commit  = "none"     // set by -X main.commit
  date    = "unknown"  // set by -X main.date
)

func hasArg(args []string, targets ...string) bool {
	for _, a := range args {
		for _, t := range targets {
			if a == t {
				return true
			}
		}
	}
	return false
}

func main() {
	
	if len(os.Args) > 1 && hasArg(os.Args[1:], "--version", "-v", "version") {
		fmt.Printf("GoThreatScope %s (commit %s, built %s)\n", version, commit, date)
		return
	}
	
	// No args → show help
	if len(os.Args) < 2 {
		rootUsage()
		return
	}

	arg := os.Args[1]

	// Global flags
	switch arg {
	case "--help", "-h":
		rootUsage()
		return
	case "--mcp":
		runMCP()
		return
	}

	// CLI subcommands
	switch arg {
	case "sbom":
		runSBOM(os.Args[2:])
	case "vuln":
		runVuln(os.Args[2:])
	case "secrets":
		runSecrets(os.Args[2:])
	case "analyze":
		runAnalyze(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", arg)
		rootUsage()
	}
}

// rootUsage prints the top-level help (shown when no args or unknown command).
func rootUsage() {
	fmt.Println("GoThreatScope", version)
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  gothreatscope sbom --path /path")
	fmt.Println("  gothreatscope vuln --path /path")
	fmt.Println("  gothreatscope secrets --path /path [--engine auto|gitleaks|builtin]")
	fmt.Println("  gothreatscope analyze --path /path   # runs sbom→vuln→secrets; persists under gothreatscope_store/")
	fmt.Println("  gothreatscope --mcp                   # start MCP server on stdio (for Cursor/VS Code)")
	fmt.Println("  gothreatscope --version               # print version and exit")
	fmt.Println("  gothreatscope --help                  # show this help menu")
	fmt.Println()
	fmt.Println("Tips:")
	fmt.Println("  Use --help with a subcommand for details, e.g.: gothreatscope sbom --help")
}

/* =========================== sbom =========================== */

// runSBOM executes the SBOM generator and persists results per-project.
// It writes latest/sbom.json on first run or when the SBOM digest changes.
// Metrics are always refreshed (latest/metrics.json + remote POST).
func runSBOM(args []string) {
	fs := flag.NewFlagSet("sbom", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: gothreatscope sbom --path /path/to/repo")
		fs.PrintDefaults()
	}
	path := fs.String("path", ".", "path to repository root")
	_ = fs.Parse(args)

	start := time.Now()
	doc, err := sbom.GenerateSBOM(*path)
	dur := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "SBOM error: %v\n", err)
		os.Exit(2)
	}

	// per-project store
	storeDir, latestDir, historyDir := projectStore(*path)
	_ = os.MkdirAll(latestDir, 0o755)

	// read previous index (digests & counts)
	var prev idx
	_ = readJSON(filepath.Join(storeDir, "index.json"), &prev)

	// digest + change detection
	sbomHex := hex.EncodeToString(digestSBOM(doc))
	needWrite := sbomHex != prev.Digests.SBOM || !exists(filepath.Join(latestDir, "sbom.json"))

	// write if changed or missing
	if needWrite {
		must(writeJSONAtomic(filepath.Join(latestDir, "sbom.json"), doc))
		if keep := getenvInt("GTS_KEEP_HISTORY", 1); keep > 0 {
			runID := nowRunID()
			runDir := filepath.Join(historyDir, runID)
			if err := os.MkdirAll(runDir, 0o755); err == nil {
				_ = copyFile(filepath.Join(latestDir, "sbom.json"), filepath.Join(runDir, "sbom.json"))
				_ = pruneHistory(historyDir, keep)
			}
		}
		prev = updateIndexForSBOM(prev, *path, sbomHex, countSBOMComponents(doc))
		_ = writeJSONAtomic(filepath.Join(storeDir, "index.json"), prev)
	}

	// metrics (always refresh)
	m := metrics.MetricEvent{
		RunID:       nowRunID(),
		StartedAt:   start,
		DurationSec: dur.Seconds(),
		UserConsent: true,
		Env:         metrics.CollectEnv(version),
		Modules: map[string]metrics.Module{
			"sbom": {Status: "ok", DurationMs: dur.Milliseconds(), Findings: countSBOMComponents(doc)},
		},
	}
	_ = writeJSONAtomic(filepath.Join(latestDir, "metrics.json"), m)
	//metrics.SendRemote(m)
	metrics.SendRemote(m)

	// print to stdout (unchanged behavior)
	out, _ := doc.MarshalJSONPretty()
	fmt.Println(string(out))
}

/* =========================== vuln =========================== */

// runVuln executes osv.dev queries for supported manifests and persists result.
// Writes latest/vuln.json when changed; metrics always refreshed.
func runVuln(args []string) {
	fs := flag.NewFlagSet("vuln", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: gothreatscope vuln --path /path/to/repo")
		fmt.Println("Queries osv.dev for detected manifests (Python requirements.txt, Go go.mod).")
		fs.PrintDefaults()
	}
	path := fs.String("path", ".", "path to repository root")
	_ = fs.Parse(args)

	start := time.Now()
	res, err := vuln.VulnCheck(*path) // OSV by default
	dur := time.Since(start)
	if err != nil {
		fmt.Fprintf(os.Stderr, "vulnCheck error: %v\n", err)
		os.Exit(2)
	}

	storeDir, latestDir, historyDir := projectStore(*path)
	_ = os.MkdirAll(latestDir, 0o755)

	var prev idx
	_ = readJSON(filepath.Join(storeDir, "index.json"), &prev)

	vulnHex := hex.EncodeToString(digestVuln(res))
	needWrite := vulnHex != prev.Digests.Vuln || !exists(filepath.Join(latestDir, "vuln.json"))

	if needWrite {
		must(writeJSONAtomic(filepath.Join(latestDir, "vuln.json"), res))
		if keep := getenvInt("GTS_KEEP_HISTORY", 1); keep > 0 {
			runID := nowRunID()
			runDir := filepath.Join(historyDir, runID)
			if err := os.MkdirAll(runDir, 0o755); err == nil {
				_ = copyFile(filepath.Join(latestDir, "vuln.json"), filepath.Join(runDir, "vuln.json"))
				_ = pruneHistory(historyDir, keep)
			}
		}
		prev = updateIndexForVuln(prev, *path, vulnHex, len(res.Findings))
		_ = writeJSONAtomic(filepath.Join(storeDir, "index.json"), prev)
	}

	m := metrics.MetricEvent{
		RunID:       nowRunID(),
		StartedAt:   start,
		DurationSec: dur.Seconds(),
		UserConsent: true,
		Env:         metrics.CollectEnv(version),
		Modules: map[string]metrics.Module{
			"vuln": {Status: "ok", DurationMs: dur.Milliseconds(), Findings: len(res.Findings)},
		},
	}
	_ = writeJSONAtomic(filepath.Join(latestDir, "metrics.json"), m)
	//metrics.SendRemote(m)
	metrics.SendRemote(m)

	b, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(b))
}

/* ========================== secrets ========================== */

// runSecrets scans for secrets using gitleaks when available, else builtin.
// Writes latest/secrets.json when changed; metrics always refreshed.
func runSecrets(args []string) {
	fs := flag.NewFlagSet("secrets", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: gothreatscope secrets --path /path [--engine auto|gitleaks|builtin]")
		fs.PrintDefaults()
	}
	path := fs.String("path", ".", "path to repository root")
	engine := fs.String("engine", "auto", "engine: auto|gitleaks|builtin")
	_ = fs.Parse(args)

	var eng secrets.Engine
	switch *engine {
	case "auto":
		eng = secrets.EngineAuto
	case "gitleaks":
		eng = secrets.EngineGitleaks
	case "builtin":
		eng = secrets.EngineBuiltin
	default:
		fmt.Fprintf(os.Stderr, "invalid --engine: %s\n", *engine)
		os.Exit(2)
	}

	// heads up if gitleaks missing (non-fatal)
	if warn := secrets.EnsureGitleaksInstalled(); warn != nil {
		fmt.Fprintln(os.Stderr, warn)
	}

	start := time.Now()
	res, err := secrets.Scan(*path, eng)
	dur := time.Since(start)
	// continue even if err != nil; we still persist what we got

	storeDir, latestDir, historyDir := projectStore(*path)
	_ = os.MkdirAll(latestDir, 0o755)

	var prev idx
	_ = readJSON(filepath.Join(storeDir, "index.json"), &prev)

	secHex := hex.EncodeToString(digestSecrets(res))
	needWrite := secHex != prev.Digests.Secrets || !exists(filepath.Join(latestDir, "secrets.json"))

	if needWrite {
		must(writeJSONAtomic(filepath.Join(latestDir, "secrets.json"), res))
		if keep := getenvInt("GTS_KEEP_HISTORY", 1); keep > 0 {
			runID := nowRunID()
			runDir := filepath.Join(historyDir, runID)
			if err := os.MkdirAll(runDir, 0o755); err == nil {
				_ = copyFile(filepath.Join(latestDir, "secrets.json"), filepath.Join(runDir, "secrets.json"))
				_ = pruneHistory(historyDir, keep)
			}
		}
		prev = updateIndexForSecrets(prev, *path, secHex, len(res.Findings))
		_ = writeJSONAtomic(filepath.Join(storeDir, "index.json"), prev)
	}

	m := metrics.MetricEvent{
		RunID:       nowRunID(),
		StartedAt:   start,
		DurationSec: dur.Seconds(),
		UserConsent: true,
		Env:         metrics.CollectEnv(version),
		Modules: map[string]metrics.Module{
			"secrets": {Status: statusOf(err), DurationMs: dur.Milliseconds(), Findings: len(res.Findings)},
		},
	}
	_ = writeJSONAtomic(filepath.Join(latestDir, "metrics.json"), m)
	//metrics.SendRemote(m)
	metrics.SendRemote(m)

	b, _ := json.MarshalIndent(res, "", "  ")
	fmt.Println(string(b))

	if err != nil {
		fmt.Fprintf(os.Stderr, "secrets scan error: %v\n", err)
		os.Exit(1)
	}
}

/* ========================== analyze ========================== */

// runAnalyze executes the full pipeline (SBOM→Vuln→Secrets) using pkg/analysis,
// which already implements per-project store, write-on-change, metrics.
func runAnalyze(args []string) {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Println("Usage: gothreatscope analyze --path /path/to/repo")
		fmt.Println("Runs SBOM, OSV vuln, and secrets scan; persists per-project under gothreatscope_store/")
		fs.PrintDefaults()
	}
	path := fs.String("path", ".", "path to repository root")
	_ = fs.Parse(args)

	bundle, err := analysis.AnalyzeRepo(*path)
	if err != nil {
		// Still print bundle if partially created
		out, _ := json.MarshalIndent(bundle, "", "  ")
		fmt.Println(string(out))
		fmt.Fprintf(os.Stderr, "analyze error: %v\n", err)
		os.Exit(1)
	}
	out, _ := json.MarshalIndent(bundle, "", "  ")
	fmt.Println(string(out))
}

/* ============================ MCP ============================ */

// runMCP wires MCP tools to the same persistence model used by the CLI.
// The actual protocol loop lives in pkg/mcp; here we only provide callbacks.
func runMCP() {
	// Tell subpackages we're in MCP mode: stdout must be JSON-only.
    _ = os.Setenv("GTS_MCP_MODE", "1")
	s := &mcp.Server{}

	// A) Full pipeline (already per-project persistent via analysis.AnalyzeRepo)
	s.RunAnalyzeRepo = func(path string) (interface{}, error) {
		return analysis.AnalyzeRepo(path)
	}

	// B) SBOM — persist + return URI
	s.RunScanRepoSBOM = func(path string) (interface{}, error) {
		start := time.Now()
		doc, err := sbom.GenerateSBOM(path)
		if err != nil {
			return nil, err
		}
		storeDir, latestDir, historyDir := projectStore(path)
		_ = os.MkdirAll(latestDir, 0o755)
		var prev idx
		_ = readJSON(filepath.Join(storeDir, "index.json"), &prev)
		sbomHex := hex.EncodeToString(digestSBOM(doc))
		needWrite := sbomHex != prev.Digests.SBOM || !exists(filepath.Join(latestDir, "sbom.json"))
		if needWrite {
			must(writeJSONAtomic(filepath.Join(latestDir, "sbom.json"), doc))
			if keep := getenvInt("GTS_KEEP_HISTORY", 1); keep > 0 {
				runID := nowRunID()
				runDir := filepath.Join(historyDir, runID)
				if err := os.MkdirAll(runDir, 0o755); err == nil {
					_ = copyFile(filepath.Join(latestDir, "sbom.json"), filepath.Join(runDir, "sbom.json"))
					_ = pruneHistory(historyDir, keep)
				}
			}
			prev = updateIndexForSBOM(prev, path, sbomHex, countSBOMComponents(doc))
			_ = writeJSONAtomic(filepath.Join(storeDir, "index.json"), prev)
		}
		dur := time.Since(start)
		m := metrics.MetricEvent{
			RunID:       nowRunID(),
			StartedAt:   start,
			DurationSec: dur.Seconds(),
			UserConsent: true,
			Env:         metrics.CollectEnv(version),
			Modules: map[string]metrics.Module{
				"sbom": {Status: "ok", DurationMs: dur.Milliseconds(), Findings: countSBOMComponents(doc)},
			},
		}
		_ = writeJSONAtomic(filepath.Join(latestDir, "metrics.json"), m)
		//metrics.SendRemote(m)
		metrics.SendRemoteAsync(m)

		return map[string]interface{}{
			"uri":     pathToFileURI(filepath.Join(latestDir, "sbom.json")),
			"changed": needWrite,
			"counts":  map[string]int{"components": countSBOMComponents(doc)},
			"note":    tern(needWrite, "SBOM updated (change detected)", "SBOM unchanged; metrics refreshed"),
		}, nil
	}

	// C) Vuln — persist + return URI
	s.RunVulnCheck = func(path string) (interface{}, error) {
		start := time.Now()
		res, err := vuln.VulnCheck(path)
		if err != nil {
			return nil, err
		}
		storeDir, latestDir, historyDir := projectStore(path)
		_ = os.MkdirAll(latestDir, 0o755)
		var prev idx
		_ = readJSON(filepath.Join(storeDir, "index.json"), &prev)
		vulnHex := hex.EncodeToString(digestVuln(res))
		needWrite := vulnHex != prev.Digests.Vuln || !exists(filepath.Join(latestDir, "vuln.json"))
		if needWrite {
			must(writeJSONAtomic(filepath.Join(latestDir, "vuln.json"), res))
			if keep := getenvInt("GTS_KEEP_HISTORY", 1); keep > 0 {
				runID := nowRunID()
				runDir := filepath.Join(historyDir, runID)
				if err := os.MkdirAll(runDir, 0o755); err == nil {
					_ = copyFile(filepath.Join(latestDir, "vuln.json"), filepath.Join(runDir, "vuln.json"))
					_ = pruneHistory(historyDir, keep)
				}
			}
			prev = updateIndexForVuln(prev, path, vulnHex, len(res.Findings))
			_ = writeJSONAtomic(filepath.Join(storeDir, "index.json"), prev)
		}
		dur := time.Since(start)
		m := metrics.MetricEvent{
			RunID:       nowRunID(),
			StartedAt:   start,
			DurationSec: dur.Seconds(),
			UserConsent: true,
			Env:         metrics.CollectEnv(version),
			Modules: map[string]metrics.Module{
				"vuln": {Status: "ok", DurationMs: dur.Milliseconds(), Findings: len(res.Findings)},
			},
		}
		_ = writeJSONAtomic(filepath.Join(latestDir, "metrics.json"), m)
		//metrics.SendRemote(m)
		metrics.SendRemoteAsync(m)

		return map[string]interface{}{
			"uri":     pathToFileURI(filepath.Join(latestDir, "vuln.json")),
			"changed": needWrite,
			"counts":  map[string]int{"vulns": len(res.Findings)},
			"note":    tern(needWrite, "Vulnerability report updated (change detected)", "Vulnerability report unchanged; metrics refreshed"),
		}, nil
	}

	// D) Secrets — persist + return URI
	s.RunSecretScan = func(path, engine string) (interface{}, error) {
		if engine == "" {
			engine = "auto"
		}
		eng := secrets.Engine(engine)
		// best-effort notice about gitleaks (non-fatal)
		if eng == secrets.EngineAuto || eng == secrets.EngineGitleaks {
			if warn := secrets.EnsureGitleaksInstalled(); warn != nil {
				_ = warn
			}
		}
		start := time.Now()
		res, err := secrets.Scan(path, eng) // continue even if err != nil; we still persist
		storeDir, latestDir, historyDir := projectStore(path)
		_ = os.MkdirAll(latestDir, 0o755)
		var prev idx
		_ = readJSON(filepath.Join(storeDir, "index.json"), &prev)
		secHex := hex.EncodeToString(digestSecrets(res))
		needWrite := secHex != prev.Digests.Secrets || !exists(filepath.Join(latestDir, "secrets.json"))
		if needWrite {
			must(writeJSONAtomic(filepath.Join(latestDir, "secrets.json"), res))
			if keep := getenvInt("GTS_KEEP_HISTORY", 1); keep > 0 {
				runID := nowRunID()
				runDir := filepath.Join(historyDir, runID)
				if err := os.MkdirAll(runDir, 0o755); err == nil {
					_ = copyFile(filepath.Join(latestDir, "secrets.json"), filepath.Join(runDir, "secrets.json"))
					_ = pruneHistory(historyDir, keep)
				}
			}
			prev = updateIndexForSecrets(prev, path, secHex, len(res.Findings))
			_ = writeJSONAtomic(filepath.Join(storeDir, "index.json"), prev)
		}
		dur := time.Since(start)
		m := metrics.MetricEvent{
			RunID:       nowRunID(),
			StartedAt:   start,
			DurationSec: dur.Seconds(),
			UserConsent: true,
			Env:         metrics.CollectEnv(version),
			Modules: map[string]metrics.Module{
				"secrets": {Status: statusOf(err), DurationMs: dur.Milliseconds(), Findings: len(res.Findings)},
			},
		}
		_ = writeJSONAtomic(filepath.Join(latestDir, "metrics.json"), m)
		//metrics.SendRemote(m)
		metrics.SendRemoteAsync(m)

		resp := map[string]interface{}{
			"uri":     pathToFileURI(filepath.Join(latestDir, "secrets.json")),
			"changed": needWrite,
			"counts":  map[string]int{"secrets": len(res.Findings)},
			"note":    tern(needWrite, "Secrets report updated (change detected)", "Secrets report unchanged; metrics refreshed"),
		}
		if err != nil {
			resp["warning"] = err.Error()
		}
		return resp, nil
	}

	if err := s.RunStdio(); err != nil {
		fmt.Fprintf(os.Stderr, "mcp stdio error: %v\n", err)
		os.Exit(1)
	}
}

/* ======================== shared helpers ===================== */

type idx struct {
	ProjectPath string    `json:"project_path"`
	UpdatedAt   time.Time `json:"updated_at"`
	Digests     digests   `json:"digests"`
	Counts      counts    `json:"counts"`
}
type digests struct {
	SBOM    string `json:"sbom"`
	Vuln    string `json:"vuln"`
	Secrets string `json:"secrets"`
	Overall string `json:"overall"`
}
type counts struct {
	Components int `json:"components"`
	Vulns      int `json:"vulns"`
	Secrets    int `json:"secrets"`
}

func nowRunID() string { return time.Now().UTC().Format("20060102T150405Z") }

func projectStore(repoPath string) (storeDir, latestDir, historyDir string) {
	pid := projectID(repoPath)
	storeDir = filepath.Join("gothreatscope_store", pid)
	latestDir = filepath.Join(storeDir, "latest")
	historyDir = filepath.Join(storeDir, "history")
	return
}

func updateIndexForSBOM(prev idx, repoPath, sbomHex string, compCount int) idx {
	prev.ProjectPath = repoPath
	prev.UpdatedAt = time.Now().UTC()
	prev.Digests.SBOM = sbomHex
	prev.Counts.Components = compCount
	prev.Digests.Overall = hexSum(prev.Digests.SBOM, prev.Digests.Vuln, prev.Digests.Secrets)
	return prev
}
func updateIndexForVuln(prev idx, repoPath, vulnHex string, vulnCount int) idx {
	prev.ProjectPath = repoPath
	prev.UpdatedAt = time.Now().UTC()
	prev.Digests.Vuln = vulnHex
	prev.Counts.Vulns = vulnCount
	prev.Digests.Overall = hexSum(prev.Digests.SBOM, prev.Digests.Vuln, prev.Digests.Secrets)
	return prev
}
func updateIndexForSecrets(prev idx, repoPath, secHex string, secretCount int) idx {
	prev.ProjectPath = repoPath
	prev.UpdatedAt = time.Now().UTC()
	prev.Digests.Secrets = secHex
	prev.Counts.Secrets = secretCount
	prev.Digests.Overall = hexSum(prev.Digests.SBOM, prev.Digests.Vuln, prev.Digests.Secrets)
	return prev
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// writeJSONAtomic writes pretty JSON via a temp file then renames (atomic replace).
func writeJSONAtomic(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// pruneHistory keeps at most `keep` history folders (oldest removed first).
func pruneHistory(historyDir string, keep int) error {
	ents, err := os.ReadDir(historyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var runs []string
	for _, e := range ents {
		if e.IsDir() {
			runs = append(runs, e.Name())
		}
	}
	sort.Strings(runs)
	if len(runs) <= keep {
		return nil
	}
	for _, r := range runs[:len(runs)-keep] {
		_ = os.RemoveAll(filepath.Join(historyDir, r))
	}
	return nil
}

func getenvInt(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return def
	}
	return n
}

// projectID returns a stable, anonymous identifier for a repo path.
func projectID(p string) string {
	abs := p
	if a, err := filepath.Abs(p); err == nil {
		abs = a
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:])[:12]
}

func statusOf(err error) string {
	if err != nil {
		return "fail"
	}
	return "ok"
}

// must exits the process on error (used in CLI flows to keep code tidy).
func must(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}

// pathToFileURI converts a local file path to a file:// URI for MCP/CLI references.
func pathToFileURI(p string) string {
    abs, err := filepath.Abs(p)
    if err != nil {
        abs = p
    }
    // On Windows produce file:///C:/path, on POSIX file:///abs/path
    if os.PathSeparator == '\\' {
        abs = strings.ReplaceAll(abs, `\`, `/`)
        // ensure drive letter gets a leading slash
        if len(abs) > 1 && abs[1] == ':' {
            return "file:///" + abs
        }
        return "file:///" + abs
    }
    return "file://" + abs
}


/* -------------- digests & counters (stable) -------------- */

// digestSBOM normalizes the SBOM into ecosystem|name|version lines and hashes it.
// Falls back to hashing the whole JSON if the shape is unfamiliar.
func digestSBOM(doc any) []byte {
	b, _ := json.Marshal(doc)
	var probe struct {
		Components []struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			Version   string `json:"version"`
		} `json:"components"`
	}
	if json.Unmarshal(b, &probe) == nil && len(probe.Components) > 0 {
		type row struct{ E, N, V string }
		rows := make([]row, 0, len(probe.Components))
		for _, c := range probe.Components {
			rows = append(rows, row{E: c.Ecosystem, N: c.Name, V: c.Version})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].E != rows[j].E {
				return rows[i].E < rows[j].E
			}
			if rows[i].N != rows[j].N {
				return rows[i].N < rows[j].N
			}
			return rows[i].V < rows[j].V
		})
		var buf bytes.Buffer
		for _, r := range rows {
			buf.WriteString(r.E); buf.WriteByte("|"[0])
			buf.WriteString(r.N); buf.WriteByte("|"[0])
			buf.WriteString(r.V); buf.WriteByte("\n"[0])
		}
		h := sha256.Sum256(buf.Bytes())
		return h[:]
	}
	h := sha256.Sum256(b)
	return h[:]
}

// digestVuln hashes sorted "ecosystem|package|version|id" tuples for stability.
func digestVuln(res vuln.Result) []byte {
	type t struct{ E, P, V, ID string }
	var rows []t
	for _, f := range res.Findings {
		for _, id := range f.IDs {
			rows = append(rows, t{E: f.Ecosystem, P: f.Package, V: f.Version, ID: id})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].E != rows[j].E {
			return rows[i].E < rows[j].E
		}
		if rows[i].P != rows[j].P {
			return rows[i].P < rows[j].P
		}
		if rows[i].V != rows[j].V {
			return rows[i].V < rows[j].V
		}
		return rows[i].ID < rows[j].ID
	})
	var buf bytes.Buffer
	for _, r := range rows {
		buf.WriteString(r.E); buf.WriteByte("|"[0])
		buf.WriteString(r.P); buf.WriteByte("|"[0])
		buf.WriteString(r.V); buf.WriteByte("|"[0])
		buf.WriteString(r.ID); buf.WriteByte("\n"[0])
	}
	h := sha256.Sum256(buf.Bytes())
	return h[:]
}

// digestSecrets hashes sorted "path|line|rule_id" tuples.
func digestSecrets(res secrets.Result) []byte {
	type t struct {
		Path string
		Line int
		Rule string
	}
	var rows []t
	for _, f := range res.Findings {
		rows = append(rows, t{Path: f.Path, Line: f.StartLine, Rule: f.RuleID})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Path != rows[j].Path {
			return rows[i].Path < rows[j].Path
		}
		if rows[i].Line != rows[j].Line {
			return rows[i].Line < rows[j].Line
		}
		return rows[i].Rule < rows[j].Rule
	})
	var buf bytes.Buffer
	for _, r := range rows {
		buf.WriteString(r.Path); buf.WriteByte("|"[0])
		fmt.Fprintf(&buf, "%d", r.Line); buf.WriteByte("|"[0])
		buf.WriteString(r.Rule); buf.WriteByte("\n"[0])
	}
	h := sha256.Sum256(buf.Bytes())
	return h[:]
}

// hexSum = sha256(SBOMhex + Vulnhex + Secretshex)
func hexSum(parts ...string) string {
	var b bytes.Buffer
	for _, p := range parts {
		b.WriteString(p)
	}
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:])
}

// countSBOMComponents tries to count components without a concrete SBOM type.
func countSBOMComponents(doc any) int {
	b, _ := json.Marshal(doc)
	var probe struct {
		Components []json.RawMessage `json:"components"`
	}
	if json.Unmarshal(b, &probe) == nil && probe.Components != nil {
		return len(probe.Components)
	}
	return 0
}

// tern is a tiny ternary helper for short responses.
func tern[T any](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}
