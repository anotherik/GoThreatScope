package analysis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/anotherik/gothreatscope/pkg/metrics"
	"github.com/anotherik/gothreatscope/pkg/sbom"
	"github.com/anotherik/gothreatscope/pkg/secrets"
	"github.com/anotherik/gothreatscope/pkg/vuln"
)

type Bundle struct {
	RunID      string        `json:"run_id"`
	RepoPath   string        `json:"repo"`
	SBOMURI    string        `json:"sbom_uri"`
	VulnURI    string        `json:"vuln_uri"`
	SecretsURI string        `json:"secrets_uri"`
	Summary    BundleSummary `json:"summary"`
	Note       string        `json:"note"`
}

type BundleSummary struct {
	Components int `json:"components"`
	Vulns      int `json:"vulns"`
	Secrets    int `json:"secrets"`
}

// AnalyzeRepo runs SBOM → OSV Vuln → Secrets, then stores artifacts per-project.
// It overwrites only the parts that changed (or are missing) and always refreshes metrics.
func AnalyzeRepo(repoPath string) (Bundle, error) {
	runID := time.Now().UTC().Format("20060102T150405Z")
	start := time.Now()

	/* --------- run the three analyses --------- */
	sbomStart := time.Now()
	sbomDoc, err := sbom.GenerateSBOM(repoPath)
	sbomDur := time.Since(sbomStart)
	if err != nil {
		return Bundle{}, fmt.Errorf("sbom: %w", err)
	}

	vulnStart := time.Now()
	vulnRes, err := vuln.VulnCheck(repoPath)
	vulnDur := time.Since(vulnStart)
	if err != nil {
		return Bundle{}, fmt.Errorf("vuln: %w", err)
	}

	secretsStart := time.Now()
	secRes, secErr := secrets.Scan(repoPath, secrets.EngineAuto)
	secretsDur := time.Since(secretsStart)
	// keep going even if secErr != nil; we still persist what we have

	/* --------- compute per-project paths --------- */
	storeDir := filepath.Join("gothreatscope_store", projectID(repoPath))
	latestDir := filepath.Join(storeDir, "latest")
	historyDir := filepath.Join(storeDir, "history")
	if err := os.MkdirAll(latestDir, 0o755); err != nil {
		return Bundle{}, fmt.Errorf("mkdir store: %w", err)
	}

	/* --------- read previous index (digests per artifact) --------- */
	metaPath := filepath.Join(storeDir, "index.json")
	var prev idx
	_ = readJSON(metaPath, &prev)

	/* --------- build normalized digests (stable, no volatile fields) --------- */
	sbomHex := hex.EncodeToString(digestSBOM(sbomDoc)) // now type-agnostic
	vulnHex := hex.EncodeToString(digestVuln(vulnRes))
	secHex := hex.EncodeToString(digestSecrets(secRes))
	overallHex := hexSum(sbomHex, vulnHex, secHex)

	/* --------- decide what to write --------- */
	needSBOM := sbomHex != prev.Digests.SBOM || !exists(filepath.Join(latestDir, "sbom.json"))
	needVuln := vulnHex != prev.Digests.Vuln || !exists(filepath.Join(latestDir, "vuln.json"))
	needSec := secHex != prev.Digests.Secrets || !exists(filepath.Join(latestDir, "secrets.json"))
	changedAny := needSBOM || needVuln || needSec

	/* --------- write artifacts if missing/changed --------- */
	if needSBOM {
		if err := writeJSONAtomic(filepath.Join(latestDir, "sbom.json"), sbomDoc); err != nil {
			return Bundle{}, err
		}
	}
	if needVuln {
		if err := writeJSONAtomic(filepath.Join(latestDir, "vuln.json"), vulnRes); err != nil {
			return Bundle{}, err
		}
	}
	if needSec {
		if err := writeJSONAtomic(filepath.Join(latestDir, "secrets.json"), secRes); err != nil {
			return Bundle{}, err
		}
	}

	/* --------- optional history only when changed --------- */
	if changedAny {
		if keep := getenvInt("GTS_KEEP_HISTORY", 1); keep > 0 {
			runDir := filepath.Join(historyDir, runID)
			if err := os.MkdirAll(runDir, 0o755); err == nil {
				if needSBOM {
					_ = copyFile(filepath.Join(latestDir, "sbom.json"), filepath.Join(runDir, "sbom.json"))
				}
				if needVuln {
					_ = copyFile(filepath.Join(latestDir, "vuln.json"), filepath.Join(runDir, "vuln.json"))
				}
				if needSec {
					_ = copyFile(filepath.Join(latestDir, "secrets.json"), filepath.Join(runDir, "secrets.json"))
				}
				_ = pruneHistory(historyDir, keep)
			}
		}
		// update index
		prev = idx{
			ProjectPath: repoPath,
			UpdatedAt:   time.Now().UTC(),
			Digests: digests{
				SBOM:    sbomHex,
				Vuln:    vulnHex,
				Secrets: secHex,
				Overall: overallHex,
			},
			Counts: counts{
				Components: countSBOMComponents(sbomDoc), // was len(sbomDoc.Components)
				Vulns:      len(vulnRes.Findings),
				Secrets:    len(secRes.Findings),
			},
		}
		_ = writeJSONAtomic(metaPath, prev)
	}

	/* --------- metrics (always refreshed; no per-run folder) --------- */
	totalDur := time.Since(start)
	m := metrics.MetricEvent{
		RunID:       runID,
		StartedAt:   start,
		DurationSec: totalDur.Seconds(),
		UserConsent: true,
		Env:         metrics.CollectEnv("0.3.1"),
		Modules: map[string]metrics.Module{
			"sbom":    {Status: "ok", DurationMs: sbomDur.Milliseconds(), Findings: countSBOMComponents(sbomDoc)}, // was len(...)
			"vuln":    {Status: "ok", DurationMs: vulnDur.Milliseconds(), Findings: len(vulnRes.Findings)},
			"secrets": {Status: statusOf(secErr), DurationMs: secretsDur.Milliseconds(), Findings: len(secRes.Findings)},
		},
	}
	_ = writeJSONAtomic(filepath.Join(latestDir, "metrics.json"), m)
	//metrics.SendRemote(m)
	metrics.SendRemote(m)

	/* --------- final bundle (URIs always point to latest/*) --------- */
	summary := BundleSummary{
		Components: countSBOMComponents(sbomDoc), // was len(...)
		Vulns:      len(vulnRes.Findings),
		Secrets:    len(secRes.Findings),
	}
	b := Bundle{
		RunID:      runID,
		RepoPath:   repoPath,
		SBOMURI:    pathToFileURI(filepath.Join(latestDir, "sbom.json")),
		VulnURI:    pathToFileURI(filepath.Join(latestDir, "vuln.json")),
		SecretsURI: pathToFileURI(filepath.Join(latestDir, "secrets.json")),
		Summary:    summary,
		Note: func() string {
			if changedAny {
				return "Artifacts updated (change detected)"
			}
			return "No changes since last run; metrics refreshed"
		}(),
	}
	_ = writeJSONAtomic(filepath.Join(latestDir, "bundle.json"), b)
	if changedAny {
		if keep := getenvInt("GTS_KEEP_HISTORY", 1); keep > 0 {
			_ = writeJSONAtomic(filepath.Join(historyDir, runID, "bundle.json"), b)
		}
	}

	// Preserve previous behavior: do not fail on secrets error, just note status in metrics.
	if secErr != nil {
		// still return the bundle; caller can read Note/metrics for the warning
	}

	return b, nil
}

/* ----------------- helpers / types ----------------- */

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

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

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

func projectID(p string) string {
	abs := p
	if a, err := filepath.Abs(p); err == nil {
		abs = a
	}
	sum := sha256.Sum256([]byte(abs))
	return hex.EncodeToString(sum[:])[:12]
}

func pathToFileURI(p string) string {
    abs, err := filepath.Abs(p)
    if err != nil {
        abs = p
    }
    if os.PathSeparator == '\\' {
        abs = strings.ReplaceAll(abs, `\`, `/`)
        if len(abs) > 1 && abs[1] == ':' {
            return "file:///" + abs
        }
        return "file:///" + abs
    }
    return "file://" + abs
}

func statusOf(err error) string {
	if err != nil {
		return "fail"
	}
	return "ok"
}

/* ---------- normalized digests (stable) ---------- */

// SBOM digest (type-agnostic):
// Try to extract components as ecosystem|name|version; else hash the whole JSON.
func digestSBOM(doc any) []byte {
	// Marshal the doc to JSON
	b, _ := json.Marshal(doc)

	// Probe a common shape: { "components": [ { "ecosystem","name","version" } ] }
	var probe struct {
		Components []struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
			Version   string `json:"version"`
		} `json:"components"`
	}
	if err := json.Unmarshal(b, &probe); err == nil && len(probe.Components) > 0 {
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
			buf.WriteString(r.E)
			buf.WriteByte('|')
			buf.WriteString(r.N)
			buf.WriteByte('|')
			buf.WriteString(r.V)
			buf.WriteByte('\n')
		}
		h := sha256.Sum256(buf.Bytes())
		return h[:]
	}

	// Fallback: stable hash of the whole JSON
	h := sha256.Sum256(b)
	return h[:]
}

// Vuln digest: hash sorted "eco|pkg|ver|id" tuples.
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
	buf := &bytes.Buffer{}
	for _, r := range rows {
		buf.WriteString(r.E)
		buf.WriteByte('|')
		buf.WriteString(r.P)
		buf.WriteByte('|')
		buf.WriteString(r.V)
		buf.WriteByte('|')
		buf.WriteString(r.ID)
		buf.WriteByte('\n')
	}
	h := sha256.Sum256(buf.Bytes())
	return h[:]
}

// Secrets digest: hash sorted "path|line|rule_id" tuples.
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
	buf := &bytes.Buffer{}
	for _, r := range rows {
		buf.WriteString(r.Path)
		buf.WriteByte('|')
		fmt.Fprintf(buf, "%d", r.Line)
		buf.WriteByte('|')
		buf.WriteString(r.Rule)
		buf.WriteByte('\n')
	}
	h := sha256.Sum256(buf.Bytes())
	return h[:]
}

// overall = sha256(SBOMhex + Vulnhex + Secretshex) — stable string concat
func hexSum(parts ...string) string {
	var b bytes.Buffer
	for _, p := range parts {
		b.WriteString(p)
	}
	sum := sha256.Sum256(b.Bytes())
	return hex.EncodeToString(sum[:])
}

// countSBOMComponents tries to count components without relying on a concrete SBOM type.
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
