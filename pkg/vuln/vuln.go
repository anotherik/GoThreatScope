// Package vuln queries OSV (osv.dev) for known issues in dependency manifests.
// It currently supports:
//   - Python: requirements.txt
//   - Go:     go.mod
//
// What it detects:
//   - Traditional vulnerabilities (CVEs, GHSA, etc.).
//   - **Malicious packages / malware advisories** published in OSV for some
//     ecosystems (e.g., entries flagged as malicious/typosquats). OSV models
//     these as regular advisories with IDs; you’ll see them listed in the IDs.
//
// Notes:
//   - We prefer exact versions (== in requirements.txt, explicit versions in go.mod).
//   - Network calls are minimized and time-bounded.
//   - Results are a compact list of Findings with advisory IDs.
package vuln

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Finding struct {
	Package   string   `json:"package"`
	Version   string   `json:"version,omitempty"`
	Ecosystem string   `json:"ecosystem"`
	IDs       []string `json:"ids"`   // CVE/GHSA/OSV/MAL-* ids
	Source    string   `json:"source"`// "osv.dev"
}

type Result struct {
	Path     string    `json:"path"`
	Findings []Finding `json:"findings"`
	Note     string    `json:"note"` // "Queried osv.dev"
}

var rePyExact = regexp.MustCompile(`^\s*([A-Za-z0-9_\-\.]+)==([A-Za-z0-9_\-\.]+)\s*$`)

// VulnCheck scans manifests in path and queries OSV for each (package, version).
// It returns all matching advisory IDs, which can include CVEs/GHSA and
// malware/typosquat advisories where present in OSV.
func VulnCheck(path string) (Result, error) {
	path = filepath.Clean(path)

	findings := []Finding{}

	// Python: requirements.txt (exact pins only, to keep queries precise)
	if info, err := os.Stat(filepath.Join(path, "requirements.txt")); err == nil && !info.IsDir() {
		fs, _ := scanPythonRequirements(filepath.Join(path, "requirements.txt"))
		findings = append(findings, fs...)
	}

	// Go: go.mod
	if info, err := os.Stat(filepath.Join(path, "go.mod")); err == nil && !info.IsDir() {
		fs, _ := scanGoMod(filepath.Join(path, "go.mod"))
		findings = append(findings, fs...)
	}

	return Result{Path: path, Findings: findings, Note: "Queried osv.dev"}, nil
}

func scanPythonRequirements(file string) ([]Finding, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	type osvReq struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}

	var findings []Finding
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		// keep things strict here; we ignore non-== pins to avoid guessing
		m := rePyExact.FindStringSubmatch(line)
		if len(m) != 3 {
			continue
		}
		name, ver := m[1], m[2]

		req := osvReq{}
		req.Package.Name = name
		req.Package.Ecosystem = "PyPI"
		req.Version = ver

		ids, _ := queryOSV(req)
		if len(ids) > 0 {
			findings = append(findings, Finding{
				Package: name, Version: ver, Ecosystem: "PyPI",
				IDs: ids, Source: "osv.dev",
			})
		}
	}
	return findings, nil
}

func scanGoMod(file string) ([]Finding, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	type osvReq struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Version string `json:"version"`
	}

	var findings []Finding
	lines := strings.Split(string(data), "\n")
	inBlock := false
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "require (") {
			inBlock = true
			continue
		}
		if inBlock && ln == ")" {
			inBlock = false
			continue
		}

		// handle "require x y" or block lines "module/version vX"
		if strings.HasPrefix(ln, "require ") && !inBlock {
			ln = strings.TrimPrefix(ln, "require ")
		}
		// skip comments and module decls
		if strings.HasPrefix(ln, "module") || strings.HasPrefix(ln, "//") || ln == "" {
			continue
		}

		fields := strings.Fields(ln)
		if len(fields) >= 2 {
			name, ver := fields[0], fields[1]

			req := osvReq{}
			req.Package.Name = name
			req.Package.Ecosystem = "Go"
			req.Version = ver

			ids, _ := queryOSV(req)
			if len(ids) > 0 {
				findings = append(findings, Finding{
					Package: name, Version: ver, Ecosystem: "Go",
					IDs: ids, Source: "osv.dev",
				})
			}
		}
	}
	return findings, nil
}

// queryOSV performs a single-package query and returns advisory IDs,
// including CVE/GHSA and, where applicable, malware/typosquat advisories.
// We keep tight timeouts and set a User-Agent for transparency.
func queryOSV(body interface{}) ([]string, error) {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", "https://api.osv.dev/v1/query", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GoThreatScope/0.3 (+mcp)")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var out struct {
		Vulns []struct{ Id string `json:"id"` } `json:"vulns"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)

	ids := make([]string, 0, len(out.Vulns))
	for _, v := range out.Vulns {
		ids = append(ids, v.Id)
	}
	return ids, nil
}
