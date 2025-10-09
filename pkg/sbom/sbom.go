// Package sbom provides a fast, heuristic SBOM generator for demo/triage use.
// It walks a project folder and records notable files (sources, module
// manifests, configs, large binaries). It does not attempt to be a full SPDX
// or CycloneDX implementation—just enough structure for downstream tooling.
//
// Design goals:
//   - Zero network calls (safe to run offline).
//   - Skip very large files by default (size threshold).
//   - Ignore noisy directories (.git, node_modules, vendor).
package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Component is a minimal “thing of interest” in a repo, e.g. a source file,
// dependency manifest, configuration file, or large artifact.
type Component struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"` // "source", "module-file", "config", "large-file"
	Path     string `json:"path"`           // path relative to RootPath
	Detected string `json:"detected,omitempty"`
}

// SBOM is a compact, self-contained description of project components.
// Notes clarifies that this is a heuristic, non-SPDX document.
type SBOM struct {
	GeneratedAt string      `json:"generated_at"`
	RootPath    string      `json:"root_path"`
	Components  []Component `json:"components"`
	Notes       string      `json:"notes,omitempty"`
}

// GenerateSBOM walks rootPath and collects a minimal set of components.
// It is intentionally conservative: no network, no dependency resolution.
// This is ideal for quick local triage and as an input to later steps (OSV, etc.).
func GenerateSBOM(rootPath string) (SBOM, error) {
	var comps []Component
	rootPath = filepath.Clean(rootPath)

	err := filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip unreadable entries but do not fail the whole SBOM.
			return nil
		}
		if info.IsDir() {
			switch strings.ToLower(info.Name()) {
			case ".git", "node_modules", "vendor":
				return filepath.SkipDir
			}
			return nil
		}

		rel, _ := filepath.Rel(rootPath, path)
		ext := strings.ToLower(filepath.Ext(path))
		base := strings.ToLower(filepath.Base(path))

		// Skip very large files to keep SBOM small and safe.
		if info.Size() > 10*1024*1024 { // 10MB
			comps = append(comps, Component{
				Name:     filepath.Base(path),
				Type:     "large-file",
				Path:     rel,
				Detected: "skipped-large",
			})
			return nil
		}

		switch {
		// Very light “source-ish” signal
		case ext == ".go" || ext == ".py" || ext == ".js" || ext == ".java" || ext == ".cs":
			comps = append(comps, Component{Name: filepath.Base(path), Type: "source", Path: rel})

		// Dependency / build manifests (used by later stages)
		case base == "go.mod":
			comps = append(comps, Component{Name: "go.mod", Type: "module-file", Path: rel, Detected: "go-module"})
		case base == "go.sum":
			comps = append(comps, Component{Name: "go.sum", Type: "module-file", Path: rel, Detected: "go-sum"})
		case base == "package.json":
			comps = append(comps, Component{Name: "package.json", Type: "module-file", Path: rel, Detected: "npm-package"})
		case base == "requirements.txt":
			comps = append(comps, Component{Name: "requirements.txt", Type: "module-file", Path: rel, Detected: "pip-requirements"})
		case base == "pyproject.toml":
			comps = append(comps, Component{Name: "pyproject.toml", Type: "module-file", Path: rel, Detected: "pyproject"})
		case base == "pom.xml":
			comps = append(comps, Component{Name: "pom.xml", Type: "module-file", Path: rel, Detected: "maven-pom"})

		// Misc config that may matter during triage
		default:
			if base == ".env" || base == "dockerfile" || strings.Contains(base, "license") {
				comps = append(comps, Component{Name: filepath.Base(path), Type: "config", Path: rel})
			}
		}
		return nil
	})
	if err != nil {
		return SBOM{}, err
	}

	return SBOM{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		RootPath:    rootPath,
		Components:  comps,
		Notes:       "Minimal SBOM (demo). Heuristic-only; not full SPDX.",
	}, nil
}

// MarshalJSONPretty renders the SBOM as pretty JSON for CLI/MCP display.
func (s SBOM) MarshalJSONPretty() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}
