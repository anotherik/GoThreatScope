package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"github.com/anotherik/gothreatscope/pkg/mcp/toolspec"
)

type manifestTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	InputSchema map[string]any         `json:"inputSchema"`
}

type manifest struct {
	Name         string         `json:"name"`
	Version      string         `json:"version"`
	Language     string         `json:"language"`
	Tools        []manifestTool `json:"tools"`
	Capabilities map[string]any `json:"capabilities,omitempty"`
}

func main() {
	outFile := filepath.Join(".", "tools.json")

	m := manifest{
		Name:     "anotherik-gothreatscope",
		Version:  "0.1.0", // keep aligned with your release tag
		Language: "go",
		Tools:    make([]manifestTool, 0, len(toolspec.Registry)),
		Capabilities: map[string]any{
			"resources": map[string]any{
				"list": true,
				"read": true,
			},
		},
	}

	for _, r := range toolspec.Registry {
		m.Tools = append(m.Tools, manifestTool{
			Name:        r.Name,
			Description: r.Description,
			InputSchema: toolspec.ToJSONMap(r.Schema),
		})
	}

	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(outFile, b, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("Wrote %s with %d tools (resources supported)\n", outFile, len(m.Tools))
}