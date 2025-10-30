package toolspec

import (
	"encoding/json"

	"github.com/invopop/jsonschema"
)

// Typed arguments for each tool (these generate the JSON Schemas)

type AnalyzeRepoArgs struct {
	Path string `json:"path" description:"Path to the repository to analyze"`
}

type ScanRepoSBOMArgs struct {
	Path string `json:"path" description:"Path to the repository to scan"`
}

type VulnCheckArgs struct {
	Path string `json:"path" description:"Path to the repository to check"`
}

type SecretScanArgs struct {
	Path   string `json:"path" description:"Path to the repository to scan"`
	Engine string `json:"engine" description:"auto|gitleaks|builtin" default:"auto"`
}

type ToolSpec struct {
	Name        string
	Description string
	Schema      *jsonschema.Schema
}

// Single source of truth for tools
var Registry = []ToolSpec{
	{
		Name:        "analyzeRepo",
		Description: "Run complete security analysis pipeline (SBOM → Vulnerability → Secrets) on a repository",
		Schema:      jsonschema.Reflect(&AnalyzeRepoArgs{}),
	},
	{
		Name:        "scanRepoSBOM",
		Description: "Generate Software Bill of Materials for a repository",
		Schema:      jsonschema.Reflect(&ScanRepoSBOMArgs{}),
	},
	{
		Name:        "vulnCheck",
		Description: "Check for vulnerabilities in repository dependencies using OSV.dev",
		Schema:      jsonschema.Reflect(&VulnCheckArgs{}),
	},
	{
		Name:        "secretScan",
		Description: "Scan repository for secrets and sensitive information",
		Schema:      jsonschema.Reflect(&SecretScanArgs{}),
	},
}

// Convert jsonschema.Schema → map[string]any (for JSON-RPC & manifest)
func ToJSONMap(s *jsonschema.Schema) map[string]any {
	b, _ := json.Marshal(s)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}
