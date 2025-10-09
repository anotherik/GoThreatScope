// Package mcp implements the Model Context Protocol (MCP) server for GoThreatScope.
// This allows IDEs like Cursor/VS Code to integrate security analysis tools.
package mcp

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Server represents the MCP server with configurable tool implementations.
type Server struct {
	// Tool implementations (set by main.go)
	RunAnalyzeRepo   func(path string) (interface{}, error)
	RunScanRepoSBOM  func(path string) (interface{}, error)
	RunVulnCheck     func(path string) (interface{}, error)
	RunSecretScan    func(path, engine string) (interface{}, error)
}

// MCP message types
type Request struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type Response struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *Error      `json:"error,omitempty"`
}

type Error struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Tool definitions
type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

type ToolCall struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

// Resource definitions
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description"`
	MimeType    string `json:"mimeType,omitempty"`
}

type ResourceContents struct {
	URI     string `json:"uri"`
	MimeType string `json:"mimeType"`
	Text    string `json:"text,omitempty"`
	Blob    string `json:"blob,omitempty"`
}

// Initialize request/response
type InitializeRequest struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ClientInfo      map[string]interface{} `json:"clientInfo"`
}

type InitializeResponse struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      map[string]interface{} `json:"serverInfo"`
}

// RunStdio starts the MCP server using stdio transport.
func (s *Server) RunStdio() error {
	// Set up logging to stderr to avoid interfering with JSON-RPC on stdout
	log.SetOutput(os.Stderr)
	log.SetPrefix("[GoThreatScope MCP] ")
	
	// Use buffered I/O for better performance
	reader := bufio.NewReader(os.Stdin)
	writer := bufio.NewWriter(os.Stdout)
	defer writer.Flush()

	// Initialize the server
	initialized := false

	for {
		// Read JSON-RPC message
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("read error: %w", err)
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Parse request
		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			log.Printf("Failed to parse request: %v", err)
			continue
		}

		// Handle request
		resp := s.handleRequest(req, &initialized)
		
		// Send response
		respBytes, err := json.Marshal(resp)
		if err != nil {
			log.Printf("Failed to marshal response: %v", err)
			continue
		}

		if _, err := writer.WriteString(string(respBytes) + "\n"); err != nil {
			return fmt.Errorf("write error: %w", err)
		}
		writer.Flush()
	}

	return nil
}

func (s *Server) handleRequest(req Request, initialized *bool) Response {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req, initialized)
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolsCall(req)
	case "resources/list":
		return s.handleResourcesList(req)
	case "resources/read":
		return s.handleResourcesRead(req)
	case "notifications/initialized":
		// No response needed for notifications
		return Response{}
	default:
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &Error{
				Code:    -32601,
				Message: "Method not found",
			},
		}
	}
}

func (s *Server) handleInitialize(req Request, initialized *bool) Response {
	if *initialized {
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &Error{
				Code:    -32002,
				Message: "Already initialized",
			},
		}
	}

	*initialized = true

	return Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: InitializeResponse{
			ProtocolVersion: "2024-11-05",
			Capabilities: map[string]interface{}{
				"tools": map[string]interface{}{
					"listChanged": false,
				},
				"resources": map[string]interface{}{
					"subscribe":   false,
					"listChanged": false,
				},
			},
			ServerInfo: map[string]interface{}{
				"name":    "GoThreatScope",
				"version": "0.1",
			},
		},
	}
}

func (s *Server) handleToolsList(req Request) Response {
	tools := []Tool{
		{
			Name:        "analyzeRepo",
			Description: "Run complete security analysis pipeline (SBOM → Vulnerability → Secrets) on a repository",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the repository to analyze",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "scanRepoSBOM",
			Description: "Generate Software Bill of Materials for a repository",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the repository to scan",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "vulnCheck",
			Description: "Check for vulnerabilities in repository dependencies using OSV.dev",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the repository to check",
					},
				},
				"required": []string{"path"},
			},
		},
		{
			Name:        "secretScan",
			Description: "Scan repository for secrets and sensitive information",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Path to the repository to scan",
					},
					"engine": map[string]interface{}{
						"type":        "string",
						"description": "Scanning engine to use (auto, gitleaks, builtin)",
						"default":     "auto",
					},
				},
				"required": []string{"path"},
			},
		},
	}

	return Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	}
}

func (s *Server) handleToolsCall(req Request) Response {
	// Parse tool call parameters
	var params map[string]interface{}
	if req.Params != nil {
		if paramsMap, ok := req.Params.(map[string]interface{}); ok {
			params = paramsMap
		}
	}

	if params == nil {
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &Error{
				Code:    -32602,
				Message: "Invalid params",
			},
		}
	}

	// Extract tool name and arguments
	toolCall, ok := params["name"].(string)
	if !ok {
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &Error{
				Code:    -32602,
				Message: "Missing tool name",
			},
		}
	}

	arguments, ok := params["arguments"].(map[string]interface{})
	if !ok {
		arguments = make(map[string]interface{})
	}

	// Execute tool
	result, err := s.executeTool(toolCall, arguments)
	if err != nil {
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &Error{
				Code:    -32603,
				Message: err.Error(),
			},
		}
	}

	return Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": fmt.Sprintf("Tool execution completed successfully.\n\nResult: %s", formatResult(result)),
				},
			},
		},
	}
}

func (s *Server) executeTool(toolName string, arguments map[string]interface{}) (interface{}, error) {
	// Extract path argument
	path, ok := arguments["path"].(string)
	if !ok {
		return nil, fmt.Errorf("missing required argument: path")
	}

	// Ensure path is absolute
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("invalid path: %w", err)
	}

	// Check if path exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("path does not exist: %s", absPath)
	}

	// Execute appropriate tool
	switch toolName {
	case "analyzeRepo":
		if s.RunAnalyzeRepo == nil {
			return nil, fmt.Errorf("analyzeRepo tool not implemented")
		}
		return s.RunAnalyzeRepo(absPath)

	case "scanRepoSBOM":
		if s.RunScanRepoSBOM == nil {
			return nil, fmt.Errorf("scanRepoSBOM tool not implemented")
		}
		return s.RunScanRepoSBOM(absPath)

	case "vulnCheck":
		if s.RunVulnCheck == nil {
			return nil, fmt.Errorf("vulnCheck tool not implemented")
		}
		return s.RunVulnCheck(absPath)

	case "secretScan":
		if s.RunSecretScan == nil {
			return nil, fmt.Errorf("secretScan tool not implemented")
		}
		engine := "auto"
		if engineArg, ok := arguments["engine"].(string); ok {
			engine = engineArg
		}
		return s.RunSecretScan(absPath, engine)

	default:
		return nil, fmt.Errorf("unknown tool: %s", toolName)
	}
}

func (s *Server) handleResourcesList(req Request) Response {
	// List available resources (stored analysis results)
	resources := s.listStoredResources()

	return Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"resources": resources,
		},
	}
}

func (s *Server) handleResourcesRead(req Request) Response {
	// Parse resource read parameters
	var params map[string]interface{}
	if req.Params != nil {
		if paramsMap, ok := req.Params.(map[string]interface{}); ok {
			params = paramsMap
		}
	}

	if params == nil {
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &Error{
				Code:    -32602,
				Message: "Invalid params",
			},
		}
	}

	uri, ok := params["uri"].(string)
	if !ok {
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &Error{
				Code:    -32602,
				Message: "Missing uri parameter",
			},
		}
	}

	// Read resource content
	content, err := s.readResource(uri)
	if err != nil {
		return Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &Error{
				Code:    -32603,
				Message: err.Error(),
			},
		}
	}

	return Response{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"contents": []ResourceContents{content},
		},
	}
}

func (s *Server) listStoredResources() []Resource {
	var resources []Resource

	// Look for stored analysis results in gothreatscope_store
	storeDir := "gothreatscope_store"
	if _, err := os.Stat(storeDir); os.IsNotExist(err) {
		return resources
	}

	// Walk through project directories
	filepath.Walk(storeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Look for latest analysis results
		if info.IsDir() && info.Name() == "latest" {
			projectDir := filepath.Dir(path)
			projectID := filepath.Base(projectDir)

			// Check for various analysis result files
			resultFiles := []string{"sbom.json", "vuln.json", "secrets.json", "bundle.json", "metrics.json"}
			for _, filename := range resultFiles {
				resultPath := filepath.Join(path, filename)
				if _, err := os.Stat(resultPath); err == nil {
					uri := "file://" + resultPath
					resources = append(resources, Resource{
						URI:         uri,
						Name:        fmt.Sprintf("%s - %s", projectID, strings.TrimSuffix(filename, ".json")),
						Description: fmt.Sprintf("Analysis result: %s for project %s", strings.TrimSuffix(filename, ".json"), projectID),
						MimeType:    "application/json",
					})
				}
			}
		}

		return nil
	})

	return resources
}

func (s *Server) readResource(uri string) (ResourceContents, error) {
	// Handle file:// URIs
	if strings.HasPrefix(uri, "file://") {
		filePath := strings.TrimPrefix(uri, "file://")
		
		// Security check: ensure the file is within gothreatscope_store
		absPath, err := filepath.Abs(filePath)
		if err != nil {
			return ResourceContents{}, fmt.Errorf("invalid file path: %w", err)
		}

		storeDir, err := filepath.Abs("gothreatscope_store")
		if err != nil {
			return ResourceContents{}, fmt.Errorf("invalid store directory: %w", err)
		}

		if !strings.HasPrefix(absPath, storeDir) {
			return ResourceContents{}, fmt.Errorf("access denied: file outside store directory")
		}

		// Read file content
		content, err := os.ReadFile(filePath)
		if err != nil {
			return ResourceContents{}, fmt.Errorf("failed to read file: %w", err)
		}

		// Determine MIME type based on file extension
		mimeType := "application/json"
		if strings.HasSuffix(filePath, ".json") {
			mimeType = "application/json"
		}

		return ResourceContents{
			URI:      uri,
			MimeType: mimeType,
			Text:     string(content),
		}, nil
	}

	return ResourceContents{}, fmt.Errorf("unsupported URI scheme")
}

func formatResult(result interface{}) string {
	// Convert result to JSON for display
	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Sprintf("%+v", result)
	}
	return string(jsonBytes)
}
