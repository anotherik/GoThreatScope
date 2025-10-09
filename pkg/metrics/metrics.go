package metrics

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

type MetricEvent struct {
	RunID       string            `json:"run_id"`
	StartedAt   time.Time         `json:"started_at"`
	DurationSec float64           `json:"duration_sec"`
	Modules     map[string]Module `json:"modules"`
	Env         EnvInfo           `json:"env"`
	UserConsent bool              `json:"user_consent"`
}

type Module struct {
	Status     string `json:"status"`
	DurationMs int64  `json:"duration_ms"`
	Findings   int    `json:"findings"`
	Note       string `json:"note,omitempty"`
}

type EnvInfo struct {
	Version   string `json:"version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	GoVersion string `json:"go_version"`
}

func inMCP() bool { return os.Getenv("GTS_MCP_MODE") == "1" }
func quiet() bool { return inMCP() || os.Getenv("GTS_QUIET") == "1" }

// Destination can be changed by env var, but never disabled.
func defaultRemoteURL() string {
	if u := os.Getenv("GOTHREATSCOPE_METRICS_URL"); u != "" {
		return u
	}
	// Default collector for demo/testing
	return "https://eo6ahqkjxm792aa.m.pipedream.net"
}

// NOTE: This writes under gothreatscope_out/<run_id>/metrics.json.
// Your MCP resources read from gothreatscope_store/<project_id>/latest/metrics.json.
// If you still use WriteLocal, consider aligning paths with the store layout.
func WriteLocal(runID string, data MetricEvent) error {
	dir := filepath.Join("gothreatscope_out", runID)
	_ = os.MkdirAll(dir, 0o755)
	f := filepath.Join(dir, "metrics.json")
	b, _ := json.MarshalIndent(data, "", "  ")
	return os.WriteFile(f, b, 0o644)
}

// SendRemote posts metrics; use SendRemoteAsync to avoid blocking tool calls.
func SendRemote(data MetricEvent) {
	url := defaultRemoteURL()
	b, _ := json.Marshal(data)

	req, _ := http.NewRequest("POST", url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "GoThreatScope/metrics")

	client := &http.Client{Timeout: 10 * time.Second}

	if !quiet() {
		fmt.Fprintf(os.Stderr, "[GoThreatScope metrics] sending to %s\n", url)
	}
	resp, err := client.Do(req)
	if err != nil {
		if !quiet() {
			fmt.Fprintf(os.Stderr, "[GoThreatScope metrics] send error: %v\n", err)
		}
		return
	}
	defer resp.Body.Close()
	if !quiet() {
		fmt.Fprintf(os.Stderr, "[GoThreatScope metrics] POST %s\n", resp.Status)
	}
}

// Fire-and-forget wrapper (recommended from MCP tool paths)
func SendRemoteAsync(data MetricEvent) {
	go SendRemote(data)
}

func CollectEnv(version string) EnvInfo {
	return EnvInfo{
		Version:   version,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
	}
}
