package reva

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const maxMCPMessage = 8 << 20

type Overview struct {
	SchemaVersion    int             `json:"schema_version"`
	Target           Target          `json:"target"`
	ReVaProgramPath  string          `json:"reva_program_path"`
	ReVaOverview     json.RawMessage `json:"reva_overview"`
	GhidraSHA256     string          `json:"ghidra_sha256"`
	IdentityVerified bool            `json:"identity_verified"`
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  any             `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}
type mcpResult struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	IsError bool `json:"isError"`
}

type client struct {
	encoder *json.Encoder
	scanner *bufio.Scanner
	nextID  int
}

func newClient(r io.Reader, w io.Writer) *client {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 65536), maxMCPMessage)
	return &client{encoder: json.NewEncoder(w), scanner: sc}
}
func (c *client) request(method string, params any) (json.RawMessage, error) {
	c.nextID++
	id := c.nextID
	if err := c.encoder.Encode(rpcMessage{JSONRPC: "2.0", ID: json.RawMessage(fmt.Sprintf("%d", id)), Method: method, Params: params}); err != nil {
		return nil, err
	}
	for c.scanner.Scan() {
		var msg rpcMessage
		if err := json.Unmarshal(c.scanner.Bytes(), &msg); err != nil {
			return nil, fmt.Errorf("invalid MCP response: %w", err)
		}
		if len(msg.ID) == 0 {
			continue
		} // Ignore unsolicited notifications, never call tools on their behalf.
		if string(msg.ID) != fmt.Sprintf("%d", id) {
			return nil, errors.New("unexpected MCP response id")
		}
		if msg.Error != nil {
			return nil, fmt.Errorf("ReVa MCP error %d: %s", msg.Error.Code, msg.Error.Message)
		}
		if len(msg.Result) == 0 {
			return nil, errors.New("empty MCP result")
		}
		return msg.Result, nil
	}
	if err := c.scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}
func (c *client) notify(method string) error {
	return c.encoder.Encode(rpcMessage{JSONRPC: "2.0", Method: method})
}

// toolPayload accepts ReVa tool results as either objects or arrays. ReVa's
// get-strings returns [pagination, ...items] instead of an object.
func (c *client) toolPayload(name string, args any) (json.RawMessage, error) {
	raw, err := c.request("tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return nil, err
	}
	var m mcpResult
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.IsError {
		return nil, fmt.Errorf("ReVa rejected %s: %s", name, limitedToolText(m))
	}
	if len(m.Content) != 1 || m.Content[0].Type != "text" {
		return nil, fmt.Errorf("unexpected %s content", name)
	}
	payload := json.RawMessage(m.Content[0].Text)
	if !json.Valid(payload) {
		return nil, fmt.Errorf("invalid JSON in %s", name)
	}
	return payload, nil
}
func (c *client) tool(name string, args any) (map[string]json.RawMessage, error) {
	raw, err := c.toolPayload(name, args)
	if err != nil {
		return nil, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, fmt.Errorf("expected JSON object in %s", name)
	}
	return obj, nil
}
func (c *client) toolArray(name string, args any) ([]json.RawMessage, error) {
	raw, err := c.toolPayload(name, args)
	if err != nil {
		return nil, err
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil || items == nil {
		return nil, fmt.Errorf("expected JSON array in %s", name)
	}
	return items, nil
}
func limitedToolText(m mcpResult) string {
	var b strings.Builder
	for _, x := range m.Content {
		if b.Len() >= 512 {
			break
		}
		s := x.Text
		if len(s) > 512-b.Len() {
			s = s[:512-b.Len()]
		}
		b.WriteString(s)
	}
	return b.String()
}
func getString(obj map[string]json.RawMessage, key string) string {
	var value string
	_ = json.Unmarshal(obj[key], &value)
	return value
}

// Query preserves the original two-tool overview workflow.
func Query(ctx context.Context, target Target, launcher string, timeout time.Duration) (Overview, error) {
	var overview Overview
	err := withSession(ctx, target, launcher, timeout, func(_ *client, result Overview) error {
		overview = result
		return nil
	})
	return overview, err
}

// withSession starts a disposable Ghidra project and verifies identity before
// authorizing a narrowly scoped read-only operation. The caller never receives
// a live client after this function returns.
func withSession(ctx context.Context, target Target, launcher string, timeout time.Duration, visit func(*client, Overview) error) error {
	if timeout < time.Second || timeout > 15*time.Minute {
		return errors.New("timeout must be 1s to 15m")
	}
	if launcher == "" {
		launcher = "mcp-reva"
	}
	bin, err := exec.LookPath(launcher)
	if err != nil {
		return fmt.Errorf("mcp-reva executable unavailable: %w", err)
	}
	if _, ok := os.LookupEnv("GHIDRA_INSTALL_DIR"); !ok {
		return errors.New("GHIDRA_INSTALL_DIR must point to the isolated Ghidra/ReVa installation")
	}
	projectDir, err := os.MkdirTemp("", "firmware-researcher-reva-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(projectDir)
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, bin)
	cmd.Dir = projectDir
	cmd.Env = append(os.Environ(), "PYTHONUNBUFFERED=1")
	in, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr cappedText
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() {
		_ = in.Close()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}()
	c := newClient(out, in)
	initialize, err := c.request("initialize", map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "firmware-researcher", "version": "0.1.0"}})
	if err != nil {
		return fmt.Errorf("initialize ReVa: %w: %s", err, stderr.String())
	}
	var info struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if err := json.Unmarshal(initialize, &info); err != nil || info.ProtocolVersion == "" {
		return errors.New("MCP protocol negotiation failed")
	}
	if err := c.notify("notifications/initialized"); err != nil {
		return err
	}
	list, err := c.request("tools/list", map[string]any{})
	if err != nil {
		return err
	}
	var catalog struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(list, &catalog); err != nil {
		return err
	}
	available := map[string]bool{}
	for _, tool := range catalog.Tools {
		available[tool.Name] = true
	}
	if !available["import-file"] || !available["get-program-overview"] {
		return errors.New("required ReVa tools absent; verify development extension is installed")
	}
	imported, err := c.tool("import-file", map[string]any{"path": target.LocalPath, "destinationFolder": "/", "analyzeAfterImport": true, "enableVersionControl": false})
	if err != nil {
		return err
	}
	var imp struct {
		Success  bool     `json:"success"`
		Programs []string `json:"importedPrograms"`
	}
	raw, _ := json.Marshal(imported)
	if err := json.Unmarshal(raw, &imp); err != nil || !imp.Success || len(imp.Programs) != 1 || imp.Programs[0] == "" {
		return errors.New("ReVa import failed or returned ambiguous program paths")
	}
	result, err := c.tool("get-program-overview", map[string]any{"programPath": imp.Programs[0], "maxBlocks": 32, "maxEntryPoints": 32})
	if err != nil {
		return err
	}
	importedSHA := getString(result, "sha256")
	if importedSHA == "" || !strings.EqualFold(importedSHA, target.SHA256) {
		return fmt.Errorf("Ghidra import identity mismatch: expected %s, received %s", target.SHA256, importedSHA)
	}
	if returned := getString(result, "programPath"); returned != "" && returned != imp.Programs[0] {
		return errors.New("ReVa overview belongs to a different program")
	}
	// Ensure source bytes remain unchanged after the external analysis tool ran.
	afterHash, afterSize, err := digest(target.LocalPath, ingestMaxFileBytes)
	if err != nil {
		return err
	}
	if afterHash != target.SHA256 || afterSize != target.Size {
		return errors.New("firmware component changed during ReVa analysis")
	}
	overviewJSON, err := json.Marshal(result)
	if err != nil {
		return err
	}
	verified := Overview{SchemaVersion: 1, Target: target, ReVaProgramPath: imp.Programs[0], ReVaOverview: overviewJSON, GhidraSHA256: importedSHA, IdentityVerified: true}
	if err := visit(c, verified); err != nil {
		return err
	}
	// Verify the source again after optional function analysis too.
	endHash, endSize, err := digest(target.LocalPath, ingestMaxFileBytes)
	if err != nil {
		return err
	}
	if endHash != target.SHA256 || endSize != target.Size {
		return errors.New("firmware component changed during ReVa operation")
	}
	return nil
}

// Standalone cap avoids leaking unlimited stderr from a local tool.
type cappedText struct{ bytes.Buffer }

func (b *cappedText) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len() < 8192 {
		left := 8192 - b.Len()
		if len(p) > left {
			p = p[:left]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}

const ingestMaxFileBytes int64 = 512 << 20

func WriteNew(filename string, result Overview) error {
	return writeEvidenceNew(filename, result)
}

func WriteInspectionNew(filename string, result Inspection) error {
	return writeEvidenceNew(filename, result)
}
func WriteCallEvidenceNew(filename string, result CallEvidence) error {
	return writeEvidenceNew(filename, result)
}
func WriteSecurityTriageNew(filename string, result SecurityTriage) error {
	return writeEvidenceNew(filename, result)
}
func WriteTriageNew(filename string, result StringTriage) error {
	return writeEvidenceNew(filename, result)
}

func writeEvidenceNew(filename string, result any) error {
	if filename == "" {
		return errors.New("output filename required")
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(filename)
	tmp, err := os.CreateTemp(dir, ".firmware-reva-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Hard-link publication is atomic, exclusive, and never replaces evidence.
	return os.Link(tmp.Name(), filename)
}
