package reva

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestMCPRequestUsesSingleNamedToolAndChecksID(t *testing.T) {
	reply := `{"jsonrpc":"2.0","method":"notifications/message","params":{}}` + "\n" + `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"{\"sha256\":\"abc\"}"}],"isError":false}}` + "\n"
	var requests bytes.Buffer
	c := newClient(strings.NewReader(reply), &requests)
	obj, err := c.tool("get-program-overview", map[string]any{"programPath": "/uhttpd"})
	if err != nil {
		t.Fatal(err)
	}
	if getString(obj, "sha256") != "abc" {
		t.Fatalf("unexpected result: %v", obj)
	}
	var request map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(requests.Bytes()), &request); err != nil {
		t.Fatal(err)
	}
	if request["method"] != "tools/call" {
		t.Fatalf("unexpected operation %v", request)
	}
}
func TestMCPRejectsMismatchedID(t *testing.T) {
	var buf bytes.Buffer
	c := newClient(strings.NewReader(`{"jsonrpc":"2.0","id":900,"result":{}}`+"\n"), &buf)
	if _, err := c.request("tools/list", map[string]any{}); err == nil {
		t.Fatal("accepted wrong request ID")
	}
}
func TestMCPRejectsErrorResults(t *testing.T) {
	var buf bytes.Buffer
	c := newClient(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"not allowed"}],"isError":true}}`+"\n"), &buf)
	if _, err := c.tool("import-file", map[string]any{}); err == nil {
		t.Fatal("accepted error result")
	}
}
