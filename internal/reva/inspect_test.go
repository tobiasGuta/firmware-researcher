package reva

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func rpcFixture(t *testing.T, objects ...string) *client {
	t.Helper()
	var responses strings.Builder
	for i, obj := range objects {
		fmt.Fprintf(&responses, "{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":%s}\n", i+1, obj)
	}
	return newClient(strings.NewReader(responses.String()), &bytes.Buffer{})
}

func toolFixture(t *testing.T, data string) string {
	t.Helper()
	b, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"content":[{"type":"text","text":%s}],"isError":false}`, b)
}

func overviewFixture() Overview {
	return Overview{SchemaVersion: 1, ReVaProgramPath: "/uhttpd", GhidraSHA256: strings.Repeat("a", 64), IdentityVerified: true}
}

func indexFixture(t *testing.T, count, total int) string {
	t.Helper()
	rows := make([]map[string]any, count)
	for i := range rows {
		rows[i] = map[string]any{"name": fmt.Sprintf("FUN_%04d", i), "address": fmt.Sprintf("0x%08x", i*4+65536)}
	}
	b, err := json.Marshal(map[string]any{"functions": rows, "actualCount": count, "totalCount": total, "nextStartIndex": count, "startIndex": 0})
	if err != nil {
		t.Fatal(err)
	}
	return toolFixture(t, string(b))
}

func TestInspectFunctionIndexBoundedAndNoAnalysisWithoutSelection(t *testing.T) {
	c := rpcFixture(t,
		`{"tools":[{"name":"get-functions"}]}`,
		indexFixture(t, 2, 431))
	result, err := inspectFunction(c, overviewFixture(), "")
	if err != nil {
		t.Fatal(err)
	}
	if result.RequestedFunction != "" || len(result.FunctionCFG) != 0 || len(result.PCode) != 0 {
		t.Fatalf("unwanted function inspection: %+v", result)
	}
	var idx struct {
		ActualCount int `json:"actualCount"`
		TotalCount  int `json:"totalCount"`
	}
	if err := json.Unmarshal(result.FunctionIndex, &idx); err != nil || idx.ActualCount != 2 || idx.TotalCount != 431 {
		t.Fatalf("bad function page: %+v, %v", idx, err)
	}
}

func TestInspectSelectedFunctionPreservesTruncationAndIdentity(t *testing.T) {
	c := rpcFixture(t,
		`{"tools":[{"name":"get-functions"},{"name":"get-function-cfg"},{"name":"get-pcode"}]}`,
		indexFixture(t, 1, 431),
		toolFixture(t, `{"programPath":"/uhttpd","function":"main","functionAddress":"0x00010500","truncated":true,"blocks":[]}`),
		toolFixture(t, `{"programPath":"/uhttpd","scope":"basic-block","resolvedAddress":"0x00010500","truncated":true,"instructionCount":32}`))
	result, err := inspectFunction(c, overviewFixture(), "main")
	if err != nil {
		t.Fatal(err)
	}
	if result.RequestedFunction != "main" || !result.Overview.IdentityVerified {
		t.Fatalf("bad evidence: %+v", result)
	}
	for _, raw := range []json.RawMessage{result.FunctionCFG, result.PCode} {
		var obj struct {
			Truncated bool `json:"truncated"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil || !obj.Truncated {
			t.Fatalf("truncation lost: %s", raw)
		}
	}
}

func TestInspectRejectsMismatchedProgramAndMissingTruncation(t *testing.T) {
	for _, cfg := range []string{
		`{"programPath":"/other","function":"main","functionAddress":"0x00010500","truncated":false}`,
		`{"programPath":"/uhttpd","function":"main","functionAddress":"0x00010500"}`,
	} {
		c := rpcFixture(t, `{"tools":[{"name":"get-functions"},{"name":"get-function-cfg"},{"name":"get-pcode"}]}`,
			indexFixture(t, 1, 431), toolFixture(t, cfg),
			toolFixture(t, `{"programPath":"/uhttpd","scope":"basic-block","resolvedAddress":"0x00010500","truncated":false}`))
		if _, err := inspectFunction(c, overviewFixture(), "main"); err == nil {
			t.Fatalf("accepted invalid CFG: %s", cfg)
		}
	}
}

func TestInspectRejectsImpossiblePagination(t *testing.T) {
	c := rpcFixture(t, `{"tools":[{"name":"get-functions"}]}`,
		toolFixture(t, `{"functions":[{"name":"a","address":"0x100"}],"actualCount":99,"totalCount":431}`))
	if _, err := inspectFunction(c, overviewFixture(), ""); err == nil {
		t.Fatal("accepted inconsistent index")
	}
}
