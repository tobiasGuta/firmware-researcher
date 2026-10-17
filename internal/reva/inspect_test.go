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

func pagedIndexFixture(t *testing.T, start, count, total int) string {
	t.Helper()
	rows := make([]map[string]any, count)
	for i := range rows {
		rows[i] = map[string]any{
			"name":        fmt.Sprintf("function_%03d", start+i),
			"address":     fmt.Sprintf("0x%08x", 0x12000+4*(start+i)),
			"sizeInBytes": 36,
		}
	}
	b, err := json.Marshal(map[string]any{
		"functions": rows, "actualCount": count, "totalCount": total,
		"startIndex": start, "nextStartIndex": start + count,
	})
	if err != nil {
		t.Fatal(err)
	}
	return toolFixture(t, string(b))
}

func TestFullFunctionIndexCollectsMultiplePages(t *testing.T) {
	c := rpcFixture(t,
		pagedIndexFixture(t, 0, 64, 130),
		pagedIndexFixture(t, 64, 64, 130),
		pagedIndexFixture(t, 128, 2, 130),
	)
	result, err := readFunctionIndex(c, "/uhttpd", true)
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		Functions      []struct{ Name string } `json:"functions"`
		ActualCount    int                     `json:"actualCount"`
		TotalCount     int                     `json:"totalCount"`
		NextStartIndex int                     `json:"nextStartIndex"`
		PageCount      int                     `json:"pageCount"`
		Complete       bool                    `json:"complete"`
		Truncated      bool                    `json:"truncated"`
	}
	if err := json.Unmarshal(result, &index); err != nil {
		t.Fatal(err)
	}
	if index.ActualCount != 130 || len(index.Functions) != 130 || index.TotalCount != 130 ||
		index.NextStartIndex != 130 || index.PageCount != 3 || !index.Complete || index.Truncated ||
		index.Functions[129].Name != "function_129" {
		t.Fatalf("incorrect assembled pages: %+v", index)
	}
}

func TestFullIndexStopsAt512WithExplicitTruncation(t *testing.T) {
	responses := make([]string, 0, 8)
	for i := 0; i < 8; i++ {
		responses = append(responses, pagedIndexFixture(t, 64*i, 64, 700))
	}
	c := rpcFixture(t, responses...)
	result, err := readFunctionIndex(c, "/uhttpd", true)
	if err != nil {
		t.Fatal(err)
	}
	var index struct {
		ActualCount    int  `json:"actualCount"`
		NextStartIndex int  `json:"nextStartIndex"`
		PageCount      int  `json:"pageCount"`
		Complete       bool `json:"complete"`
		Truncated      bool `json:"truncated"`
	}
	if err := json.Unmarshal(result, &index); err != nil {
		t.Fatal(err)
	}
	if index.ActualCount != 512 || index.NextStartIndex != 512 || index.PageCount != 8 ||
		index.Complete || !index.Truncated {
		t.Fatalf("bad capped pagination: %+v", index)
	}
}

func TestFullIndexRejectsInconsistentPages(t *testing.T) {
	tests := []struct {
		name   string
		second string
	}{
		{"total changed", pagedIndexFixture(t, 64, 1, 131)},
		{"wrong offset", pagedIndexFixture(t, 63, 1, 130)},
		{"empty unfinished page", pagedIndexFixture(t, 64, 0, 130)},
		{"duplicate address", pagedIndexFixture(t, 0, 1, 130)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := rpcFixture(t, pagedIndexFixture(t, 0, 64, 130), tt.second)
			if _, err := readFunctionIndex(c, "/uhttpd", true); err == nil {
				t.Fatal("accepted inconsistent function index")
			}
		})
	}
}

func selectedBlockCFGFixture(t *testing.T, blocks string) string {
	t.Helper()
	return toolFixture(t, `{"programPath":"/uhttpd","function":"FUN_00014e8c","functionAddress":"0x00014e8c","truncated":false,"blocks":`+blocks+`}`)
}

func TestInspectSelectedNonEntryBlock(t *testing.T) {
	c := rpcFixture(t,
		`{"tools":[{"name":"get-functions"},{"name":"get-function-cfg"},{"name":"get-pcode"}]}`,
		indexFixture(t, 1, 319),
		selectedBlockCFGFixture(t, `[{"minAddress":"0x00014e8c","maxAddress":"0x00014eab"},{"minAddress":"0x00014f00","maxAddress":"0x00014f23"}]`),
		toolFixture(t, `{"programPath":"/uhttpd","scope":"basic-block","resolvedAddress":"0x00014f18","scopeStart":"0x00014f00","scopeEnd":"0x00014f23","truncated":false,"instructions":[]}`),
	)
	got, err := inspectFunctionPagedAt(c, overviewFixture(), "FUN_00014e8c", false, "0x14f18")
	if err != nil {
		t.Fatal(err)
	}
	if got.PcodeRequestedAddress != "0x00014f18" || !got.Overview.IdentityVerified || len(got.FunctionCFG) == 0 || len(got.PCode) == 0 {
		t.Fatalf("wrong bounded block evidence: %+v", got)
	}
}

func TestInspectSelectedBlockRejectsBadCFGOrPCode(t *testing.T) {
	tests := []struct {
		name, blocks, pcode string
	}{
		{"no matching CFG block", `[{"minAddress":"0x00014e8c","maxAddress":"0x00014eab"}]`, `{"programPath":"/uhttpd","scope":"basic-block","resolvedAddress":"0x00014f18","scopeStart":"0x00014f00","scopeEnd":"0x00014f23","truncated":false}`},
		{"malformed CFG bounds", `[{"minAddress":"wrong","maxAddress":"0x00014f23"}]`, `{"programPath":"/uhttpd","scope":"basic-block","resolvedAddress":"0x00014f18","scopeStart":"0x00014f00","scopeEnd":"0x00014f23","truncated":false}`},
		{"wrong P-code block", `[{"minAddress":"0x00014f00","maxAddress":"0x00014f23"}]`, `{"programPath":"/uhttpd","scope":"basic-block","resolvedAddress":"0x00014f18","scopeStart":"0x00014f04","scopeEnd":"0x00014f23","truncated":false}`},
		{"wrong P-code address", `[{"minAddress":"0x00014f00","maxAddress":"0x00014f23"}]`, `{"programPath":"/uhttpd","scope":"basic-block","resolvedAddress":"0x00014f14","scopeStart":"0x00014f00","scopeEnd":"0x00014f23","truncated":false}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := rpcFixture(t,
				`{"tools":[{"name":"get-functions"},{"name":"get-function-cfg"},{"name":"get-pcode"}]}`,
				indexFixture(t, 1, 319),
				selectedBlockCFGFixture(t, tc.blocks),
				toolFixture(t, tc.pcode),
			)
			if _, err := inspectFunctionPagedAt(c, overviewFixture(), "FUN_00014e8c", false, "0x14f18"); err == nil {
				t.Fatal("accepted inconsistent block evidence")
			}
		})
	}
}

func TestPcodeAddressValidation(t *testing.T) {
	for _, raw := range []string{"", "14f18", "0xZZ", "0x1\n", "0x123456789123456789", "0x"} {
		if _, err := parsePcodeAddress(raw); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	if n, err := parsePcodeAddress("0x00014f18"); err != nil || n != 0x14f18 {
		t.Fatalf("bad accepted address %x %v", n, err)
	}
}
