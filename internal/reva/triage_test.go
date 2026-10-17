package reva

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func stringArrayFixture(t *testing.T, start int, complete bool, hits ...map[string]any) string {
	t.Helper()
	parts := make([]any, 0, len(hits)+1)
	parts = append(parts, map[string]any{"regexPattern": webStringPattern, "startIndex": start, "actualCount": len(hits), "nextStartIndex": start + len(hits), "searchComplete": complete})
	for _, h := range hits {
		parts = append(parts, h)
	}
	b, err := json.Marshal(parts)
	if err != nil {
		t.Fatal(err)
	}
	return toolFixture(t, string(b))
}
func stringHit(addr, content string, refs ...map[string]string) map[string]any {
	return map[string]any{"address": addr, "content": content, "referenceCount": len(refs), "referencingFunctions": refs}
}

func TestStringTriageCorrelatesActualGhidraReferencesAcrossPages(t *testing.T) {
	c := rpcFixture(t, `{"tools":[{"name":"get-strings"}]}`,
		stringArrayFixture(t, 0, false,
			stringHit("0x00022000", "HTTP/1.1", map[string]string{"name": "FUN_000130b0", "address": "0x000130b0"}),
			stringHit("0x00022020", "Content-Type", map[string]string{"name": "FUN_000130b0", "address": "0x000130b0"}, map[string]string{"name": "FUN_0001460c", "address": "0x0001460c"})),
		stringArrayFixture(t, 2, true, stringHit("0x00022040", "/cgi-bin", map[string]string{"name": "FUN_0001460c", "address": "0x0001460c"})))
	result, err := scanWebStrings(c, overviewFixture())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Complete || result.Truncated || result.MatchCount != 3 || result.PageCount != 2 {
		t.Fatalf("bad completeness/count: %+v", result)
	}
	if len(result.ReferencingFunctions) != 2 || result.ReferencingFunctions[0].Name != "FUN_000130b0" || result.ReferencingFunctions[0].StringCount != 2 || result.ReferencingFunctions[1].StringCount != 2 {
		t.Fatalf("unexpected candidates: %+v", result.ReferencingFunctions)
	}
	if result.Overview.GhidraSHA256 != strings.Repeat("a", 64) || !result.Overview.IdentityVerified {
		t.Fatal("identity lost")
	}
	if len(result.Matches) != 3 {
		t.Fatal("string evidence lost")
	}
}

func TestStringTriageAtCapIsExplicitlyIncomplete(t *testing.T) {
	var fixtures []string
	fixtures = append(fixtures, `{"tools":[{"name":"get-strings"}]}`)
	for page := 0; page < 4; page++ {
		var hits []map[string]any
		for i := 0; i < 32; i++ {
			hits = append(hits, stringHit(fmt.Sprintf("0x%08x", (page*32+i+1)*4), "http"))
		}
		fixtures = append(fixtures, stringArrayFixture(t, page*32, false, hits...))
	}
	c := rpcFixture(t, fixtures...)
	result, err := scanWebStrings(c, overviewFixture())
	if err != nil {
		t.Fatal(err)
	}
	if result.Complete || !result.Truncated || result.MatchCount != 128 || result.PageCount != 4 {
		t.Fatalf("overstated completeness: %+v", result)
	}
}

func TestStringTriageRejectsMalformedPages(t *testing.T) {
	cases := []struct {
		name string
		page string
	}{
		{"no progress", stringArrayFixture(t, 0, false)},
		{"wrong cursor", stringArrayFixture(t, 8, true, stringHit("0x1", "http"))},
		{"no reference count", toolFixture(t, `[{"regexPattern":"`+webStringPattern+`","startIndex":0,"actualCount":1,"nextStartIndex":1,"searchComplete":true},{"address":"0x1","content":"http"}]`)},
		{"duplicate strings", stringArrayFixture(t, 0, true, stringHit("0x1", "http"), stringHit("0x1", "auth"))},
		{"unbounded references", stringArrayFixture(t, 0, true, map[string]any{"address": "0x1", "content": "auth", "referenceCount": 3, "referencingFunctions": []any{}})},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			c := rpcFixture(t, `{"tools":[{"name":"get-strings"}]}`, tt.page)
			if _, err := scanWebStrings(c, overviewFixture()); err == nil {
				t.Fatal("accepted invalid ReVa string response")
			}
		})
	}
}
func TestStringTriageRejectsUnverifiedOrUnavailableTool(t *testing.T) {
	ov := overviewFixture()
	ov.IdentityVerified = false
	if _, err := scanWebStrings(nil, ov); err == nil {
		t.Fatal("accepted unverified program")
	}
	c := rpcFixture(t, `{"tools":[]}`)
	if _, err := scanWebStrings(c, overviewFixture()); err == nil {
		t.Fatal("allowed absent tool")
	}
}
func TestRevaArrayMCPResponseAndErrors(t *testing.T) {
	c := rpcFixture(t, toolFixture(t, `[{"startIndex":0}]`))
	arr, err := c.toolArray("get-strings", map[string]any{"programPath": "/uhttpd"})
	if err != nil || len(arr) != 1 {
		t.Fatalf("array MCP support: %d %v", len(arr), err)
	}
	var out bytes.Buffer
	c2 := newClient(strings.NewReader(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"not available"}],"isError":true}}`+"\n"), &out)
	if _, err := c2.toolArray("get-strings", map[string]any{}); err == nil {
		t.Fatal("ignored MCP tool failure")
	}
}
