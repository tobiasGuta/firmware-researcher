package reva

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func securityCFG(t *testing.T, name, address, callsite, callTarget string, truncated bool) string {
	t.Helper()
	blocks := []any{map[string]any{"start": address, "minAddress": address, "maxAddress": address, "calls": []any{}}}
	if callsite != "" {
		blocks = append(blocks, map[string]any{
			"start": callsite, "minAddress": callsite, "maxAddress": callsite,
			"calls": []any{map[string]any{"fromInstruction": callsite, "to": callTarget, "flowType": "UNCONDITIONAL_CALL"}},
		})
	}
	return securityToolFixture(t, map[string]any{
		"programPath": "/uhttpd", "function": name, "functionAddress": address,
		"blockCount": len(blocks), "returnedBlockCount": len(blocks), "blocks": blocks, "truncated": truncated,
	})
}
func securityPcode(t *testing.T, address string, truncated bool) string {
	t.Helper()
	return securityToolFixture(t, map[string]any{
		"programPath": "/uhttpd", "scope": "basic-block", "resolvedAddress": address,
		"scopeStart": address, "scopeEnd": address, "truncated": truncated, "instructions": []any{},
	})
}
func securityToolFixture(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return toolFixture(t, string(b))
}

func twoCandidateSecurityFixtures(t *testing.T, badCFG, badPcode, badCall bool) []string {
	t.Helper()
	a, b := "0x00014e8c", "0x000159a0"
	aName, bName := "FUN_00014e8c", "FUN_000159a0"
	scan := stringArrayFixture(t, 0, true,
		stringHit("0x00030000", "http-auth-user", map[string]string{"name": aName, "address": a}),
		stringHit("0x00030010", "request", map[string]string{"name": aName, "address": a}),
		stringHit("0x00030020", "Authorization Required", map[string]string{"name": bName, "address": b}),
	)
	cfgA := securityCFG(t, aName, a, "0x00014f18", b, false)
	if badCFG {
		cfgA = securityCFG(t, "OTHER", a, "0x00014f18", b, false)
	}
	pcodeA := securityPcode(t, a, false)
	if badPcode {
		pcodeA = securityPcode(t, b, false)
	}
	callTarget := b
	if badCall {
		callTarget = "0x00014a14"
	}
	boundaries := callFixture(t, "0x00014f18", map[string]any{
		"calls": []any{map[string]any{
			"opcode": "CALL", "targetKind": "direct_internal", "mappingStatus": "ambiguous_prototype_or_storage",
			"argumentsTruncated": false, "targetAddress": callTarget,
		}},
	})
	return []string{
		`{"tools":[{"name":"get-strings"}]}`, scan,
		cfgA, pcodeA,
		securityCFG(t, bName, b, "", "", false), securityPcode(t, b, true),
		`{"tools":[{"name":"inspect-call-boundary"}]}`, boundaries,
	}
}

func TestSecurityTriageCorrelatesStringsCallsAndKeepsAmbiguity(t *testing.T) {
	c := rpcFixture(t, twoCandidateSecurityFixtures(t, false, false, false)...)
	report, err := analyzeSecurityCandidates(c, overviewFixture())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Candidates) != 2 || len(report.CallBoundaries) != 1 {
		t.Fatalf("incomplete consolidated evidence: %+v", report.Coverage)
	}
	if report.Candidates[0].Address != "0x00014e8c" || report.Candidates[0].PriorityScore != 7 {
		t.Fatalf("bad ranking: %+v", report.Candidates[0])
	}
	if report.Candidates[1].PriorityScore != 5 || report.Candidates[1].PcodeTruncated != true {
		t.Fatal("lost ranking or P-code truncation")
	}
	edge := report.Candidates[0].Calls[0]
	if edge.Target != "0x000159a0" || !edge.StringReferencedTarget || edge.TargetName != "FUN_000159a0" {
		t.Fatalf("lost evidence link: %+v", edge)
	}
	if report.Coverage.CFGTruncatedFunctions != 0 || report.Coverage.PcodeTruncatedFunctions != 1 || report.Coverage.CallBoundariesOmitted != 0 {
		t.Fatalf("wrong coverage %+v", report.Coverage)
	}
	if report.Candidates[0].Status == "confirmed vulnerability" {
		t.Fatal("report overclaims vulnerability")
	}
	var raw struct {
		Calls []struct {
			MappingStatus string `json:"mappingStatus"`
		} `json:"calls"`
	}
	if err := json.Unmarshal(report.CallBoundaries[0], &raw); err != nil || raw.Calls[0].MappingStatus != "ambiguous_prototype_or_storage" {
		t.Fatal("lost decompiler uncertainty")
	}
	if report.Overview.GhidraSHA256 != strings.Repeat("a", 64) {
		t.Fatal("identity lost")
	}
}

func TestSecurityTriageRejectsUntrustedMismatches(t *testing.T) {
	for _, test := range []struct {
		name                      string
		badCFG, badPcode, badCall bool
	}{
		{"wrong CFG identity", true, false, false},
		{"wrong P-code identity", false, true, false},
		{"wrong call-boundary target", false, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := rpcFixture(t, twoCandidateSecurityFixtures(t, test.badCFG, test.badPcode, test.badCall)...)
			if _, err := analyzeSecurityCandidates(c, overviewFixture()); err == nil {
				t.Fatal("accepted contradictory evidence")
			}
		})
	}
	ov := overviewFixture()
	ov.IdentityVerified = false
	if _, err := analyzeSecurityCandidates(nil, ov); err == nil {
		t.Fatal("accepted unverified ELF")
	}
}

func TestSecurityRankingIsDeterministicAndBounded(t *testing.T) {
	scan := StringTriage{Matches: []json.RawMessage{}, ReferencingFunctions: []FunctionCandidate{}}
	for i := 0; i < 8; i++ {
		addr := fmt.Sprintf("0x%08x", 0x13000+4*i)
		straddr := fmt.Sprintf("0x%08x", 0x33000+4*i)
		content := "HTTP/1.1"
		if i == 6 {
			content = "Authorization Required"
		}
		raw, _ := json.Marshal(map[string]string{"address": straddr, "content": content})
		scan.Matches = append(scan.Matches, raw)
		scan.ReferencingFunctions = append(scan.ReferencingFunctions, FunctionCandidate{Name: fmt.Sprintf("FUN_%d", i), Address: addr, StringAddresses: []string{straddr}, StringCount: 1})
	}
	ranked, err := rankSecurityCandidates(scan)
	if err != nil {
		t.Fatal(err)
	}
	if len(ranked) != 8 || ranked[0].Name != "FUN_6" || ranked[1].Address != "0x00013000" {
		t.Fatalf("unexpected ranking %+v", ranked)
	}
	ranked = ranked[:maxSecurityCandidates]
	if len(ranked) != 4 {
		t.Fatal("candidate budget not enforced")
	}
	candidates := []SecurityCandidate{{Address: "0x00013000", PriorityScore: 5, Calls: []SecurityCall{
		{Instruction: "0x00013008", Target: "0x00015000"},
		{Instruction: "0x00013010", Target: "0x00014000", StringReferencedTarget: true},
	}}}
	sites, chosen, err := selectSecurityCalls(candidates)
	if err != nil {
		t.Fatal(err)
	}
	if len(chosen) != 2 || sites[0] != "0x00013010" {
		t.Fatalf("priority link not selected: %v", sites)
	}
}

func TestSecurityTriageExplicitlyTracksIncompleteCoverage(t *testing.T) {
	c := rpcFixture(t,
		`{"tools":[{"name":"get-strings"}]}`,
		stringArrayFixture(t, 0, true, stringHit("0x00033000", "HTTP/1.1", map[string]string{"name": "FUN_000130b0", "address": "0x000130b0"})),
		securityCFG(t, "FUN_000130b0", "0x000130b0", "", "", true),
		securityPcode(t, "0x000130b0", true),
	)
	result, err := analyzeSecurityCandidates(c, overviewFixture())
	if err != nil {
		t.Fatal(err)
	}
	cov := result.Coverage
	if cov.CFGTruncatedFunctions != 1 || cov.PcodeTruncatedFunctions != 1 || cov.CallBoundariesInspected != 0 || len(result.CallBoundaries) != 0 {
		t.Fatalf("lost limitations: %+v", cov)
	}
}

func TestSecurityCallBudgetAndTargetValidation(t *testing.T) {
	candidates := []SecurityCandidate{{Address: "0x00010000", PriorityScore: 2}}
	for i := 0; i < 8; i++ {
		candidates[0].Calls = append(candidates[0].Calls, SecurityCall{Instruction: fmt.Sprintf("0x%08x", 0x10100+i*4), Target: "0x00030000", StringReferencedTarget: i%2 == 0})
	}
	sites, choices, err := selectSecurityCalls(candidates)
	if err != nil || len(sites) != 4 || len(choices) != 8 {
		t.Fatalf("failed budget: %v %v", sites, err)
	}
	for _, site := range sites {
		var number uint64
		fmt.Sscanf(site, "0x%x", &number)
		if number%8 != 0 {
			t.Fatal("unrelated call prioritized over string-linked call")
		}
	}
	fixture := map[string]any{"callsite": sites[0], "caller": map[string]any{"address": "0x00010000"}, "calls": []any{map[string]string{"targetKind": "direct_internal", "targetAddress": "0x00030004"}}}
	raw, _ := json.Marshal(fixture)
	if err := verifySecurityBoundaries([]json.RawMessage{raw}, choices[:1]); err == nil {
		t.Fatal("accepted mismatch")
	}
}
