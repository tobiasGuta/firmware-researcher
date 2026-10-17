package reva

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Fixed work budgets. Nothing in an extracted binary or MCP response can
// authorize additional tools, candidates or follow-on calls.
const maxSecurityCandidates = 4
const maxSecurityCalls = 4

type SecurityTriage struct {
	SchemaVersion  int                 `json:"schema_version"`
	Overview       Overview            `json:"verified_overview"`
	StringScan     StringTriage        `json:"string_scan"`
	SelectionRule  string              `json:"selection_rule"`
	Candidates     []SecurityCandidate `json:"candidates"`
	CallBoundaries []json.RawMessage   `json:"call_boundaries"`
	Coverage       SecurityCoverage    `json:"coverage"`
	Notes          []string            `json:"notes"`
}

type SecurityCoverage struct {
	StringScanComplete       bool `json:"string_scan_complete"`
	ReferencingFunctionCount int  `json:"referencing_function_count"`
	InspectedFunctions       int  `json:"inspected_functions"`
	UninspectedFunctions     int  `json:"uninspected_functions"`
	CFGTruncatedFunctions    int  `json:"cfg_truncated_functions"`
	PcodeTruncatedFunctions  int  `json:"pcode_truncated_functions"`
	CallEdgesObserved        int  `json:"call_edges_observed"`
	CallBoundariesInspected  int  `json:"call_boundaries_inspected"`
	CallBoundariesOmitted    int  `json:"call_boundaries_omitted"`
}

type SecurityCandidate struct {
	Name            string          `json:"name"`
	Address         string          `json:"address"`
	PriorityScore   int             `json:"priority_score"`
	Indicators      []string        `json:"indicators"`
	StringAddresses []string        `json:"string_addresses"`
	CFG             json.RawMessage `json:"function_cfg"`
	EntryPcode      json.RawMessage `json:"entry_basic_block_pcode"`
	CFGTruncated    bool            `json:"cfg_truncated"`
	PcodeTruncated  bool            `json:"pcode_truncated"`
	Calls           []SecurityCall  `json:"observed_calls"`
	Status          string          `json:"status"`
}

type SecurityCall struct {
	Instruction            string `json:"from_instruction"`
	Target                 string `json:"to"`
	FlowType               string `json:"flow_type"`
	StringReferencedTarget bool   `json:"target_has_string_evidence"`
	TargetName             string `json:"target_name,omitempty"`
}

type chosenCall struct {
	site              string
	target            string
	caller            string
	hasStringEvidence bool
	sourcePriority    int
}

// QuerySecurityTriage collects only static evidence for top-ranked functions.
// It neither executes a firmware component nor interprets control-flow as a bug.
func QuerySecurityTriage(ctx context.Context, target Target, launcher string, timeout time.Duration) (SecurityTriage, error) {
	var report SecurityTriage
	err := withSession(ctx, target, launcher, timeout, func(c *client, ov Overview) error {
		r, err := analyzeSecurityCandidates(c, ov)
		if err != nil {
			return err
		}
		report = r
		return nil
	})
	if err != nil {
		return SecurityTriage{}, err
	}
	return report, nil
}

func analyzeSecurityCandidates(c *client, ov Overview) (SecurityTriage, error) {
	if !ov.IdentityVerified || ov.ReVaProgramPath == "" {
		return SecurityTriage{}, errors.New("unverified ReVa program")
	}
	scan, err := scanWebStrings(c, ov)
	if err != nil {
		return SecurityTriage{}, err
	}
	report := SecurityTriage{
		SchemaVersion: 1, Overview: ov, StringScan: scan,
		SelectionRule: "Deterministic heuristic over referenced string content: authentication 5, request/CGI/ubus 2, other matched strings 1; ties broken by string count then address. Scores are NOT severity, exploitability, or vulnerability confidence.",
		Candidates:    []SecurityCandidate{}, CallBoundaries: []json.RawMessage{},
		Coverage: SecurityCoverage{StringScanComplete: scan.Complete, ReferencingFunctionCount: len(scan.ReferencingFunctions)},
		Notes: []string{
			"Firmware extraction coverage is unverified. The regex and string-reference scan are bounded and not an exhaustive security analysis.",
			"Call edges and P-code are static Ghidra evidence, not proven runtime paths, authorization outcomes or vulnerabilities.",
			"An unselected or truncated function/edge must never be interpreted as absent.",
			"Call-boundary parameter mappings are decompiler candidates; ambiguous signatures remain ambiguous.",
		},
	}
	ranking, err := rankSecurityCandidates(scan)
	if err != nil {
		return SecurityTriage{}, err
	}
	if len(ranking) > maxSecurityCandidates {
		ranking = ranking[:maxSecurityCandidates]
	}
	allNames := make(map[string]string, len(scan.ReferencingFunctions))
	for _, f := range scan.ReferencingFunctions {
		key, err := canonicalAddress(f.Address)
		if err != nil {
			return SecurityTriage{}, fmt.Errorf("invalid string reference function address: %w", err)
		}
		if other, exists := allNames[key]; exists && other != f.Name {
			return SecurityTriage{}, errors.New("conflicting reference function address")
		}
		allNames[key] = f.Name
	}
	for _, selected := range ranking {
		row, err := inspectSecurityCandidate(c, ov.ReVaProgramPath, selected, allNames)
		if err != nil {
			return SecurityTriage{}, fmt.Errorf("candidate %s: %w", selected.Address, err)
		}
		report.Candidates = append(report.Candidates, row)
		if row.CFGTruncated {
			report.Coverage.CFGTruncatedFunctions++
		}
		if row.PcodeTruncated {
			report.Coverage.PcodeTruncatedFunctions++
		}
		report.Coverage.CallEdgesObserved += len(row.Calls)
	}
	report.Coverage.InspectedFunctions = len(report.Candidates)
	report.Coverage.UninspectedFunctions = len(scan.ReferencingFunctions) - len(report.Candidates)

	sites, chosen, err := selectSecurityCalls(report.Candidates)
	if err != nil {
		return SecurityTriage{}, err
	}
	report.Coverage.CallBoundariesOmitted = len(chosen) - len(sites)
	if len(sites) > 0 {
		observed, err := queryCallBoundaries(c, ov, sites)
		if err != nil {
			return SecurityTriage{}, err
		}
		if err := verifySecurityBoundaries(observed.Boundaries, chosen[:len(sites)]); err != nil {
			return SecurityTriage{}, err
		}
		report.CallBoundaries = observed.Boundaries
	}
	report.Coverage.CallBoundariesInspected = len(report.CallBoundaries)
	return report, nil
}

type rankedCandidate struct {
	FunctionCandidate
	score      int
	indicators []string
}

func rankSecurityCandidates(scan StringTriage) ([]rankedCandidate, error) {
	hitContent := map[string]string{}
	for _, raw := range scan.Matches {
		var hit struct {
			Address string `json:"address"`
			Content string `json:"content"`
		}
		if err := json.Unmarshal(raw, &hit); err != nil || hit.Address == "" {
			return nil, errors.New("invalid stored string evidence")
		}
		if _, exists := hitContent[hit.Address]; exists {
			return nil, errors.New("duplicated stored string address")
		}
		hitContent[hit.Address] = strings.ToLower(hit.Content)
	}
	ranked := make([]rankedCandidate, 0, len(scan.ReferencingFunctions))
	for _, f := range scan.ReferencingFunctions {
		if _, err := canonicalAddress(f.Address); err != nil {
			return nil, err
		}
		if f.Name == "" || f.StringCount != len(f.StringAddresses) || f.StringCount == 0 {
			return nil, errors.New("invalid function string references")
		}
		candidate := rankedCandidate{FunctionCandidate: f, indicators: []string{}}
		kinds := map[string]bool{}
		for _, addr := range f.StringAddresses {
			content, ok := hitContent[addr]
			if !ok {
				return nil, errors.New("candidate references unknown string")
			}
			weight, indicator := weighString(content)
			candidate.score += weight
			kinds[indicator] = true
		}
		for kind := range kinds {
			candidate.indicators = append(candidate.indicators, kind)
		}
		sort.Strings(candidate.indicators)
		ranked = append(ranked, candidate)
	}
	sort.Slice(ranked, func(i, j int) bool {
		a, b := ranked[i], ranked[j]
		if a.score != b.score {
			return a.score > b.score
		}
		if a.StringCount != b.StringCount {
			return a.StringCount > b.StringCount
		}
		aa, _ := canonicalAddress(a.Address)
		bb, _ := canonicalAddress(b.Address)
		return aa < bb
	})
	return ranked, nil
}

func weighString(s string) (int, string) {
	for _, kw := range []string{"authorization", "authenticate", "www-authenticate", "http-auth", "password", "passwd", "cookie", "session", "login"} {
		if strings.Contains(s, kw) {
			return 5, "authentication-related string"
		}
	}
	for _, kw := range []string{"request", "/cgi", "cgi-bin", "ubus", "/rpc", "http/"} {
		if strings.Contains(s, kw) {
			return 2, "request/routing-related string"
		}
	}
	return 1, "other web-related string"
}

func canonicalAddress(raw string) (string, error) {
	n, err := parsePcodeAddress(raw)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("0x%08x", n), nil
}

func inspectSecurityCandidate(c *client, program string, candidate rankedCandidate, allNames map[string]string) (SecurityCandidate, error) {
	cfg, err := c.tool("get-function-cfg", map[string]any{"programPath": program, "function": candidate.Address, "maxBlocks": maxCFGBlocks})
	if err != nil {
		return SecurityCandidate{}, err
	}
	address, err := canonicalAddress(getString(cfg, "functionAddress"))
	if err != nil {
		return SecurityCandidate{}, errors.New("CFG missing valid function address")
	}
	selected, err := canonicalAddress(candidate.Address)
	if err != nil || address != selected || getString(cfg, "programPath") != program || getString(cfg, "function") != candidate.Name {
		return SecurityCandidate{}, errors.New("CFG belongs to a different function or program")
	}
	var truncated bool
	if err := json.Unmarshal(cfg["truncated"], &truncated); err != nil || len(cfg["truncated"]) == 0 {
		return SecurityCandidate{}, errors.New("CFG lacks truncation metadata")
	}
	var blocks []struct {
		Min   string `json:"minAddress"`
		Max   string `json:"maxAddress"`
		Calls []struct {
			From string `json:"fromInstruction"`
			To   string `json:"to"`
			Flow string `json:"flowType"`
		} `json:"calls"`
	}
	if err := json.Unmarshal(cfg["blocks"], &blocks); err != nil || blocks == nil || len(blocks) > maxCFGBlocks {
		return SecurityCandidate{}, errors.New("invalid or oversized CFG block list")
	}
	for _, block := range blocks {
		a, e1 := parsePcodeAddress(block.Min)
		b, e2 := parsePcodeAddress(block.Max)
		if e1 != nil || e2 != nil || a > b {
			return SecurityCandidate{}, errors.New("invalid CFG block bounds")
		}
	}
	pcode, err := c.tool("get-pcode", map[string]any{"programPath": program, "target": candidate.Address, "scope": "basic-block", "maxInstructions": maxPcodeInstructions, "maxOps": maxPcodeOps})
	if err != nil {
		return SecurityCandidate{}, err
	}
	if getString(pcode, "programPath") != program || getString(pcode, "scope") != "basic-block" || !sameHexAddress(getString(pcode, "resolvedAddress"), candidate.Address) {
		return SecurityCandidate{}, errors.New("entry P-code belongs to another program/function")
	}
	var pTrunc bool
	if err := json.Unmarshal(pcode["truncated"], &pTrunc); err != nil || len(pcode["truncated"]) == 0 {
		return SecurityCandidate{}, errors.New("P-code lacks truncation metadata")
	}
	cfgRaw, err := json.Marshal(cfg)
	if err != nil {
		return SecurityCandidate{}, err
	}
	pcodeRaw, err := json.Marshal(pcode)
	if err != nil {
		return SecurityCandidate{}, err
	}
	out := SecurityCandidate{
		Name: candidate.Name, Address: selected, PriorityScore: candidate.score, Indicators: candidate.indicators,
		StringAddresses: append([]string{}, candidate.StringAddresses...), CFG: cfgRaw, EntryPcode: pcodeRaw,
		CFGTruncated: truncated, PcodeTruncated: pTrunc, Calls: []SecurityCall{}, Status: "security-relevant static candidate; no vulnerability confirmed",
	}
	seen := map[string]bool{}
	for _, block := range blocks {
		low, _ := parsePcodeAddress(block.Min)
		high, _ := parsePcodeAddress(block.Max)
		for _, call := range block.Calls {
			site, err := canonicalAddress(call.From)
			if err != nil {
				return SecurityCandidate{}, errors.New("invalid CFG callsite")
			}
			num, _ := parsePcodeAddress(site)
			if num < low || num > high || seen[site] || call.Flow == "" {
				return SecurityCandidate{}, errors.New("inconsistent CFG call instruction")
			}
			seen[site] = true
			to, err := canonicalAddress(call.To)
			if err != nil {
				return SecurityCandidate{}, errors.New("invalid CFG call target")
			}
			name, related := allNames[to]
			out.Calls = append(out.Calls, SecurityCall{Instruction: site, Target: to, FlowType: call.Flow, StringReferencedTarget: related, TargetName: name})
		}
	}
	sort.Slice(out.Calls, func(i, j int) bool { return out.Calls[i].Instruction < out.Calls[j].Instruction })
	return out, nil
}

func selectSecurityCalls(candidates []SecurityCandidate) ([]string, []chosenCall, error) {
	var choices []chosenCall
	seen := map[string]bool{}
	for _, candidate := range candidates {
		for _, call := range candidate.Calls {
			if seen[call.Instruction] {
				return nil, nil, errors.New("duplicate callsite in selected functions")
			}
			seen[call.Instruction] = true
			choices = append(choices, chosenCall{site: call.Instruction, target: call.Target, caller: candidate.Address, hasStringEvidence: call.StringReferencedTarget, sourcePriority: candidate.PriorityScore})
		}
	}
	sort.Slice(choices, func(i, j int) bool {
		a, b := choices[i], choices[j]
		if a.hasStringEvidence != b.hasStringEvidence {
			return a.hasStringEvidence
		}
		if a.sourcePriority != b.sourcePriority {
			return a.sourcePriority > b.sourcePriority
		}
		return a.site < b.site
	})
	max := len(choices)
	if max > maxSecurityCalls {
		max = maxSecurityCalls
	}
	selected := make([]string, 0, max)
	for _, choice := range choices[:max] {
		selected = append(selected, choice.site)
	}
	return selected, choices, nil
}

func verifySecurityBoundaries(boundaries []json.RawMessage, expected []chosenCall) error {
	if len(boundaries) != len(expected) {
		return errors.New("call-boundary count mismatches CFG selection")
	}
	for i, raw := range boundaries {
		var boundary struct {
			Callsite string `json:"callsite"`
			Caller   struct {
				Address string `json:"address"`
			} `json:"caller"`
			Calls []struct {
				TargetAddress string `json:"targetAddress"`
				TargetKind    string `json:"targetKind"`
			} `json:"calls"`
			CallOperationsTruncated bool `json:"callOperationsTruncated"`
		}
		if err := json.Unmarshal(raw, &boundary); err != nil {
			return err
		}
		if !sameHexAddress(boundary.Callsite, expected[i].site) || !sameHexAddress(boundary.Caller.Address, expected[i].caller) {
			return errors.New("call-boundary caller/callsite mismatches CFG")
		}
		// For an unambiguous recovered direct call, the decompiler target must
		// equal the machine-level CFG target. Unresolved/ambiguous stays visible.
		for _, observed := range boundary.Calls {
			if observed.TargetKind == "direct_internal" || observed.TargetKind == "thunk" || observed.TargetKind == "external" || observed.TargetKind == "direct_no_function" {
				if !sameHexAddress(observed.TargetAddress, expected[i].target) {
					return errors.New("call-boundary target mismatches CFG")
				}
			}
		}
	}
	return nil
}
