package reva

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Inspection preserves the verified executable identity and the exact bounded
// ReVa responses, including any truncation, instead of inferring a bug.
type Inspection struct {
	SchemaVersion     int             `json:"schema_version"`
	Overview          Overview        `json:"verified_overview"`
	FunctionIndex     json.RawMessage `json:"function_index"`
	RequestedFunction string          `json:"requested_function,omitempty"`
	FunctionCFG       json.RawMessage `json:"function_cfg,omitempty"`
	PCode             json.RawMessage `json:"basic_block_pcode,omitempty"`
}

const maxFunctions = 64
const maxIndexedFunctions = 512
const maxCFGBlocks = 64
const maxPcodeInstructions = 32
const maxPcodeOps = 256

// QueryInspection lists at most 64 functions in a newly analyzed disposable
// project; optionally requests one function CFG and one entry basic-block
// P-code excerpt. No execution, scripts, or arbitrary MCP tool calls.
func QueryInspection(ctx context.Context, target Target, launcher, function string, timeout time.Duration, fullIndex bool) (Inspection, error) {
	if len(function) > 160 || strings.ContainsAny(function, "\r\n\x00") {
		return Inspection{}, errors.New("function identifier is too long or contains controls")
	}
	var result Inspection
	err := withSession(ctx, target, launcher, timeout, func(c *client, ov Overview) error {
		inspected, err := inspectFunctionPaged(c, ov, function, fullIndex)
		if err != nil {
			return err
		}
		result = inspected
		return nil
	})
	return result, err
}

func inspectFunction(c *client, overview Overview, function string) (Inspection, error) {
	return inspectFunctionPaged(c, overview, function, false)
}

func inspectFunctionPaged(c *client, overview Overview, function string, fullIndex bool) (Inspection, error) {
	program := overview.ReVaProgramPath
	if program == "" || !overview.IdentityVerified {
		return Inspection{}, errors.New("unverified ReVa program")
	}
	catalog, err := c.request("tools/list", map[string]any{})
	if err != nil {
		return Inspection{}, err
	}
	var tools struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(catalog, &tools); err != nil {
		return Inspection{}, err
	}
	available := map[string]bool{}
	for _, entry := range tools.Tools {
		available[entry.Name] = true
	}
	if !available["get-functions"] || (function != "" && (!available["get-function-cfg"] || !available["get-pcode"])) {
		return Inspection{}, errors.New("required read-only ReVa function tools unavailable in development extension")
	}
	indexJSON, err := readFunctionIndex(c, program, fullIndex)
	if err != nil {
		return Inspection{}, err
	}
	result := Inspection{SchemaVersion: 1, Overview: overview, FunctionIndex: indexJSON}
	if function == "" {
		return result, nil
	}
	cfg, err := c.tool("get-function-cfg", map[string]any{"programPath": program, "function": function, "maxBlocks": maxCFGBlocks})
	if err != nil {
		return Inspection{}, err
	}
	address := getString(cfg, "functionAddress")
	if address == "" || getString(cfg, "programPath") != program || getString(cfg, "function") == "" {
		return Inspection{}, errors.New("CFG lacks a verifiable program, function or entry address")
	}
	if name := getString(cfg, "function"); function != name && !strings.EqualFold(function, address) {
		return Inspection{}, fmt.Errorf("requested function %q resolved to unexpected %q at %q", function, name, address)
	}
	// P-code uses Ghidra's returned entry address, not an invented offset.
	pcode, err := c.tool("get-pcode", map[string]any{"programPath": program, "target": address,
		"scope": "basic-block", "maxInstructions": maxPcodeInstructions, "maxOps": maxPcodeOps})
	if err != nil {
		return Inspection{}, err
	}
	if getString(pcode, "programPath") != program || getString(pcode, "scope") != "basic-block" || !strings.EqualFold(getString(pcode, "resolvedAddress"), address) {
		return Inspection{}, errors.New("P-code result does not correspond to selected CFG entry block")
	}
	// Require truncation metadata; never infer completeness from a small page.
	for _, row := range []map[string]json.RawMessage{cfg, pcode} {
		var truncated bool
		if raw, ok := row["truncated"]; !ok || json.Unmarshal(raw, &truncated) != nil {
			return Inspection{}, errors.New("ReVa result omitted valid truncation metadata")
		}
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return Inspection{}, err
	}
	pcodeJSON, err := json.Marshal(pcode)
	if err != nil {
		return Inspection{}, err
	}
	result.RequestedFunction = function
	result.FunctionCFG = cfgJSON
	result.PCode = pcodeJSON
	return result, nil
}

// readFunctionIndex returns a single upstream page by default. Full indexing
// fetches at most eight bounded pages in one temporary Ghidra project. Its
// pagination metadata describes the returned *index*, not Ghidra's separate
// overview functionCount, which may use a different scope.
func readFunctionIndex(c *client, program string, fullIndex bool) (json.RawMessage, error) {
	limit := maxFunctions
	if fullIndex {
		limit = maxIndexedFunctions
	}
	var collected []json.RawMessage
	seen := make(map[string]bool)
	cursor, total, pages := 0, -1, 0
	for cursor < limit {
		pageSize := maxFunctions
		if cursor+pageSize > limit {
			pageSize = limit - cursor
		}
		index, err := c.tool("get-functions", map[string]any{
			"programPath": program, "startIndex": cursor, "maxCount": pageSize,
			"filterDefaultNames": false, "verbose": false,
		})
		if err != nil {
			return nil, err
		}
		var found []json.RawMessage
		if err := json.Unmarshal(index["functions"], &found); err != nil {
			return nil, fmt.Errorf("invalid ReVa function index: %w", err)
		}
		count, err := positiveIndexInt(index, "actualCount")
		if err != nil || count != len(found) || count > pageSize {
			return nil, errors.New("invalid returned function count")
		}
		pageTotal, err := positiveIndexInt(index, "totalCount")
		if err != nil || pageTotal < cursor+count {
			return nil, errors.New("invalid total function count")
		}
		if total != -1 && total != pageTotal {
			return nil, errors.New("function index total changed between pages")
		}
		total = pageTotal
		start, err := positiveIndexInt(index, "startIndex")
		if err != nil || start != cursor {
			return nil, errors.New("function index returned an unexpected page")
		}
		next, err := positiveIndexInt(index, "nextStartIndex")
		if err != nil || next != cursor+count {
			return nil, errors.New("function index advanced an incorrect offset")
		}
		if count == 0 && cursor < total {
			return nil, errors.New("incomplete function index: empty page before end")
		}
		for _, raw := range found {
			var row struct {
				Name    string `json:"name"`
				Address string `json:"address"`
			}
			if err := json.Unmarshal(raw, &row); err != nil || row.Name == "" || row.Address == "" {
				return nil, errors.New("function index contains incomplete entry")
			}
			if seen[row.Address] {
				return nil, fmt.Errorf("duplicate function address across pages: %s", row.Address)
			}
			seen[row.Address] = true
		}
		collected = append(collected, found...)
		cursor = next
		pages++
		if !fullIndex {
			// Preserve ReVa's original first-page representation.
			return json.Marshal(index)
		}
		if cursor >= total {
			break
		}
	}
	return json.Marshal(map[string]any{
		"functions": collected, "actualCount": len(collected),
		"totalCount": total, "startIndex": 0,
		"nextStartIndex": cursor, "filterDefaultNames": false,
		"verbose": false, "pageSize": maxFunctions,
		"pageCount": pages, "complete": cursor >= total,
		"truncated": cursor < total,
	})
}

func positiveIndexInt(obj map[string]json.RawMessage, key string) (int, error) {
	var number json.Number
	if len(obj[key]) == 0 {
		return 0, errors.New("missing " + key)
	}
	if err := json.Unmarshal(obj[key], &number); err != nil {
		return 0, err
	}
	numberInt, err := strconv.Atoi(string(number))
	if err != nil || numberInt < 0 {
		return 0, errors.New("invalid " + key)
	}
	return numberInt, nil
}
