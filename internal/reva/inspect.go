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
const maxCFGBlocks = 64
const maxPcodeInstructions = 32
const maxPcodeOps = 256

// QueryInspection lists at most 64 functions in a newly analyzed disposable
// project; optionally requests one function CFG and one entry basic-block
// P-code excerpt. No execution, scripts, or arbitrary MCP tool calls.
func QueryInspection(ctx context.Context, target Target, launcher, function string, timeout time.Duration) (Inspection, error) {
	if len(function) > 160 || strings.ContainsAny(function, "\r\n\x00") {
		return Inspection{}, errors.New("function identifier is too long or contains controls")
	}
	var result Inspection
	err := withSession(ctx, target, launcher, timeout, func(c *client, ov Overview) error {
		inspected, err := inspectFunction(c, ov, function)
		if err != nil {
			return err
		}
		result = inspected
		return nil
	})
	return result, err
}

func inspectFunction(c *client, overview Overview, function string) (Inspection, error) {
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
	index, err := c.tool("get-functions", map[string]any{
		"programPath": program, "startIndex": 0, "maxCount": maxFunctions,
		"filterDefaultNames": false, "verbose": false,
	})
	if err != nil {
		return Inspection{}, err
	}
	var found []json.RawMessage
	if err := json.Unmarshal(index["functions"], &found); err != nil {
		return Inspection{}, fmt.Errorf("invalid ReVa function index: %w", err)
	}
	count, err := positiveIndexInt(index, "actualCount")
	if err != nil || count != len(found) || count > maxFunctions {
		return Inspection{}, errors.New("invalid returned function count")
	}
	total, err := positiveIndexInt(index, "totalCount")
	if err != nil || total < count {
		return Inspection{}, errors.New("invalid total function count")
	}
	for _, raw := range found {
		var row struct {
			Name    string `json:"name"`
			Address string `json:"address"`
		}
		if err := json.Unmarshal(raw, &row); err != nil || row.Name == "" || row.Address == "" {
			return Inspection{}, errors.New("function index contains incomplete entry")
		}
	}
	indexJSON, err := json.Marshal(index)
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
