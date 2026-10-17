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

const maxCallSites = 4
const maxCallArguments = 16

type CallEvidence struct {
    SchemaVersion int `json:"schema_version"`
    Overview Overview `json:"verified_overview"`
    CallSites []string `json:"requested_callsites"`
    Boundaries []json.RawMessage `json:"call_boundaries"`
    Notes []string `json:"notes"`
}

// QueryCallEvidence observes operator-selected machine call instructions only.
// ReVa's decompiler is an evidence source, not a runtime/ABI oracle.
func QueryCallEvidence(ctx context.Context, target Target, launcher string, sites []string, timeout time.Duration) (CallEvidence, error) {
    canonical, err := normalizeCallSites(sites)
    if err != nil { return CallEvidence{}, err }
    var evidence CallEvidence
    err = withSession(ctx, target, launcher, timeout, func(c *client, overview Overview) error {
        found, err := queryCallBoundaries(c, overview, canonical)
        if err != nil { return err }
        evidence = found
        return nil
    })
    if err != nil { return CallEvidence{}, err }
    return evidence, nil
}

func normalizeCallSites(sites []string) ([]string, error) {
    if len(sites) == 0 || len(sites) > maxCallSites {
        return nil, fmt.Errorf("select 1 to %d call sites", maxCallSites)
    }
    result := make([]string, 0, len(sites))
    seen := map[uint64]bool{}
    for _, raw := range sites {
        if !strings.HasPrefix(raw, "0x") || len(raw) < 3 || len(raw) > 18 {
            return nil, fmt.Errorf("invalid hexadecimal call site %q", raw)
        }
        n, err := strconv.ParseUint(raw[2:], 16, 64)
        if err != nil || seen[n] { return nil, fmt.Errorf("invalid or duplicate call site %q", raw) }
        seen[n] = true
        result = append(result, fmt.Sprintf("0x%08x", n))
    }
    return result, nil
}

func queryCallBoundaries(c *client, ov Overview, sites []string) (CallEvidence, error) {
    if !ov.IdentityVerified || ov.ReVaProgramPath == "" { return CallEvidence{}, errors.New("unverified ReVa program") }
    if len(sites) == 0 || len(sites) > maxCallSites { return CallEvidence{}, errors.New("invalid call site count") }
    catalog, err := c.request("tools/list", map[string]any{})
    if err != nil { return CallEvidence{}, err }
    var tools struct { Tools []struct{ Name string `json:"name"` } `json:"tools"` }
    if err := json.Unmarshal(catalog, &tools); err != nil { return CallEvidence{}, err }
    allowed := false
    for _, t := range tools.Tools { if t.Name == "inspect-call-boundary" { allowed = true } }
    if !allowed { return CallEvidence{}, errors.New("inspect-call-boundary not available in ReVa development extension") }
    result := CallEvidence{
        SchemaVersion: 1, Overview: ov,
        CallSites: append([]string(nil), sites...),
        Boundaries: make([]json.RawMessage, 0, len(sites)),
        Notes: []string{"Static High P-code argument/formal mappings are candidates, not runtime-verified values or authorization outcomes.", "Any truncation or unresolved target must be treated as incomplete evidence."},
    }
    for _, site := range sites {
        observed, err := c.tool("inspect-call-boundary", map[string]any{
            "programPath": ov.ReVaProgramPath, "callsite": site, "maxArguments": maxCallArguments,
        })
        if err != nil { return CallEvidence{}, fmt.Errorf("callsite %s: %w", site, err) }
        if getString(observed, "programPath") != ov.ReVaProgramPath || !sameHexAddress(getString(observed, "callsite"), site) {
            return CallEvidence{}, fmt.Errorf("callsite %s: ReVa returned a mismatched program or address", site)
        }
        var caller struct { Name string `json:"name"`; Address string `json:"address"` }
        if err := json.Unmarshal(observed["caller"], &caller); err != nil || caller.Name == "" || caller.Address == "" {
            return CallEvidence{}, errors.New("ReVa omitted caller identity")
        }
        var count, returned int
        if err := json.Unmarshal(observed["callOperationCount"], &count); err != nil || count < 1 { return CallEvidence{}, errors.New("invalid call operation count") }
        if err := json.Unmarshal(observed["returnedCallOperationCount"], &returned); err != nil || returned < 1 || returned > 8 || returned > count { return CallEvidence{}, errors.New("invalid returned call operation count") }
        var trunc bool
        if err := json.Unmarshal(observed["callOperationsTruncated"], &trunc); err != nil || trunc != (returned < count) { return CallEvidence{}, errors.New("invalid call truncation marker") }
        var calls []json.RawMessage
        if err := json.Unmarshal(observed["calls"], &calls); err != nil || len(calls) != returned { return CallEvidence{}, errors.New("inconsistent call records") }
        for _, raw := range calls {
            var item struct {
                Opcode string `json:"opcode"`
                TargetKind string `json:"targetKind"`
                MappingStatus string `json:"mappingStatus"`
                ArgumentsTruncated *bool `json:"argumentsTruncated"`
            }
            if err := json.Unmarshal(raw, &item); err != nil || (item.Opcode != "CALL" && item.Opcode != "CALLIND") || item.TargetKind == "" || item.MappingStatus == "" || item.ArgumentsTruncated == nil {
                return CallEvidence{}, errors.New("invalid ReVa static call observation")
            }
        }
        raw, err := json.Marshal(observed)
        if err != nil { return CallEvidence{}, err }
        result.Boundaries = append(result.Boundaries, raw)
    }
    return result, nil
}

func sameHexAddress(a, b string) bool {
    if !strings.HasPrefix(a, "0x") || !strings.HasPrefix(b, "0x") { return false }
    x, ex := strconv.ParseUint(a[2:], 16, 64)
    y, ey := strconv.ParseUint(b[2:], 16, 64)
    return ex == nil && ey == nil && x == y
}
