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

// A fixed, bounded research query. Regex is defined by the program, not by
// firmware strings, an agent or an untrusted caller.
const webStringPattern = `(?i)(http|authorization|auth|cookie|session|cgi|ubus|content-type|request|/rpc|redirect)`
const maxStringPage = 32
const maxStringHits = 128
const maxReferencesPerString = 100 // upstream ReVa limit; saturation is ambiguous

type StringTriage struct {
	SchemaVersion        int                 `json:"schema_version"`
	Overview             Overview            `json:"verified_overview"`
	Pattern              string              `json:"regex_pattern"`
	Matches              []json.RawMessage   `json:"matches"`
	MatchCount           int                 `json:"match_count"`
	PageCount            int                 `json:"page_count"`
	Complete             bool                `json:"complete"`
	Truncated            bool                `json:"truncated"`
	ReferencingFunctions []FunctionCandidate `json:"referencing_functions"`
	Notes                []string            `json:"notes"`
}

type FunctionCandidate struct {
	Name            string   `json:"name"`
	Address         string   `json:"address"`
	StringAddresses []string `json:"string_addresses"`
	StringCount     int      `json:"string_count"`
}

func QueryStringTriage(ctx context.Context, target Target, launcher string, timeout time.Duration) (StringTriage, error) {
	var result StringTriage
	err := withSession(ctx, target, launcher, timeout, func(c *client, overview Overview) error {
		found, err := scanWebStrings(c, overview)
		if err != nil {
			return err
		}
		result = found
		return nil
	})
	return result, err
}

func scanWebStrings(c *client, overview Overview) (StringTriage, error) {
	if !overview.IdentityVerified || overview.ReVaProgramPath == "" {
		return StringTriage{}, errors.New("cannot triage an unverified program")
	}
	catalog, err := c.request("tools/list", map[string]any{})
	if err != nil {
		return StringTriage{}, err
	}
	var list struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(catalog, &list); err != nil {
		return StringTriage{}, err
	}
	exists := false
	for _, item := range list.Tools {
		if item.Name == "get-strings" {
			exists = true
		}
	}
	if !exists {
		return StringTriage{}, errors.New("ReVa get-strings tool unavailable")
	}
	result := StringTriage{SchemaVersion: 1, Overview: overview, Pattern: webStringPattern, Matches: make([]json.RawMessage, 0), ReferencingFunctions: make([]FunctionCandidate, 0), Notes: []string{"String references are static Ghidra candidates, not proven execution paths or vulnerabilities.", "A string with 100 returned referencing functions may have more; upstream ReVa caps this list."}}
	candidates := map[string]*FunctionCandidate{}
	seenStrings := map[string]bool{}
	for cursor := 0; cursor < maxStringHits; {
		pageSize := maxStringPage
		if maxStringHits-cursor < pageSize {
			pageSize = maxStringHits - cursor
		}
		page, err := c.toolArray("get-strings", map[string]any{"programPath": overview.ReVaProgramPath, "regexPattern": webStringPattern, "startIndex": cursor, "maxCount": pageSize, "includeReferencingFunctions": true})
		if err != nil {
			return StringTriage{}, err
		}
		if len(page) < 1 || len(page) > pageSize+1 {
			return StringTriage{}, errors.New("invalid ReVa string page length")
		}
		var meta struct {
			Pattern  string `json:"regexPattern"`
			Start    int    `json:"startIndex"`
			Actual   int    `json:"actualCount"`
			Next     int    `json:"nextStartIndex"`
			Complete *bool  `json:"searchComplete"`
		}
		if err := json.Unmarshal(page[0], &meta); err != nil {
			return StringTriage{}, fmt.Errorf("invalid ReVa strings metadata: %w", err)
		}
		if meta.Pattern != webStringPattern || meta.Start != cursor || meta.Actual != len(page)-1 || meta.Actual > pageSize || meta.Next != cursor+meta.Actual || meta.Complete == nil || (!*meta.Complete && meta.Actual == 0) {
			return StringTriage{}, errors.New("inconsistent ReVa string pagination")
		}
		for _, raw := range page[1:] {
			var hit struct {
				Address              string `json:"address"`
				Content              string `json:"content"`
				ReferenceCount       *int   `json:"referenceCount"`
				ReferencingFunctions []struct {
					Name    string `json:"name"`
					Address string `json:"address"`
				} `json:"referencingFunctions"`
			}
			if err := json.Unmarshal(raw, &hit); err != nil {
				return StringTriage{}, fmt.Errorf("invalid ReVa string: %w", err)
			}
			if hit.Address == "" || len(hit.Address) > 128 || len(hit.Content) > 4096 || seenStrings[hit.Address] || hit.ReferenceCount == nil || *hit.ReferenceCount != len(hit.ReferencingFunctions) || len(hit.ReferencingFunctions) > maxReferencesPerString {
				return StringTriage{}, errors.New("invalid ReVa string reference record")
			}
			seenStrings[hit.Address] = true
			result.Matches = append(result.Matches, raw)
			for _, ref := range hit.ReferencingFunctions {
				if strings.TrimSpace(ref.Name) == "" || strings.TrimSpace(ref.Address) == "" || len(ref.Name) > 256 || len(ref.Address) > 128 {
					return StringTriage{}, errors.New("invalid string referencing function")
				}
				candidate := candidates[ref.Address]
				if candidate == nil {
					candidate = &FunctionCandidate{Name: ref.Name, Address: ref.Address}
					candidates[ref.Address] = candidate
				}
				if candidate.Name != ref.Name {
					return StringTriage{}, errors.New("conflicting Ghidra names for one function entry")
				}
				candidate.StringAddresses = append(candidate.StringAddresses, hit.Address)
			}
		}
		result.PageCount++
		cursor = meta.Next
		if *meta.Complete {
			result.Complete = true
			break
		}
	}
	result.Truncated = !result.Complete
	result.MatchCount = len(result.Matches)
	for _, ref := range candidates {
		ref.StringCount = len(ref.StringAddresses)
		result.ReferencingFunctions = append(result.ReferencingFunctions, *ref)
	}
	sort.Slice(result.ReferencingFunctions, func(i, j int) bool {
		a, b := result.ReferencingFunctions[i], result.ReferencingFunctions[j]
		if a.StringCount != b.StringCount {
			return a.StringCount > b.StringCount
		}
		return a.Address < b.Address
	})
	return result, nil
}
