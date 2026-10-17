package reva

import (
    "encoding/json"
    "strings"
    "testing"
)

func callFixture(t *testing.T, site string, override map[string]any) string {
    t.Helper()
    payload := map[string]any{
        "programPath":"/uhttpd", "callsite":site, "caller":map[string]string{"name":"FUN_00014e8c","address":"0x00014e8c"},
        "callOperationCount":1, "returnedCallOperationCount":1, "callOperationsTruncated":false,
        "calls":[]any{map[string]any{"opcode":"CALL","targetKind":"direct_internal","mappingStatus":"ambiguous_prototype_or_storage","argumentsTruncated":false,"targetAddress":"0x00014a14"}},
    }
    for k,v := range override { payload[k] = v }
    b,err:=json.Marshal(payload);if err!=nil{t.Fatal(err)}
    return toolFixture(t,string(b))
}

func TestCallEvidencePreservesMultipleCallSitesAndAmbiguity(t *testing.T) {
    sites,err:=normalizeCallSites([]string{"0x14e9c","0x00014f18"});if err!=nil{t.Fatal(err)}
    c:=rpcFixture(t,`{"tools":[{"name":"inspect-call-boundary"}]}`,
        callFixture(t,sites[0],nil),callFixture(t,sites[1],map[string]any{"callOperationsTruncated":true,"callOperationCount":2}))
    evidence,err:=queryCallBoundaries(c,overviewFixture(),sites)
    if err!=nil{t.Fatal(err)}
    if len(evidence.Boundaries)!=2 || !evidence.Overview.IdentityVerified || len(evidence.CallSites)!=2 {t.Fatal("lost evidence")}
    var payload map[string]json.RawMessage
    if err:=json.Unmarshal(evidence.Boundaries[0],&payload);err!=nil{t.Fatal(err)}
    var calls []struct{ MappingStatus string `json:"mappingStatus"` }
    if err:=json.Unmarshal(payload["calls"],&calls);err!=nil||calls[0].MappingStatus!="ambiguous_prototype_or_storage"{t.Fatal("lost ambiguous mapping")}
}

func TestCallSitesRejectedBeforeLaunchingReVa(t *testing.T) {
    for _, sites:=range [][]string{nil,{"0x1","0x2","0x3","0x4","0x5"},{"0x14e9c","0x00014e9c"},{"1234"},{"0xZZ"},{"0x1\n"}} {
        if _,err:=normalizeCallSites(sites);err==nil {t.Errorf("accepted %v",sites)}
    }
}

func TestCallBoundariesRejectMismatchedAndMalformedEvidence(t *testing.T) {
    cases:=[]map[string]any{
        {"programPath":"/other"}, {"callsite":"0x14eac"}, {"callOperationCount":0},
        {"returnedCallOperationCount":2},{"callOperationsTruncated":true},{"caller":map[string]any{}},
        {"calls":[]any{map[string]any{"opcode":"CALL","targetKind":"direct_internal","mappingStatus":"", "argumentsTruncated":false}}},
    }
    for i,mutation:=range cases {
        c:=rpcFixture(t,`{"tools":[{"name":"inspect-call-boundary"}]}`,callFixture(t,"0x00014e9c",mutation))
        if _,err:=queryCallBoundaries(c,overviewFixture(),[]string{"0x00014e9c"});err==nil{t.Errorf("accepted malformed response #%d",i)}
    }
    c:=rpcFixture(t,`{"tools":[]}`)
    if _,err:=queryCallBoundaries(c,overviewFixture(),[]string{"0x00014e9c"});err==nil{t.Error("accepted absent tool")}
    ov:=overviewFixture();ov.IdentityVerified=false
    if _,err:=queryCallBoundaries(nil,ov,[]string{"0x00014e9c"});err==nil{t.Error("accepted unverified binary")}
}

func TestCallsiteNormalization(t *testing.T) {
    sites,err:=normalizeCallSites([]string{"0x14e9c"});if err!=nil||!strings.EqualFold(sites[0],"0x00014e9c"){t.Fatalf("bad normalization %v %v",sites,err)}
}
