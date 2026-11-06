package collector

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

// The deprecated security_features block copies each scanner's coverage from
// the vuln-scanning artifact. A coverage over no projects is left out, and a
// coverage left out with a gap passes the gap on.
func TestSecurityFeaturesCopiesEachScannersCoverage(t *testing.T) {
	rec := &componentsdk.Recorder{}
	c := New(Config{Group: kitGroup, Recorder: rec, VulnScanning: true, Now: func() time.Time { return kitNow }}, &fakeClient{})
	rec.NotCollectedCode(vuln("/scanners/2/coverage_pct"), componentsdk.CodeNotLicensed, "secret detection needs GitLab Ultimate")
	vs := &VulnScanning{Scanners: []VulnScanner{
		{Scanner: "dependency_scanning", CoveragePct: Reading[int]{Read: true}},
		{Scanner: "sast", CoveragePct: Reading[int]{Value: ptr(40), Read: true}},
		{Scanner: "secret_detection"},
	}}

	got := c.securityFeatures(vs)

	if got.VulnAlertsPct != nil {
		t.Errorf("vuln_alerts_pct = %v, want it left out over no projects", *got.VulnAlertsPct)
	}
	if got.CodeScanningPct == nil || *got.CodeScanningPct != 40 {
		t.Errorf("code_scanning_pct = %v, want 40", got.CodeScanningPct)
	}
	if got.SecretScanningPct != nil {
		t.Errorf("secret_scanning_pct = %v, want it left out", *got.SecretScanningPct)
	}
	var carried bool
	for _, g := range rec.Gaps() {
		if g.Path == NormalizedPath && g.Pointer == "/security_features/secret_scanning_pct" && g.Code == componentsdk.CodeNotLicensed {
			carried = true
		}
	}
	if !carried {
		t.Errorf("secret_scanning_pct has no copy of its scanner's gap: %+v", rec.Gaps())
	}
}

// The deprecated org_security block copies the group's 2FA requirement.
func TestToVCSPostureKeepsTheTwoFactorRequirement(t *testing.T) {
	g := &GroupPosture{Group: kitGroup, AccessControl: AccessControl{TwoFactorRequired: ptr(true)}}
	if got := g.ToVCSPosture().OrgSecurity.TwoFactorRequired; got == nil || !*got {
		t.Errorf("two_factor_required = %v, want true", got)
	}
	if got := (&GroupPosture{Group: kitGroup}).ToVCSPosture().OrgSecurity.TwoFactorRequired; got != nil {
		t.Errorf("two_factor_required = %v, want it left out when unknown", *got)
	}
}

// A collect list that leaves out access-posture and vuln-scanning leaves out
// the deprecated blocks that moved to them, each with a not_shared gap.
func TestCollectLeavesOutTheDeprecatedBlocksMovedToAKindLeftOut(t *testing.T) {
	full := runInProcess(trustConfig(), kitSecrets(), newReplay(t, kitResponses(kitCleanTenant(), kitBase)))
	if doc := vcsDoc(t, full); doc["org_security"] == nil || doc["security_features"] == nil {
		t.Fatalf("vcs-posture = %v, want both deprecated blocks with every kind collected", doc)
	}

	config := trustConfig()
	config["collect"] = []any{"vcs-posture", "details"}
	res := runInProcess(config, kitSecrets(), newReplay(t, kitResponses(kitCleanTenant(), kitBase)))
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	doc := vcsDoc(t, res)
	for _, block := range []string{"org_security", "security_features"} {
		if _, ok := doc[block]; ok {
			t.Errorf("vcs-posture has %s = %v, which moved to a kind collect leaves out", block, doc[block])
		}
		if g := resultGap(res, NormalizedPath, "/"+block); g == nil || g.Code != componentsdk.CodeNotShared {
			t.Errorf("gap at /%s = %+v, want not_shared", block, g)
		}
	}
}

func vcsDoc(t *testing.T, res componentsdk.InProcessResult) map[string]any {
	t.Helper()
	for _, a := range res.Artifacts {
		if a.Path != NormalizedPath {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal(a.Data, &doc); err != nil {
			t.Fatalf("decode %s: %v", a.Path, err)
		}
		return doc
	}
	t.Fatalf("the run wrote no %s", NormalizedPath)
	return nil
}
