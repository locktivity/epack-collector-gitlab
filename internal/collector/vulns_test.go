package collector

import (
	"testing"
	"time"

	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
	"github.com/locktivity/epack/componentsdk"
)

const day24 = 24 * time.Hour

// A finding is overdue when it is critical and open more than 30 days, or
// high and open more than 90 days.
func TestCountFindings_OverdueRule(t *testing.T) {
	now := kitNow
	open := func(project int, reportType, severity string, age time.Duration) gitlab.Vulnerability {
		return gitlab.Vulnerability{ProjectID: project, ReportType: reportType, Severity: severity, DetectedAt: now.Add(-age)}
	}
	vulns := []gitlab.Vulnerability{
		open(1, "SAST", "CRITICAL", 30*day24),
		open(1, "SAST", "CRITICAL", 30*day24+time.Second),
		open(1, "SAST", "HIGH", 90*day24),
		open(1, "SAST", "HIGH", 90*day24+time.Second),
		open(1, "SAST", "MEDIUM", 400*day24),
		open(1, "SAST", "LOW", 400*day24),
		// Another scanner's finding, and one in a project the patterns
		// leave out.
		open(1, "SECRET_DETECTION", "CRITICAL", 400*day24),
		open(2, "SAST", "CRITICAL", 400*day24),
	}
	got := countFindings(vulns, "SAST", map[int]bool{1: true}, now)
	want := findingCounts{critical: 2, high: 2, medium: 1, low: 1, overdueCritical: 1, overdueHigh: 1}
	if got != want {
		t.Errorf("countFindings = %+v, want %+v", got, want)
	}
}

func TestCountCoverage(t *testing.T) {
	projects := []gitlab.Project{{ID: 1}, {ID: 2}, {ID: 3}, {ID: 4}}
	scanners := map[int]gitlab.SecurityScanners{
		1: {PipelineRun: []string{"SAST"}},
		2: {PipelineRun: []string{"SAST_ADVANCED", "DEPENDENCY_SCANNING"}},
		3: {PipelineRun: []string{}},
	}
	sast := countCoverage(projects, scanners, scannerKinds[1])
	if sast != (coverage{scanned: 2, unknown: 1}) {
		t.Errorf("sast coverage = %+v, want 2 scanned and project 4 unknown", sast)
	}
	secrets := countCoverage(projects, scanners, scannerKinds[2])
	if secrets != (coverage{scanned: 0, unknown: 1}) {
		t.Errorf("secret detection coverage = %+v, want none scanned and project 4 unknown", secrets)
	}
}

// A scanner is enabled when it covers at least one assessed project. A
// project whose CI configuration sets the scanner up does not count until
// the scanner succeeds in its latest default branch pipeline.
func TestVulnScanning_EnabledWhenTheScannerCoversAProject(t *testing.T) {
	tenant := kitCleanTenant()
	tenant.scanners[10] = kitScanners{Available: kitUltimateScanners, PipelineRun: []string{"SAST"}}
	tenant.scanners[12] = kitScanners{Available: kitUltimateScanners, PipelineRun: []string{}}
	res := runInProcess(trustConfig(), kitSecrets(), newReplay(t, kitResponses(tenant, kitBase)))
	scanners, _ := valueAt(artifactData(t, res, VulnPath), "scanners")
	for i, want := range []bool{false, true, false} {
		entry := scanners.([]any)[i].(map[string]any)
		if entry["enabled"] != want {
			t.Errorf("%s enabled = %v, want %v", entry["scanner"], entry["enabled"], want)
		}
	}
}

// Without GitLab Ultimate the vulnerability report is out of reach, so the
// finding values are left out as not_licensed. Coverage stays.
func TestVulnScanning_PremiumIsNotLicensed(t *testing.T) {
	res := runInProcess(trustConfig(), kitSecrets(), newReplay(t, kitResponses(kitPremiumTenant(), kitBase)))
	if res.ExitCode != 0 {
		t.Fatalf("run failed with exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, pointer := range []string{"/scanners/0/open_critical_present", "/scanners/1/open_high_present", "/scanners/2/overdue_present"} {
		if g := resultGap(res, VulnPath, pointer); g == nil || g.Code != componentsdk.CodeNotLicensed {
			t.Errorf("gap at %s = %+v, want not_licensed", pointer, g)
		}
	}
	if got, _ := valueAt(artifactData(t, res, VulnPath), "scanners"); got.([]any)[0].(map[string]any)["coverage_pct"] != 25.0 {
		t.Errorf("dependency scanning coverage = %v, want 25", got.([]any)[0])
	}
}

// With Ultimate, a token below the Developer role gets the same empty
// answer, and the gap is permission_denied.
func TestVulnScanning_UltimateWithoutTheRoleIsPermissionDenied(t *testing.T) {
	res := runInProcess(trustConfig(), kitSecrets(), newReplay(t, kitMaintainerResponses()))
	g := resultGap(res, VulnPath, "/scanners/0/open_critical_present")
	if g == nil || g.Code != componentsdk.CodePermissionDenied || g.MissingPermission != developerRole {
		t.Errorf("gap = %+v, want permission_denied for the Developer role", g)
	}
}

func TestVulnScanning_TrustLevelHasNoCounts(t *testing.T) {
	res := runInProcess(trustConfig(), kitSecrets(), newReplay(t, kitResponses(kitCleanTenant(), kitBase)))
	scanners, _ := valueAt(artifactData(t, res, VulnPath), "scanners")
	first := scanners.([]any)[0].(map[string]any)
	for _, field := range []string{"resource_count", "scanned_resource_count", "open_critical_count", "overdue_critical_count"} {
		if v, ok := first[field]; ok {
			t.Errorf("%s = %v at trust, want it left out", field, v)
		}
	}
	for field, want := range map[string]any{"coverage_pct": 25.0, "open_critical_present": true, "overdue_present": true, "resources_present": true} {
		if first[field] != want {
			t.Errorf("%s = %v, want %v", field, first[field], want)
		}
	}
}
