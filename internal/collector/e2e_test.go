//go:build e2e
// +build e2e

// End-to-end tests that make real requests to the GitLab API.
//
// Run with:
//
//	go test -tags=e2e -v ./internal/collector/...
//
// Required environment variables:
//
//	GITLAB_TOKEN         group access token with read_api scope
//	GITLAB_E2E_GROUP     group path (e.g. "my-org")
//
// Optional environment variables:
//
//	GITLAB_E2E_LEVEL     trust | audit | internal (default trust)
//	GITLAB_E2E_BASE_URL  base URL for self-managed instances

package collector

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
	"github.com/locktivity/epack/componentsdk"
)

func e2eLevel() componentsdk.Level {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GITLAB_E2E_LEVEL"))) {
	case "audit":
		return componentsdk.LevelAudit
	case "internal":
		return componentsdk.LevelInternal
	default:
		return componentsdk.LevelTrust
	}
}

func getE2EConfig(t *testing.T) (Config, *gitlab.Client) {
	t.Helper()

	token := os.Getenv("GITLAB_TOKEN")
	if token == "" {
		t.Skip("GITLAB_TOKEN not set; skipping e2e test")
	}
	group := strings.TrimSpace(os.Getenv("GITLAB_E2E_GROUP"))
	if group == "" {
		t.Skip("GITLAB_E2E_GROUP not set; skipping e2e test")
	}

	baseURL := strings.TrimSpace(os.Getenv("GITLAB_E2E_BASE_URL"))

	cfg := Config{
		Group:   group,
		BaseURL: baseURL,
	}
	client := gitlab.NewClient(baseURL, token)
	return cfg, client
}

func collectE2E(t *testing.T, level componentsdk.Level) *GroupPosture {
	t.Helper()
	cfg, client := getE2EConfig(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	c := New(cfg, client)
	posture, err := c.Collect(ctx, level)
	if err != nil {
		t.Fatalf("Collect(%s) error: %v", level, err)
	}
	return posture
}

func TestE2E_RealGitLabCollection(t *testing.T) {
	level := e2eLevel()
	posture := collectE2E(t, level)

	if posture.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", posture.SchemaVersion, SchemaVersion)
	}
	if posture.CollectedAtLevel != string(level) {
		t.Errorf("collected_at_level = %q, want %q", posture.CollectedAtLevel, level)
	}
	if _, err := time.Parse(time.RFC3339, posture.CollectedAt); err != nil {
		t.Errorf("collected_at %q is not RFC3339: %v", posture.CollectedAt, err)
	}
	if posture.Group == "" {
		t.Error("group should not be empty")
	}

	assertPercentE2E(t, "posture.branch_protection_coverage", posture.Posture.BranchProtectionCoverage)
	assertPercentE2E(t, "posture.security_features_coverage", posture.Posture.SecurityFeaturesCoverage)
	assertPercentE2E(t, "branch_protection_rules.merge_request_required", posture.BranchProtectionRules.MergeRequestRequired)
	assertPercentE2E(t, "branch_protection_rules.approving_reviews", posture.BranchProtectionRules.ApprovingReviews)
	assertPercentE2E(t, "branch_protection_rules.code_owner_approval", posture.BranchProtectionRules.CodeOwnerApproval)
	assertPercentE2E(t, "branch_protection_rules.no_force_push", posture.BranchProtectionRules.NoForcePush)

	if level >= componentsdk.LevelAudit {
		if posture.Members == nil {
			t.Error("members should be present at audit level")
		}
		if posture.Projects == nil {
			t.Error("projects should be present at audit level")
		}
	}

	data, _ := json.MarshalIndent(posture, "", "  ")
	t.Logf("collection complete at level=%s group=%s\n%s", level, posture.Group, string(data))
}

func TestE2E_OutputValidJSON(t *testing.T) {
	posture := collectE2E(t, e2eLevel())

	data, err := json.Marshal(posture)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	for _, field := range []string{
		"schema_version", "collected_at", "collected_at_level", "group",
		"scope", "posture", "access_control", "branch_protection_rules",
		"security_features",
	} {
		if _, ok := decoded[field]; !ok {
			t.Errorf("missing required top-level field: %s", field)
		}
	}
}

func TestE2E_VCSPostureTransformation(t *testing.T) {
	posture := collectE2E(t, e2eLevel())

	normalized := posture.ToVCSPosture()
	if normalized.Provider != "gitlab" {
		t.Errorf("provider = %q, want gitlab", normalized.Provider)
	}
	if normalized.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", normalized.SchemaVersion, SchemaVersion)
	}

	assertPercentFloatE2E(t, "vcs.branch_protection.pr_required_pct", normalized.BranchProtection.PRRequiredPct)
	assertPercentFloatE2E(t, "vcs.branch_protection.approving_reviews_pct", normalized.BranchProtection.ApprovingReviewsPct)
	assertPercentFloatE2E(t, "vcs.security_features.secret_scanning_pct", normalized.SecurityFeatures.SecretScanningPct)

	data, _ := json.MarshalIndent(normalized, "", "  ")
	t.Logf("VCS posture:\n%s", string(data))
}

func TestE2E_DiagnosticsAreSafe(t *testing.T) {
	posture := collectE2E(t, e2eLevel())

	if posture.Diagnostics == nil {
		t.Log("no diagnostics emitted (all surfaces accessible)")
		return
	}

	for _, msg := range posture.Diagnostics.PermissionErrors {
		if strings.Contains(msg, "glpat-") || strings.Contains(msg, "token") {
			t.Errorf("diagnostic permission_error may contain a secret: %q", msg)
		}
	}
	for _, msg := range posture.Diagnostics.Warnings {
		if strings.Contains(msg, "glpat-") || strings.Contains(msg, "token") {
			t.Errorf("diagnostic warning may contain a secret: %q", msg)
		}
	}

	t.Logf("diagnostics: %d permission_errors, %d warnings",
		len(posture.Diagnostics.PermissionErrors), len(posture.Diagnostics.Warnings))
}

func assertPercentE2E(t *testing.T, name string, v int) {
	t.Helper()
	if v < 0 || v > 100 {
		t.Errorf("%s should be in [0,100], got %d", name, v)
	}
}

func assertPercentFloatE2E(t *testing.T, name string, v float64) {
	t.Helper()
	if v < 0 || v > 100 {
		t.Errorf("%s should be in [0,100], got %v", name, v)
	}
}
