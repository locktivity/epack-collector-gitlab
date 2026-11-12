package collector

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
	"github.com/locktivity/epack/componentsdk"
)

type fakeClient struct {
	group             *gitlab.Group
	groupErr          error
	projects          []gitlab.Project
	projectsErr       error
	protectedBranches map[int][]gitlab.ProtectedBranch
	approvalSettings  map[int]*gitlab.ApprovalSettings
	approvalRules     map[int][]gitlab.ApprovalRule
	members           []gitlab.Member
	membersErr        error
	billable          []gitlab.BillableMember
	billableErr       error
	memberRoles       []gitlab.MemberRole
	memberRolesErr    error
	groupWebhooks     []gitlab.Webhook
	groupWebhooksErr  error
	projectWebhooks   map[int][]gitlab.Webhook
	deployKeys        map[int][]gitlab.DeployKey
	runners           []gitlab.Runner
	runnersErr        error
	auditEvents       []gitlab.AuditEvent
	auditEventsErr    error
	groupTokens       []gitlab.AccessToken
	groupTokensErr    error
	projectTokens     map[int][]gitlab.AccessToken
	projectTokensErr  map[int]error
	scanners          map[int]gitlab.SecurityScanners
	scannersErr       error
	vulns             *gitlab.Vulnerabilities
	vulnsErr          error
}

func (f *fakeClient) GetGroup(_ context.Context, _ string) (*gitlab.Group, error) {
	return f.group, f.groupErr
}

func (f *fakeClient) ListProjects(_ context.Context, _ string) ([]gitlab.Project, error) {
	return f.projects, f.projectsErr
}

func (f *fakeClient) ListProtectedBranches(_ context.Context, projectID int) ([]gitlab.ProtectedBranch, error) {
	if branches, ok := f.protectedBranches[projectID]; ok {
		return branches, nil
	}
	return nil, nil
}

func (f *fakeClient) GetApprovalSettings(_ context.Context, projectID int) (*gitlab.ApprovalSettings, error) {
	if settings, ok := f.approvalSettings[projectID]; ok {
		return settings, nil
	}
	return &gitlab.ApprovalSettings{}, nil
}

func (f *fakeClient) ListApprovalRules(_ context.Context, projectID int) ([]gitlab.ApprovalRule, error) {
	if rules, ok := f.approvalRules[projectID]; ok {
		return rules, nil
	}
	return nil, nil
}

func (f *fakeClient) ListGroupMembers(_ context.Context, _ string) ([]gitlab.Member, error) {
	return f.members, f.membersErr
}

func (f *fakeClient) ListBillableMembers(_ context.Context, _ string) ([]gitlab.BillableMember, error) {
	return f.billable, f.billableErr
}

func (f *fakeClient) ListMemberRoles(_ context.Context, _ string) ([]gitlab.MemberRole, error) {
	return f.memberRoles, f.memberRolesErr
}

func (f *fakeClient) ListGroupWebhooks(_ context.Context, _ string) ([]gitlab.Webhook, error) {
	return f.groupWebhooks, f.groupWebhooksErr
}

func (f *fakeClient) ListProjectWebhooks(_ context.Context, projectID int) ([]gitlab.Webhook, error) {
	if hooks, ok := f.projectWebhooks[projectID]; ok {
		return hooks, nil
	}
	return nil, nil
}

func (f *fakeClient) ListProjectDeployKeys(_ context.Context, projectID int) ([]gitlab.DeployKey, error) {
	if keys, ok := f.deployKeys[projectID]; ok {
		return keys, nil
	}
	return nil, nil
}

func (f *fakeClient) ListGroupRunners(_ context.Context, _ string) ([]gitlab.Runner, error) {
	return f.runners, f.runnersErr
}

func (f *fakeClient) ListGroupAuditEvents(_ context.Context, _ string, _ time.Time) ([]gitlab.AuditEvent, error) {
	return f.auditEvents, f.auditEventsErr
}

func (f *fakeClient) ListGroupAccessTokens(_ context.Context, _ string) ([]gitlab.AccessToken, error) {
	return f.groupTokens, f.groupTokensErr
}

func (f *fakeClient) ListProjectAccessTokens(_ context.Context, projectID int) ([]gitlab.AccessToken, error) {
	return f.projectTokens[projectID], f.projectTokensErr[projectID]
}

func (f *fakeClient) ListSecurityScanners(_ context.Context, projectIDs []int) (map[int]gitlab.SecurityScanners, error) {
	if f.scannersErr != nil {
		return nil, f.scannersErr
	}
	out := map[int]gitlab.SecurityScanners{}
	for _, id := range projectIDs {
		if s, ok := f.scanners[id]; ok {
			out[id] = s
		}
	}
	return out, nil
}

func (f *fakeClient) ListGroupVulnerabilities(_ context.Context, _ string) (*gitlab.Vulnerabilities, error) {
	if f.vulnsErr != nil {
		return nil, f.vulnsErr
	}
	if f.vulns == nil {
		return &gitlab.Vulnerabilities{Readable: true, Items: []gitlab.Vulnerability{}}, nil
	}
	return f.vulns, nil
}

func boolPtr(b bool) *bool { return &b }

func strPtr(s string) *string { return &s }

// wantInt fails unless got holds want.
func wantInt(t *testing.T, name string, got *int, want int) {
	t.Helper()
	if got == nil {
		t.Errorf("%s = null, want %d", name, want)
		return
	}
	if *got != want {
		t.Errorf("%s = %d, want %d", name, *got, want)
	}
}

// gapAt returns the gap recorded at pointer in the detailed artifact.
func gapAt(rec *componentsdk.Recorder, pointer string) *componentsdk.Gap {
	for _, g := range rec.Gaps() {
		if g.Path == DetailedPath && g.Pointer == pointer {
			return &g
		}
	}
	return nil
}

type fakeClientWithBranchErr struct {
	*fakeClient
	branchErr error
}

func (f *fakeClientWithBranchErr) ListProtectedBranches(_ context.Context, _ int) ([]gitlab.ProtectedBranch, error) {
	return nil, f.branchErr
}

type fakeClientWithApprovalErr struct {
	*fakeClient
	approvalSettingsErr error
	approvalRulesErr    error
}

func (f *fakeClientWithApprovalErr) GetApprovalSettings(ctx context.Context, projectID int) (*gitlab.ApprovalSettings, error) {
	if f.approvalSettingsErr == nil {
		return f.fakeClient.GetApprovalSettings(ctx, projectID)
	}
	return nil, f.approvalSettingsErr
}

func (f *fakeClientWithApprovalErr) ListApprovalRules(ctx context.Context, projectID int) ([]gitlab.ApprovalRule, error) {
	if f.approvalRulesErr == nil {
		return f.fakeClient.ListApprovalRules(ctx, projectID)
	}
	return nil, f.approvalRulesErr
}

func TestCollect_TrustLevel_BasicPosture(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{
			ID:                             1,
			Name:                           "test-group",
			RequireTwoFactorAuthentication: boolPtr(true),
		},
		projects: []gitlab.Project{
			{ID: 10, Name: "project-a", DefaultBranch: "main", Visibility: "private", SecretPushProtectionEnabled: boolPtr(true), OnlyAllowMergeIfPipelineSucceeds: boolPtr(true)},
			{ID: 11, Name: "project-b", DefaultBranch: "main", Visibility: "public", SecretPushProtectionEnabled: boolPtr(false), OnlyAllowMergeIfPipelineSucceeds: boolPtr(false)},
		},
		protectedBranches: map[int][]gitlab.ProtectedBranch{
			10: {{Name: "main", AllowForcePush: false, CodeOwnerApprovalRequired: true,
				PushAccessLevels:  []gitlab.BranchAccessLevel{{AccessLevel: 0}},
				MergeAccessLevels: []gitlab.BranchAccessLevel{{AccessLevel: 40}}}},
		},
		approvalSettings: map[int]*gitlab.ApprovalSettings{
			10: {ApprovalsBeforeMerge: 2, ResetApprovalsOnPush: true},
		},
	}

	c := New(Config{Group: "test-group"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.Group != "test-group" {
		t.Errorf("expected group test-group, got %s", posture.Group)
	}
	if posture.CollectedAtLevel != "trust" {
		t.Errorf("expected trust level, got %s", posture.CollectedAtLevel)
	}
	if posture.AccessControl.TwoFactorRequired == nil || !*posture.AccessControl.TwoFactorRequired {
		t.Error("expected 2FA required")
	}
	wantInt(t, "merge_request_required", posture.BranchProtectionRules.MergeRequestRequired, 50)
	wantInt(t, "approving_reviews", posture.BranchProtectionRules.ApprovingReviews, 50)
	wantInt(t, "secret_push_protection", posture.SecurityFeatures.SecretPushProtection, 50)
	wantInt(t, "pipeline_required", posture.SecurityFeatures.PipelineRequired, 50)
	wantInt(t, "security_features_coverage", posture.Posture.SecurityFeaturesCoverage, 50)
	if posture.Members != nil {
		t.Error("trust level should not include members")
	}
	if posture.Projects != nil {
		t.Error("trust level should not include project inventory")
	}
}

func TestCollect_AuditLevel_IncludesInventories(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{
			{ID: 10, Name: "project-a", DefaultBranch: "main", Visibility: "private"},
		},
		protectedBranches: map[int][]gitlab.ProtectedBranch{},
		members: []gitlab.Member{
			{ID: 1, Username: "alice", Name: "Alice", AccessLevel: 50, TwoFactorEnabled: boolPtr(true), State: "active"},
			{ID: 2, Username: "bob", Name: "Bob", AccessLevel: 30, TwoFactorEnabled: boolPtr(false), State: "active"},
		},
		groupWebhooks: []gitlab.Webhook{
			{ID: 100, URL: "https://hooks.example.com/webhook", EnableSSLVerification: true},
		},
		runners: []gitlab.Runner{
			{ID: 200, Description: "runner-1", Status: "online", Online: true, RunnerType: "group_type"},
		},
	}

	c := New(Config{Group: "test-group"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.Members == nil {
		t.Fatal("audit level should include members")
	}
	if posture.Members.TotalCount != 2 {
		t.Errorf("expected 2 members, got %d", posture.Members.TotalCount)
	}
	if posture.Members.OwnerCount != 1 {
		t.Errorf("expected 1 owner, got %d", posture.Members.OwnerCount)
	}

	if posture.Projects == nil {
		t.Fatal("audit level should include projects")
	}
	if posture.Projects.TotalCount != 1 {
		t.Errorf("expected 1 project, got %d", posture.Projects.TotalCount)
	}

	if posture.Webhooks == nil {
		t.Fatal("audit level should include webhooks")
	}
	wantInt(t, "webhooks.group_count", posture.Webhooks.GroupCount, 1)
	if len(posture.Webhooks.Group) != 0 {
		t.Error("audit level should not include webhook detail rows")
	}

	if posture.Runners == nil {
		t.Fatal("audit level should include runners")
	}
	if posture.Runners.GroupRunnerCount != 1 {
		t.Errorf("expected 1 runner, got %d", posture.Runners.GroupRunnerCount)
	}

	if posture.AuditLog != nil {
		t.Error("audit level should not include audit log events")
	}
}

func TestCollect_InternalLevel_IncludesAuditLog(t *testing.T) {
	now := time.Now()
	client := &fakeClient{
		group:    &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{},
		auditEvents: []gitlab.AuditEvent{
			{ID: 1, Details: gitlab.AuditEventDetails{CustomMessage: "member_added", AuthorName: "admin"}, CreatedAt: &now},
		},
	}

	c := New(Config{Group: "test-group"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if posture.AuditLog == nil {
		t.Fatal("internal level should include audit log")
	}
	if len(posture.AuditLog.Events) != 1 {
		t.Errorf("expected 1 audit event, got %d", len(posture.AuditLog.Events))
	}
}

func TestCollect_ProjectFiltering(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{
			{ID: 10, Name: "backend-api", DefaultBranch: "main", Visibility: "private"},
			{ID: 11, Name: "frontend-app", DefaultBranch: "main", Visibility: "private"},
			{ID: 12, Name: "docs", DefaultBranch: "main", Visibility: "public"},
		},
		protectedBranches: map[int][]gitlab.ProtectedBranch{},
	}

	c := New(Config{
		Group:           "test-group",
		IncludePatterns: []string{"backend-*"},
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantInt(t, "projects_coverage", posture.Scope.ProjectsCoverage, 33)
	wantInt(t, "project_count", posture.Scope.ProjectCount, 3)
	wantInt(t, "included_project_count", posture.Scope.IncludedProjectCount, 1)
}

func TestCollect_ExcludePatterns(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{
			{ID: 10, Name: "backend-api", DefaultBranch: "main", Visibility: "private"},
			{ID: 11, Name: "archived-old", DefaultBranch: "main", Visibility: "private"},
		},
		protectedBranches: map[int][]gitlab.ProtectedBranch{},
	}

	c := New(Config{
		Group:           "test-group",
		ExcludePatterns: []string{"archived-*"},
	}, client)

	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantInt(t, "projects_coverage", posture.Scope.ProjectsCoverage, 50)
}

func TestCollect_GroupError_ReturnsError(t *testing.T) {
	client := &fakeClient{
		groupErr: &gitlab.APIError{StatusCode: 500, Message: "500 Internal Server Error"},
	}

	c := New(Config{Group: "test-group"}, client)
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if got := componentsdk.Classify(err); got != componentsdk.CodeVendorError {
		t.Fatalf("code = %s (%v), want the sign-in to fail with vendor_error", got, err)
	}
}

func TestCollect_EmptyGroup(t *testing.T) {
	c := New(Config{}, &fakeClient{})
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("expected error for empty group")
	}
}

func TestCollect_Unauthorized_ReturnsError(t *testing.T) {
	client := &fakeClient{
		groupErr: &gitlab.APIError{StatusCode: 401, Message: "401 Unauthorized"},
	}

	c := New(Config{Group: "test-group"}, client)
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if got := componentsdk.Classify(err); got != componentsdk.CodeAuthFailed {
		t.Errorf("code = %s (%v), want auth_failed", got, err)
	}
}

func TestMatchingProtectionRules_ExactAndWildcard(t *testing.T) {
	branches := []gitlab.ProtectedBranch{
		{Name: "*"},
		{Name: "main"},
	}
	result := matchingProtectionRules(branches, "main")
	if len(result) != 2 {
		t.Errorf("expected 2 matching rules, got %d", len(result))
	}
}

func TestMatchingProtectionRules_NoMatch(t *testing.T) {
	branches := []gitlab.ProtectedBranch{
		{Name: "release-*"},
	}
	result := matchingProtectionRules(branches, "main")
	if len(result) != 0 {
		t.Errorf("expected 0 matching rules, got %d", len(result))
	}
}

func TestOverlappingRules_PermissiveWins(t *testing.T) {
	branches := []gitlab.ProtectedBranch{
		{Name: "main", AllowForcePush: false,
			PushAccessLevels: []gitlab.BranchAccessLevel{{AccessLevel: 0}},
		},
		{Name: "m*", AllowForcePush: true,
			PushAccessLevels: []gitlab.BranchAccessLevel{{AccessLevel: 30}},
		},
	}

	c := New(Config{Group: "test"}, &fakeClient{})
	detail := c.analyzeProtection(branches, "main")
	if detail == nil {
		t.Fatal("expected non-nil protection detail")
	}
	if !detail.AllowForcePush {
		t.Error("expected force push allowed when any matching rule allows it")
	}
	if detail.MergeRequestRequired {
		t.Error("expected MR not required when a matching rule grants push access")
	}
}

func TestIsMRRequired_NoOnePush(t *testing.T) {
	levels := []gitlab.BranchAccessLevel{{AccessLevel: 0}}
	if !isMRRequired(levels) {
		t.Error("expected MR required when push access_level=0 with no grants")
	}
}

// A rule whose push selections were all cleared has an empty
// push_access_levels list, and no one can push.
func TestIsMRRequired_NoPushAccessLevels(t *testing.T) {
	var branch gitlab.ProtectedBranch
	body := `{"id":1,"name":"main","push_access_levels":[],"merge_access_levels":[{"id":2,"access_level":40}]}`
	if err := json.Unmarshal([]byte(body), &branch); err != nil {
		t.Fatal(err)
	}
	client := &fakeClient{
		group:             &gitlab.Group{ID: 1, Name: "test-group", FullPath: "test-group"},
		projects:          []gitlab.Project{{ID: 10, Name: "svc", Visibility: "private", DefaultBranch: "main"}},
		protectedBranches: map[int][]gitlab.ProtectedBranch{10: {branch}},
	}
	posture, err := New(Config{Group: "test-group"}, client).Collect(t.Context(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatal(err)
	}
	wantInt(t, "merge_request_required", posture.BranchProtectionRules.MergeRequestRequired, 100)
	vcs := posture.ToVCSPosture()
	if p := vcs.BranchProtection.PRRequiredPct; !p.Read || p.Value == nil || *p.Value != 100 {
		t.Errorf("pr_required_pct = %+v, want 100", p)
	}
	wantInt(t, "pr_required_repository_count", vcs.BranchProtection.PRRequiredRepositoryCount, 1)
}

func TestIsMRRequired_DeveloperPush(t *testing.T) {
	levels := []gitlab.BranchAccessLevel{{AccessLevel: 30}}
	if isMRRequired(levels) {
		t.Error("expected MR not required when developers can push")
	}
}

func TestIsMRRequired_UserGrant(t *testing.T) {
	userID := 42
	levels := []gitlab.BranchAccessLevel{{AccessLevel: 0, UserID: &userID}}
	if isMRRequired(levels) {
		t.Error("expected MR not required when individual user can push")
	}
}

func TestMatchesWildcard(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*", "main", true},
		{"*", "", true},
		{"main", "main", true},
		{"main", "develop", false},
		{"m*", "main", true},
		{"m*", "develop", false},
		{"*gitlab*", "gitlab", true},
		{"*gitlab*", "gitlab/staging", true},
		{"*gitlab*", "my-gitlab-repo", true},
		{"*gitlab*", "other", false},
		{"main*main", "main", false},
		{"main*main", "mainXmain", true},
		{"release-*", "release-v1", true},
		{"release-*", "main", false},
	}
	for _, tt := range tests {
		got := matchesWildcard(tt.pattern, tt.name)
		if got != tt.want {
			t.Errorf("matchesWildcard(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}

func TestRuleAppliesToBranch(t *testing.T) {
	rule := gitlab.ApprovalRule{
		ApprovalsRequired: 2,
		ProtectedBranches: []gitlab.ApprovalRuleBranch{
			{Name: "release-*"},
		},
	}
	if ruleAppliesToBranch(rule, "main", true) {
		t.Error("rule scoped to release-* should not apply to main")
	}
	if !ruleAppliesToBranch(rule, "release-v1", true) {
		t.Error("rule scoped to release-* should apply to release-v1")
	}

	globalRule := gitlab.ApprovalRule{ApprovalsRequired: 1}
	if !ruleAppliesToBranch(globalRule, "main", true) {
		t.Error("rule with no branch scope should apply to all branches")
	}
}

func TestDiagnostics_TrustLevel_NoProjectNamesOrIDs(t *testing.T) {
	const projectID = 4815162342
	for level, want := range map[componentsdk.Level]string{
		componentsdk.LevelTrust: "surface protected_branches skipped: a project: fetch failed",
		componentsdk.LevelAudit: "surface protected_branches skipped: project secret-project: fetch failed",
	} {
		client := &fakeClientWithBranchErr{
			fakeClient: &fakeClient{
				group:             &gitlab.Group{ID: 1, Name: "test-group"},
				projects:          []gitlab.Project{{ID: projectID, Name: "secret-project", DefaultBranch: "main", Visibility: "private"}},
				protectedBranches: map[int][]gitlab.ProtectedBranch{},
			},
			branchErr: &gitlab.APIError{StatusCode: 500, Message: "500 Internal Server Error"},
		}
		c := New(Config{Group: "test-group"}, client)
		posture, err := c.Collect(context.Background(), level)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", level, err)
		}
		if posture.Diagnostics == nil || !slices.Contains(posture.Diagnostics.Warnings, want) {
			t.Fatalf("%s: diagnostics = %+v, want the warning %q", level, posture.Diagnostics, want)
		}
		if level != componentsdk.LevelTrust {
			continue
		}
		for _, w := range append(posture.Diagnostics.Warnings, posture.ToVCSPosture().UnavailableSources...) {
			if strings.Contains(w, "secret-project") || strings.Contains(w, strconv.Itoa(projectID)) {
				t.Errorf("trust-level diagnostic names the project: %s", w)
			}
		}
	}
}

// Below the audit level, a group configured by its numeric ID is named by
// its full path in both artifacts, and left out of both with a gap when
// GitLab sends no full path. From the audit level, the configured ID stays.
func TestNumericGroupIsNamedByItsPathBelowAudit(t *testing.T) {
	const id = "90817263"
	cases := []struct {
		name         string
		level        componentsdk.Level
		fullPath     string
		group, org   string
		leftOut      bool
		configuredAs string
	}{
		{name: "trust", level: componentsdk.LevelTrust, fullPath: "acme/platform", group: "acme/platform", org: "acme/platform", configuredAs: id},
		{name: "trust without a full path", level: componentsdk.LevelTrust, group: "", org: "", leftOut: true, configuredAs: id},
		{name: "trust with a path", level: componentsdk.LevelTrust, fullPath: "acme/platform", group: "acme/platform", org: "acme/platform", configuredAs: "acme/platform"},
		{name: "audit", level: componentsdk.LevelAudit, fullPath: "acme/platform", group: id, org: "acme/platform", configuredAs: id},
		{name: "audit without a full path", level: componentsdk.LevelAudit, group: id, org: id, configuredAs: id},
		{name: "internal", level: componentsdk.LevelInternal, fullPath: "acme/platform", group: id, org: "acme/platform", configuredAs: id},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &componentsdk.Recorder{}
			client := &fakeClient{group: &gitlab.Group{ID: 90817263, Name: "Platform", FullPath: tc.fullPath}}
			c := New(Config{Group: tc.configuredAs, Recorder: rec}, client)
			posture, err := c.Collect(context.Background(), tc.level)
			if err != nil {
				t.Fatal(err)
			}
			vcs := posture.ToVCSPosture()
			if posture.Group != tc.group || vcs.Organization != tc.org {
				t.Errorf("group = %q and organization = %q, want %q and %q", posture.Group, vcs.Organization, tc.group, tc.org)
			}
			raw, err := json.Marshal([]any{posture, vcs})
			if err != nil {
				t.Fatal(err)
			}
			if !tc.level.AtLeast(componentsdk.LevelAudit) && strings.Contains(string(raw), id) {
				t.Errorf("a %s run wrote the group ID: %s", tc.level, raw)
			}
			gap := gapAt(rec, "/group")
			if tc.leftOut != (gap != nil) || (gap != nil && gap.Code != componentsdk.CodeInvalidResponse) {
				t.Errorf("gap at /group = %+v, want one with invalid_response: %v", gap, tc.leftOut)
			}
		})
	}
}

func TestApprovalPermissionDenied_EmitsDiagnostic(t *testing.T) {
	denied := &gitlab.APIError{StatusCode: 403, Message: "403 Forbidden"}
	client := &fakeClientWithApprovalErr{
		fakeClient: &fakeClient{
			group: &gitlab.Group{ID: 1, Name: "test-group"},
			projects: []gitlab.Project{
				{ID: 10, Name: "proj", DefaultBranch: "main", Visibility: "private"},
			},
			protectedBranches: map[int][]gitlab.ProtectedBranch{},
		},
		approvalSettingsErr: denied,
		approvalRulesErr:    denied,
	}

	c := New(Config{Group: "test-group"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Diagnostics == nil {
		t.Fatal("expected diagnostics when approval endpoints are denied")
	}
	found := false
	for _, pe := range posture.Diagnostics.PermissionErrors {
		if strings.Contains(pe, "approvals") && strings.Contains(pe, "inaccessible") {
			found = true
		}
	}
	if !found {
		t.Error("expected permission error diagnostic for inaccessible approval endpoints")
	}
}

func TestCodeOwner_OR_Semantics(t *testing.T) {
	branches := []gitlab.ProtectedBranch{
		{Name: "main", CodeOwnerApprovalRequired: true},
		{Name: "m*", CodeOwnerApprovalRequired: false},
	}

	c := New(Config{Group: "test"}, &fakeClient{})
	detail := c.analyzeProtection(branches, "main")
	if detail == nil {
		t.Fatal("expected non-nil protection detail")
	}
	if !detail.CodeOwnerApprovalRequired {
		t.Error("expected code owner approval required when any matching rule enables it")
	}
}

func TestApprovalRule_AppliesToAllProtectedBranches_Protected(t *testing.T) {
	rule := gitlab.ApprovalRule{
		ApprovalsRequired:             2,
		AppliesToAllProtectedBranches: true,
	}
	if !ruleAppliesToBranch(rule, "main", true) {
		t.Error("rule with applies_to_all_protected_branches should apply to protected main")
	}
}

func TestApprovalRule_AppliesToAllProtectedBranches_Unprotected(t *testing.T) {
	rule := gitlab.ApprovalRule{
		ApprovalsRequired:             2,
		AppliesToAllProtectedBranches: true,
	}
	if ruleAppliesToBranch(rule, "main", false) {
		t.Error("rule with applies_to_all_protected_branches should NOT apply to unprotected main")
	}
}

func TestApprovalRule_ScopedToRelease_EmptyProtectedBranches_NotGlobal(t *testing.T) {
	rule := gitlab.ApprovalRule{
		ApprovalsRequired:             2,
		AppliesToAllProtectedBranches: false,
		ProtectedBranches: []gitlab.ApprovalRuleBranch{
			{Name: "release-*"},
		},
	}
	if ruleAppliesToBranch(rule, "main", true) {
		t.Error("rule scoped to release-* with applies_to_all=false should not apply to main")
	}
}

func TestApprovalCoverage_UnprotectedDefaultBranch(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{
			{ID: 10, Name: "proj-a", DefaultBranch: "main", Visibility: "private"},
		},
		protectedBranches: map[int][]gitlab.ProtectedBranch{
			10: {{Name: "release-*",
				PushAccessLevels: []gitlab.BranchAccessLevel{{AccessLevel: 0}},
			}},
		},
		approvalRules: map[int][]gitlab.ApprovalRule{
			10: {{
				ApprovalsRequired:             2,
				AppliesToAllProtectedBranches: true,
			}},
		},
	}

	c := New(Config{Group: "test-group"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantInt(t, "approving_reviews (unprotected default branch)", posture.BranchProtectionRules.ApprovingReviews, 0)
}

func TestPartialApprovalFailure_EmitsDiagnostic(t *testing.T) {
	denied := &gitlab.APIError{StatusCode: 403, Message: "403 Forbidden"}
	client := &fakeClientWithApprovalErr{
		fakeClient: &fakeClient{
			group: &gitlab.Group{ID: 1, Name: "test-group"},
			projects: []gitlab.Project{
				{ID: 10, Name: "proj", DefaultBranch: "main", Visibility: "private"},
			},
			protectedBranches: map[int][]gitlab.ProtectedBranch{},
		},
		approvalSettingsErr: nil,
		approvalRulesErr:    denied,
	}

	c := New(Config{Group: "test-group"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Diagnostics == nil {
		t.Fatal("expected diagnostics when one approval endpoint is denied")
	}
	found := false
	for _, pe := range posture.Diagnostics.PermissionErrors {
		if strings.Contains(pe, "approval_rules") {
			found = true
		}
	}
	if !found {
		t.Error("expected permission error for inaccessible approval rules endpoint")
	}
}

func TestMember2FA_NilPreserved(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{
			{ID: 10, Name: "proj", DefaultBranch: "main", Visibility: "private"},
		},
		protectedBranches: map[int][]gitlab.ProtectedBranch{},
		members: []gitlab.Member{
			{ID: 1, Username: "alice", AccessLevel: 30, TwoFactorEnabled: nil, State: "active"},
		},
	}

	c := New(Config{Group: "test-group"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Members == nil || len(posture.Members.PerMember) == 0 {
		t.Fatal("expected member rows")
	}
	if posture.Members.PerMember[0].TwoFactorEnabled != nil {
		t.Error("expected nil 2FA status to be preserved, not defaulted to false")
	}
}

func TestSafeDiagError(t *testing.T) {
	apiErr := &gitlab.APIError{StatusCode: 500, Message: "sensitive internal error details"}
	msg := safeDiagError(apiErr)
	if strings.Contains(msg, "sensitive") {
		t.Errorf("safeDiagError leaked API body: %s", msg)
	}
	if msg != "HTTP 500" {
		t.Errorf("expected 'HTTP 500', got %s", msg)
	}
}

func TestToVCSPosture(t *testing.T) {
	posture := &GroupPosture{
		Group:       "test-group",
		CollectedAt: "2026-10-17T12:00:00Z",
		Scope:       Scope{ProjectsCoverage: intPtr(100)},
		AccessControl: AccessControl{
			TwoFactorRequired: boolPtr(true),
		},
		BranchProtectionRules: BranchProtectionRules{
			MergeRequestRequired: intPtr(80),
			ApprovingReviews:     intPtr(60),
		},
		SecurityFeatures: SecurityFeatures{
			SecretPushProtection: intPtr(50),
			PipelineRequired:     intPtr(70),
		},
	}

	vcs := posture.ToVCSPosture()
	if vcs.Provider != "gitlab" {
		t.Errorf("expected provider gitlab, got %s", vcs.Provider)
	}
	if vcs.Organization != "test-group" {
		t.Errorf("expected org test-group, got %s", vcs.Organization)
	}
	if vcs.CollectedAt != posture.CollectedAt {
		t.Errorf("collected_at = %s, want the detailed artifact's %s", vcs.CollectedAt, posture.CollectedAt)
	}
	if p := vcs.BranchProtection.PRRequiredPct.Value; p == nil || *p != 80 {
		t.Errorf("expected 80%% PR required, got %v", p)
	}
	if p := vcs.BranchProtection.StatusChecksPct.Value; p == nil || *p != 70 {
		t.Errorf("expected 70%% status checks, got %v", p)
	}
}

// The group setting can be a numeric ID. The organization is then the
// group's full path from GitLab, and the detailed group stays as configured.
func TestToVCSPosture_OrganizationIsTheGroupPath(t *testing.T) {
	client := &fakeClient{group: &gitlab.Group{ID: 7, Name: "Acme", FullPath: "acme"}}
	posture, err := New(Config{Group: "7"}, client).Collect(t.Context(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatal(err)
	}
	if org := posture.ToVCSPosture().Organization; org != "acme" {
		t.Errorf("organization = %q, want the full path acme", org)
	}
	if posture.Group != "7" {
		t.Errorf("group = %q, want the configured 7", posture.Group)
	}
}

func TestToVCSPosture_LeavesUnknownValuesOut(t *testing.T) {
	vcs := (&GroupPosture{Group: "test-group"}).ToVCSPosture()
	if vcs.RepoCoveragePct.Read || vcs.RepositoriesPresent != nil || vcs.BranchProtection != (VCSPostureBranchProtection{}) {
		t.Errorf("vcs posture = %+v, want every unknown value absent rather than false or 0", vcs)
	}
}

func TestSurface401_LeavesTheSurfaceOut(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{
			{ID: 10, Name: "project-a", DefaultBranch: "main", Visibility: "private"},
		},
		protectedBranches: map[int][]gitlab.ProtectedBranch{},
		membersErr:        &gitlab.APIError{StatusCode: 401, Message: "401 Unauthorized"},
	}

	rec := &componentsdk.Recorder{}
	c := New(Config{Group: "test-group", Recorder: rec}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("a 401 after the sign-in failed the run: %v", err)
	}
	if posture.Members != nil {
		t.Errorf("members = %+v, want them left out", posture.Members)
	}
	if g := gapAt(rec, "/members"); g == nil || g.Code != componentsdk.CodeAuthFailed {
		t.Errorf("gap at /members = %+v, want auth_failed", g)
	}
}

func TestDiagnostics_DoNotCarryGitLabMessages(t *testing.T) {
	client := &fakeClient{
		group:       &gitlab.Group{ID: 1, Name: "test-group"},
		projectsErr: &gitlab.APIError{StatusCode: 500, Message: "sensitive database trace"},
	}

	c := New(Config{Group: "test-group"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Diagnostics == nil || len(posture.Diagnostics.Warnings) == 0 {
		t.Fatal("expected a diagnostic for the failed project list")
	}
	for _, w := range posture.Diagnostics.Warnings {
		if strings.Contains(w, "sensitive") {
			t.Errorf("diagnostic leaked GitLab's message: %s", w)
		}
	}
}

func intPtr(n int) *int { return &n }

func TestIsMRRequired_CustomRoleGrant(t *testing.T) {
	levels := []gitlab.BranchAccessLevel{
		{AccessLevel: 0, MemberRoleID: intPtr(42)},
	}
	if isMRRequired(levels) {
		t.Error("custom-role push grant should not be treated as 'No one'")
	}
}

func TestIsMRRequired_MixedCustomRoleAndNoOne(t *testing.T) {
	levels := []gitlab.BranchAccessLevel{
		{AccessLevel: 0},
		{AccessLevel: 0, MemberRoleID: intPtr(7)},
	}
	if isMRRequired(levels) {
		t.Error("mixed grants with custom role should allow direct push")
	}
}

func TestSecretPushProtection_NilLeavesTheRollupOut(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{
			{ID: 10, Name: "project-a", DefaultBranch: "main", Visibility: "private", SecretPushProtectionEnabled: boolPtr(true), OnlyAllowMergeIfPipelineSucceeds: boolPtr(true)},
			{ID: 11, Name: "project-b", DefaultBranch: "main", Visibility: "private", OnlyAllowMergeIfPipelineSucceeds: boolPtr(false)},
		},
		protectedBranches: map[int][]gitlab.ProtectedBranch{},
	}

	rec := &componentsdk.Recorder{}
	c := New(Config{Group: "test-group", Recorder: rec}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := posture.SecurityFeatures.SecretPushProtection; got != nil {
		t.Errorf("secret_push_protection = %d, want it left out rather than counting the unreported project as disabled", *got)
	}
	g := gapAt(rec, "/security_features/secret_push_protection")
	if g == nil || g.Status != componentsdk.GapPartial || g.Unmeasured != 1 || g.Code != componentsdk.CodePermissionDenied {
		t.Errorf("gap = %+v, want partial permission_denied with 1 unmeasured", g)
	}
	if g := gapAt(rec, "/posture/security_features_coverage"); g == nil || g.Unmeasured != 1 {
		t.Errorf("security_features_coverage gap = %+v, want partial with 1 unmeasured", g)
	}
	wantInt(t, "pipeline_required", posture.SecurityFeatures.PipelineRequired, 50)
	if posture.Diagnostics == nil {
		t.Fatal("expected diagnostics when secret push protection status is unknown for some projects")
	}
	found := false
	for _, w := range posture.Diagnostics.Warnings {
		if strings.Contains(w, "secret_push_protection") && strings.Contains(w, "1 of 2") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected diagnostic about unknown secret push protection, got: %v", posture.Diagnostics.Warnings)
	}
}

func TestSecretPushProtection_MissingEverywhereIsNotLicensed(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{
			{ID: 10, Name: "project-a", Visibility: "private", OnlyAllowMergeIfPipelineSucceeds: boolPtr(true)},
			{ID: 11, Name: "project-b", Visibility: "private", OnlyAllowMergeIfPipelineSucceeds: boolPtr(false)},
		},
	}

	rec := &componentsdk.Recorder{}
	if _, err := New(Config{Group: "test-group", Recorder: rec}, client).Collect(context.Background(), componentsdk.LevelTrust); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if g := gapAt(rec, "/security_features/secret_push_protection"); g == nil || g.Code != componentsdk.CodeNotLicensed || g.Unmeasured != 2 {
		t.Errorf("gap = %+v, want not_licensed with 2 unmeasured", g)
	}
}

func TestGroupRead403_FailsTheRun(t *testing.T) {
	client := &fakeClient{
		groupErr: &gitlab.APIError{StatusCode: 403, Code: "insufficient_scope"},
		projects: []gitlab.Project{},
	}

	c := New(Config{Group: "test-group"}, client)
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if got := componentsdk.Classify(err); got != componentsdk.CodePermissionDenied {
		t.Errorf("code = %s (%v), want the sign-in to fail with permission_denied", got, err)
	}
}

func TestGroupNotFound_IsAConfigError(t *testing.T) {
	client := &fakeClient{groupErr: &gitlab.APIError{StatusCode: 404, Message: "404 Group Not Found"}}

	_, err := New(Config{Group: "no-such-group"}, client).Collect(context.Background(), componentsdk.LevelTrust)
	if got := componentsdk.Classify(err); got != componentsdk.CodeConfigInvalid {
		t.Errorf("code = %s (%v), want config_invalid", got, err)
	}
}

func TestFailedProjectList_LeavesProjectValuesOut(t *testing.T) {
	client := &fakeClient{
		group:         &gitlab.Group{ID: 1, Name: "test-group", RequireTwoFactorAuthentication: boolPtr(true), ProjectCreationLevel: strPtr("maintainer"), ShareWithGroupLock: boolPtr(false)},
		projectsErr:   &gitlab.APIError{StatusCode: 502},
		members:       []gitlab.Member{},
		groupWebhooks: []gitlab.Webhook{},
		runners:       []gitlab.Runner{},
	}

	rec := &componentsdk.Recorder{}
	posture, err := New(Config{Group: "test-group", Recorder: rec}, client).Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("a failed project list failed the run: %v", err)
	}
	if posture.Scope.ProjectsCoverage != nil || posture.Posture.BranchProtectionCoverage != nil || posture.BranchProtectionRules.ApprovingReviews != nil {
		t.Errorf("posture = %+v, want project values left out rather than 0", posture)
	}
	if posture.Projects != nil || posture.DeployKeys != nil || posture.Webhooks.ProjectCount != nil {
		t.Error("project inventories should be left out with the project list")
	}
	for _, pointer := range []string{"/scope/included_project_count", "/branch_protection_rules/no_force_push", "/projects", "/deploy_keys", "/webhooks/project_count"} {
		if g := gapAt(rec, pointer); g == nil || g.Code != componentsdk.CodeVendorError {
			t.Errorf("gap at %s = %+v, want vendor_error", pointer, g)
		}
	}
	wantInt(t, "webhooks.group_count", posture.Webhooks.GroupCount, 0)
}

func TestApprovalRulesFailure_KeepsAKnownApproval(t *testing.T) {
	client := &fakeClientWithApprovalErr{
		fakeClient: &fakeClient{
			group: &gitlab.Group{ID: 1, Name: "test-group"},
			projects: []gitlab.Project{
				{ID: 10, Name: "needs-two", DefaultBranch: "main", Visibility: "private"},
				{ID: 11, Name: "needs-none", DefaultBranch: "main", Visibility: "private"},
			},
			approvalSettings: map[int]*gitlab.ApprovalSettings{10: {ApprovalsBeforeMerge: 2}},
		},
		approvalRulesErr: &gitlab.APIError{StatusCode: 500},
	}

	rec := &componentsdk.Recorder{}
	posture, err := New(Config{Group: "test-group", Recorder: rec}, client).Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	g := gapAt(rec, "/branch_protection_rules/approving_reviews")
	if posture.BranchProtectionRules.ApprovingReviews != nil || g == nil || g.Unmeasured != 1 || g.Code != componentsdk.CodeVendorError {
		t.Errorf("approving_reviews = %v with gap %+v; want it left out, with only the project that needs no approval unmeasured", posture.BranchProtectionRules.ApprovingReviews, g)
	}
	for i := range posture.Projects.PerProject {
		if posture.Projects.PerProject[i].ApprovalSettings != nil || gapAt(rec, rowPointer("/projects/per_project", i, "approval_settings")) == nil {
			t.Errorf("row %d approval_settings should be left out with a gap, since the rules could require more", i)
		}
	}
}

func TestProtectedBranchFailure_LeavesRollupsOut(t *testing.T) {
	client := &fakeClientWithBranchErr{
		fakeClient: &fakeClient{
			group:    &gitlab.Group{ID: 1, Name: "test-group"},
			projects: []gitlab.Project{{ID: 10, Name: "proj", DefaultBranch: "main", Visibility: "private"}},
		},
		branchErr: &gitlab.APIError{StatusCode: 429},
	}

	rec := &componentsdk.Recorder{}
	posture, err := New(Config{Group: "test-group", Recorder: rec}, client).Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, pointer := range []string{"/posture/branch_protection_coverage", "/branch_protection_rules/merge_request_required", "/branch_protection_rules/approving_reviews", "/projects/per_project/0/branch_protection", "/projects/per_project/0/approval_settings"} {
		if g := gapAt(rec, pointer); g == nil || g.Code != componentsdk.CodeRateLimited {
			t.Errorf("gap at %s = %+v, want rate_limited", pointer, g)
		}
	}
	if posture.Posture.BranchProtectionCoverage != nil {
		t.Errorf("branch_protection_coverage = %d, want it left out", *posture.Posture.BranchProtectionCoverage)
	}
}

func TestNoProjects_PercentagesAreNull(t *testing.T) {
	client := &fakeClient{group: &gitlab.Group{ID: 1, Name: "test-group"}, projects: []gitlab.Project{}}

	rec := &componentsdk.Recorder{}
	posture, err := New(Config{Group: "test-group", Recorder: rec}, client).Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Scope.ProjectsCoverage != nil || posture.Posture.SecurityFeaturesCoverage != nil || posture.BranchProtectionRules.MergeRequestRequired != nil {
		t.Errorf("posture = %+v, want percentages over no projects null", posture)
	}
	wantInt(t, "project_count", posture.Scope.ProjectCount, 0)
	for _, g := range rec.Gaps() {
		if strings.HasPrefix(g.Pointer, "/scope") || strings.HasPrefix(g.Pointer, "/posture") {
			t.Errorf("an empty population is an answer, not a gap: %+v", g)
		}
	}
}

func TestToVCSPosture_StaticUnavailableMarkers(t *testing.T) {
	posture := &GroupPosture{
		Group: "test-group",
		Scope: Scope{ProjectsCoverage: intPtr(100)},
		AccessControl: AccessControl{
			TwoFactorRequired: boolPtr(true),
		},
	}

	vcs := posture.ToVCSPosture()
	expectedMarkers := []string{"signed_commits"}
	for _, marker := range expectedMarkers {
		found := false
		for _, u := range vcs.UnavailableSources {
			if strings.Contains(u, marker) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected unavailable marker for %s, got: %v", marker, vcs.UnavailableSources)
		}
	}
}

// The push rules API has reject_unsigned_commits on Premium and above. The
// entry names what is not collected.
func TestToVCSPosture_SignedCommitsMarkerNamesThePushRule(t *testing.T) {
	vcs := (&GroupPosture{Group: "test-group"}).ToVCSPosture()
	want := "signed_commits: the reject_unsigned_commits push rule is not collected"
	if !slices.Contains(vcs.UnavailableSources, want) {
		t.Errorf("unavailable_sources = %v, want %q", vcs.UnavailableSources, want)
	}
}

func TestInvalidExcludePattern_ReturnsError(t *testing.T) {
	client := &fakeClient{
		group:    &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{},
	}

	c := New(Config{Group: "test-group", ExcludePatterns: []string{"["}}, client)
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("expected error for invalid exclude pattern")
	}
	if !strings.Contains(err.Error(), "exclude_patterns") {
		t.Errorf("expected exclude_patterns in error, got: %v", err)
	}
	if got := componentsdk.Classify(err); got != componentsdk.CodeConfigInvalid {
		t.Errorf("code = %s, want config_invalid", got)
	}
}

func TestInvalidIncludePattern_ReturnsError(t *testing.T) {
	client := &fakeClient{
		group:    &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{},
	}

	c := New(Config{Group: "test-group", IncludePatterns: []string{"[bad"}}, client)
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("expected error for invalid include pattern")
	}
	if !strings.Contains(err.Error(), "include_patterns") {
		t.Errorf("expected include_patterns in error, got: %v", err)
	}
}

func TestEmptyRepo_NoFalsePositiveBranchProtection(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{
			{ID: 10, Name: "empty-repo", DefaultBranch: "", Visibility: "private"},
		},
		protectedBranches: map[int][]gitlab.ProtectedBranch{
			10: {{Name: "*", AllowForcePush: false,
				PushAccessLevels: []gitlab.BranchAccessLevel{{AccessLevel: 0}}}},
		},
	}

	c := New(Config{Group: "test-group"}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantInt(t, "merge_request_required (empty repo)", posture.BranchProtectionRules.MergeRequestRequired, 0)
	wantInt(t, "branch_protection_coverage (empty repo)", posture.Posture.BranchProtectionCoverage, 0)
}

func TestCancellation_FailsTheSignIn(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a canceled run reached GitLab")
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := New(Config{Group: "test-group"}, gitlab.NewClient(srv.Client(), srv.URL, "test-token"))
	_, err := c.Collect(ctx, componentsdk.LevelTrust)
	if got := componentsdk.Classify(err); got != componentsdk.CodeTimeout {
		t.Fatalf("code = %s (%v), want timeout", got, err)
	}
}

func TestGroupWithoutSettings_LeavesThemOut(t *testing.T) {
	client := &fakeClient{
		group:    &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{},
		members:  []gitlab.Member{},
	}

	rec := &componentsdk.Recorder{}
	c := New(Config{Group: "test-group", Recorder: rec}, client)
	posture, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.AccessControl != (AccessControl{}) {
		t.Errorf("access_control = %+v, want every unreported setting left out rather than false", posture.AccessControl)
	}
	for _, pointer := range []string{"/access_control/two_factor_required", "/access_control/project_creation_level", "/access_control/share_with_group_lock"} {
		if g := gapAt(rec, pointer); g == nil || g.Code != componentsdk.CodeInvalidResponse {
			t.Errorf("gap at %s = %+v, want invalid_response", pointer, g)
		}
	}
}

func TestTwoFactorRequired_AncestorGroup(t *testing.T) {
	tests := []struct {
		name          string
		own, ancestor *bool
		want          bool
	}{
		{"required by an ancestor", boolPtr(false), boolPtr(true), true},
		{"required by the group", boolPtr(true), boolPtr(false), true},
		{"required nowhere", boolPtr(false), boolPtr(false), false},
		{"GitLab before 19.6", boolPtr(false), nil, false},
		{"ancestor only", nil, boolPtr(true), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeClient{
				group: &gitlab.Group{ID: 8, Name: "platform", RequireTwoFactorAuthentication: tt.own, RequireTwoFactorFromAncestor: tt.ancestor},
			}
			rec := &componentsdk.Recorder{}
			posture, err := New(Config{Group: "acme/platform", Recorder: rec}, client).Collect(context.Background(), componentsdk.LevelTrust)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := posture.AccessControl.TwoFactorRequired; got == nil || *got != tt.want {
				t.Errorf("two_factor_required = %v, want %v", got, tt.want)
			}
			if g := gapAt(rec, "/access_control/two_factor_required"); g != nil {
				t.Errorf("gap at two_factor_required = %+v, want none", g)
			}
		})
	}
}

// Rules from merge request approval policies and Coverage-Check need
// approval only when their condition is met. An any_merge_request policy
// applies to every merge request.
func TestApprovalRule_ConditionalRulesDoNotCount(t *testing.T) {
	tests := []struct {
		name string
		rule gitlab.ApprovalRule
		want int
	}{
		{"regular rule", gitlab.ApprovalRule{RuleType: "regular"}, 100},
		{"Coverage-Check", gitlab.ApprovalRule{RuleType: "report_approver", ReportType: "code_coverage"}, 0},
		{"scan finding policy", gitlab.ApprovalRule{RuleType: "report_approver", ReportType: "scan_finding"}, 0},
		{"any merge request policy", gitlab.ApprovalRule{RuleType: "report_approver", ReportType: "any_merge_request"}, 100},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.rule
			rule.ID, rule.ApprovalsRequired, rule.AppliesToAllProtectedBranches = 1, 2, true
			client := &fakeClient{
				group:    &gitlab.Group{ID: 1, Name: "test-group"},
				projects: []gitlab.Project{{ID: 10, Name: "svc", Visibility: "private", DefaultBranch: "main"}},
				protectedBranches: map[int][]gitlab.ProtectedBranch{
					10: {{Name: "main", PushAccessLevels: []gitlab.BranchAccessLevel{{AccessLevel: 40}}}},
				},
				approvalRules: map[int][]gitlab.ApprovalRule{10: {rule}},
			}
			posture, err := New(Config{Group: "test-group"}, client).Collect(context.Background(), componentsdk.LevelAudit)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			wantInt(t, "approving_reviews", posture.BranchProtectionRules.ApprovingReviews, tt.want)
			settings := posture.Projects.PerProject[0].ApprovalSettings
			switch {
			case tt.want == 0 && settings != nil:
				t.Errorf("approval_settings = %+v, want it absent", *settings)
			case tt.want > 0 && (settings == nil || settings.ApprovalsRequired != 2):
				t.Errorf("approval_settings = %+v, want approvals_required 2", settings)
			}
			vcs := posture.ToVCSPosture()
			if p := vcs.BranchProtection.ApprovingReviewsPct.Value; p == nil || *p != float64(tt.want) {
				t.Errorf("approving_reviews_pct = %v, want %d", p, tt.want)
			}
			wantInt(t, "approving_reviews_repository_count", vcs.BranchProtection.ApprovingReviewsRepositoryCount, tt.want/100)
		})
	}
}

func TestRunners_CountOnlyGroupRunners(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{ID: 1, Name: "test-group"},
		runners: []gitlab.Runner{
			{ID: 1, Description: "acme-builders", Status: "online", RunnerType: "group_type", Online: true},
			{ID: 2, Description: "shared-linux", Status: "online", RunnerType: "instance_type", Online: true},
		},
	}

	posture, err := New(Config{Group: "test-group"}, client).Collect(context.Background(), componentsdk.LevelAudit)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Runners.GroupRunnerCount != 1 {
		t.Errorf("group_runner_count = %d, want 1", posture.Runners.GroupRunnerCount)
	}
	if rows := posture.Runners.PerRunner; len(rows) != 1 || rows[0].ID != 1 {
		t.Errorf("per_runner = %+v, want only runner 1", rows)
	}
}

func TestWebhookHost(t *testing.T) {
	tests := []struct {
		url  string
		want string
		code componentsdk.Code
	}{
		{"https://hooks.example.com/webhook", "hooks.example.com", ""},
		{"https://hooks.example.com:8443/{path}?key={value}", "hooks.example.com:8443", ""},
		{"https://{user}:{password}@hooks.example.com/webhook", "hooks.example.com", ""},
		{"https://{tenant}.example.com/hook", "", componentsdk.CodeUnsupported},
		{"https://hooks.example.com:{port}/hook", "", componentsdk.CodeUnsupported},
		{"hooks.example.com/hook", "", componentsdk.CodeInvalidResponse},
	}
	for _, tt := range tests {
		got, err := webhookHost(tt.url)
		var code componentsdk.Code
		if err != nil {
			code = componentsdk.Classify(err)
		}
		if got != tt.want || code != tt.code {
			t.Errorf("webhookHost(%q) = %q, %v; want %q with code %q", tt.url, got, err, tt.want, tt.code)
		}
		if err != nil && strings.Contains(err.Error(), "example.com") {
			t.Errorf("webhookHost(%q) error %q holds the URL", tt.url, err)
		}
	}
}

func TestWebhookMaskedHost_LeavesTheHostOut(t *testing.T) {
	hook := gitlab.Webhook{ID: 1, URL: "https://{tenant}.example.com/hook", EnableSSLVerification: true}
	client := &fakeClient{
		group:           &gitlab.Group{ID: 1, Name: "test-group"},
		projects:        []gitlab.Project{{ID: 10, Name: "proj", DefaultBranch: "main", Visibility: "private"}},
		groupWebhooks:   []gitlab.Webhook{hook},
		projectWebhooks: map[int][]gitlab.Webhook{10: {hook}},
	}

	rec := &componentsdk.Recorder{}
	posture, err := New(Config{Group: "test-group", Recorder: rec}, client).Collect(context.Background(), componentsdk.LevelInternal)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, list := range []string{"group", "project"} {
		rows := map[string][]WebhookRow{"group": posture.Webhooks.Group, "project": posture.Webhooks.Project}[list]
		if len(rows) != 1 || rows[0].URLHost != "" {
			t.Errorf("%s rows = %+v, want one row without url_host", list, rows)
		}
		pointer := "/webhooks/" + list + "/0/url_host"
		if g := gapAt(rec, pointer); g == nil || g.Code != componentsdk.CodeUnsupported {
			t.Errorf("gap at %s = %+v, want unsupported", pointer, g)
		}
	}
}

func TestAccessLevelName(t *testing.T) {
	tests := []struct {
		level    int
		expected string
	}{
		{50, "owner"},
		{40, "maintainer"},
		{30, "developer"},
		{25, "security_manager"},
		{20, "reporter"},
		{15, "planner"},
		{10, "guest"},
		{5, "minimal"},
	}

	for _, tt := range tests {
		got := accessLevelName(tt.level)
		if got != tt.expected {
			t.Errorf("accessLevelName(%d) = %s, want %s", tt.level, got, tt.expected)
		}
	}
}
