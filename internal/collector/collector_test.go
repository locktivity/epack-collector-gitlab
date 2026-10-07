package collector

import (
	"context"
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
	groupWebhooks     []gitlab.Webhook
	groupWebhooksErr  error
	projectWebhooks   map[int][]gitlab.Webhook
	deployKeys        map[int][]gitlab.DeployKey
	runners           []gitlab.Runner
	runnersErr        error
	auditEvents       []gitlab.AuditEvent
	auditEventsErr    error
	vulnFindings      map[int][]gitlab.VulnerabilityFinding
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

func (f *fakeClient) ListVulnerabilityFindings(_ context.Context, projectID int) ([]gitlab.VulnerabilityFinding, error) {
	if findings, ok := f.vulnFindings[projectID]; ok {
		return findings, nil
	}
	return nil, nil
}

func boolPtr(b bool) *bool { return &b }

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

func (f *fakeClientWithApprovalErr) GetApprovalSettings(_ context.Context, _ int) (*gitlab.ApprovalSettings, error) {
	return nil, f.approvalSettingsErr
}

func (f *fakeClientWithApprovalErr) ListApprovalRules(_ context.Context, _ int) ([]gitlab.ApprovalRule, error) {
	return nil, f.approvalRulesErr
}

func TestCollect_TrustLevel_BasicPosture(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{
			ID:                             1,
			Name:                           "test-group",
			RequireTwoFactorAuthentication: true,
		},
		projects: []gitlab.Project{
			{ID: 10, Name: "project-a", DefaultBranch: "main", Visibility: "private", SecretPushProtectionEnabled: true, OnlyAllowMergeIfPipelineSucceeds: true},
			{ID: 11, Name: "project-b", DefaultBranch: "main", Visibility: "public"},
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
	if posture.BranchProtectionRules.MergeRequestRequired != 50 {
		t.Errorf("expected 50%% merge request required, got %d", posture.BranchProtectionRules.MergeRequestRequired)
	}
	if posture.BranchProtectionRules.ApprovingReviews != 50 {
		t.Errorf("expected 50%% approving reviews, got %d", posture.BranchProtectionRules.ApprovingReviews)
	}
	if posture.SecurityFeatures.SecretPushProtection != 50 {
		t.Errorf("expected 50%% secret push protection, got %d", posture.SecurityFeatures.SecretPushProtection)
	}
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
	if posture.Webhooks.GroupCount != 1 {
		t.Errorf("expected 1 group webhook, got %d", posture.Webhooks.GroupCount)
	}
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

	if posture.Scope.ProjectsCoverage != 33 {
		t.Errorf("expected ~33%% coverage, got %d", posture.Scope.ProjectsCoverage)
	}
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

	if posture.Scope.ProjectsCoverage != 50 {
		t.Errorf("expected 50%% coverage, got %d", posture.Scope.ProjectsCoverage)
	}
}

func TestCollect_GroupError_ReturnsError(t *testing.T) {
	client := &fakeClient{
		groupErr: &gitlab.APIError{StatusCode: 500, Body: "internal error"},
	}

	c := New(Config{Group: "test-group"}, client)
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("expected error for non-permission group failure")
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
		groupErr: &gitlab.APIError{StatusCode: 401, Body: "401 Unauthorized"},
	}

	c := New(Config{Group: "test-group"}, client)
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("expected error for 401 response")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected authentication error message, got: %v", err)
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

func TestDiagnostics_TrustLevel_NoProjectNames(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{
			{ID: 10, Name: "secret-project", DefaultBranch: "main", Visibility: "private"},
		},
		protectedBranches: map[int][]gitlab.ProtectedBranch{
			10: nil,
		},
	}

	client.protectedBranches = map[int][]gitlab.ProtectedBranch{}
	delete(client.protectedBranches, 10)

	fakeBranchErr := &fakeClientWithBranchErr{
		fakeClient: client,
		branchErr:  &gitlab.APIError{StatusCode: 500, Body: "internal error"},
	}

	c := New(Config{Group: "test-group"}, fakeBranchErr)
	posture, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if posture.Diagnostics == nil {
		t.Fatal("expected diagnostics with warnings")
	}
	for _, w := range posture.Diagnostics.Warnings {
		if strings.Contains(w, "secret-project") {
			t.Errorf("trust-level diagnostic leaked project name: %s", w)
		}
	}
}

func TestApprovalPermissionDenied_EmitsDiagnostic(t *testing.T) {
	denied := &gitlab.APIError{StatusCode: 403, Body: "forbidden"}
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
	if posture.BranchProtectionRules.ApprovingReviews != 0 {
		t.Errorf("expected 0%% approving reviews (unprotected default branch), got %d", posture.BranchProtectionRules.ApprovingReviews)
	}
}

func TestPartialApprovalFailure_EmitsDiagnostic(t *testing.T) {
	denied := &gitlab.APIError{StatusCode: 403, Body: "forbidden"}
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
	apiErr := &gitlab.APIError{StatusCode: 500, Body: "sensitive internal error details"}
	msg := safeDiagError(apiErr)
	if strings.Contains(msg, "sensitive") {
		t.Errorf("safeDiagError leaked API body: %s", msg)
	}
	if msg != "HTTP 500" {
		t.Errorf("expected 'HTTP 500', got %s", msg)
	}
}

func TestToVCSPosture(t *testing.T) {
	twoFA := true
	posture := &GroupPosture{
		Group: "test-group",
		Scope: Scope{ProjectsCoverage: 100},
		AccessControl: AccessControl{
			TwoFactorRequired: &twoFA,
		},
		BranchProtectionRules: BranchProtectionRules{
			MergeRequestRequired: 80,
			ApprovingReviews:     60,
		},
		SecurityFeatures: SecurityFeatures{
			SecretPushProtection: 50,
			PipelineRequired:    70,
		},
	}

	vcs := posture.ToVCSPosture()
	if vcs.Provider != "gitlab" {
		t.Errorf("expected provider gitlab, got %s", vcs.Provider)
	}
	if vcs.Organization != "test-group" {
		t.Errorf("expected org test-group, got %s", vcs.Organization)
	}
	if !vcs.OrgSecurity.TwoFactorRequired {
		t.Error("expected 2FA required in VCS posture")
	}
	if vcs.BranchProtection.PRRequiredPct != 80 {
		t.Errorf("expected 80%% PR required, got %f", vcs.BranchProtection.PRRequiredPct)
	}
	if vcs.SecurityFeatures.SecretScanningPct != 50 {
		t.Errorf("expected 50%% secret scanning, got %f", vcs.SecurityFeatures.SecretScanningPct)
	}
}

func TestSurfaceCollector_401_FailsCollection(t *testing.T) {
	client := &fakeClient{
		group: &gitlab.Group{ID: 1, Name: "test-group"},
		projects: []gitlab.Project{
			{ID: 10, Name: "project-a", DefaultBranch: "main", Visibility: "private"},
		},
		protectedBranches: map[int][]gitlab.ProtectedBranch{},
		membersErr:        gitlab.ErrUnauthorized,
	}

	c := New(Config{Group: "test-group"}, client)
	_, err := c.Collect(context.Background(), componentsdk.LevelAudit)
	if err == nil {
		t.Fatal("expected error when members returns 401 at audit level")
	}
	if !strings.Contains(err.Error(), "authentication failed") {
		t.Errorf("expected authentication failed error, got: %v", err)
	}
}

func TestFatalError_DoesNotLeakBody(t *testing.T) {
	client := &fakeClient{
		groupErr: &gitlab.APIError{StatusCode: 500, Body: "sensitive database trace"},
	}

	c := New(Config{Group: "test-group"}, client)
	_, err := c.Collect(context.Background(), componentsdk.LevelTrust)
	if err == nil {
		t.Fatal("expected error from GetGroup failure")
	}
	if strings.Contains(err.Error(), "sensitive") {
		t.Errorf("fatal error leaked API body: %v", err)
	}
	if strings.Contains(err.Error(), "database") {
		t.Errorf("fatal error leaked API body: %v", err)
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("expected sanitized HTTP 500, got: %v", err)
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
		{20, "reporter"},
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
