package gitlab

import "time"

// Group represents a GitLab group from the API.
type Group struct {
	ID                             int    `json:"id"`
	Name                           string `json:"name"`
	FullPath                       string `json:"full_path"`
	Visibility                     string `json:"visibility"`
	RequireTwoFactorAuthentication bool   `json:"require_two_factor_authentication"`
	ProjectCreationLevel           string `json:"project_creation_level"`
	SubgroupCreationLevel          string `json:"subgroup_creation_level"`
	ShareWithGroupLock             bool   `json:"share_with_group_lock"`
	PreventSharingGroupsOutside    bool   `json:"prevent_sharing_groups_outside_hierarchy"`
	MembershipLock                 bool   `json:"membership_lock"`
	PreventForkingOutsideGroup     bool   `json:"prevent_forking_outside_group"`
	DefaultBranchProtection        int    `json:"default_branch_protection"`
	IPRestrictionRanges            string `json:"ip_restriction_ranges"`
	EnabledGitAccessProtocol       string `json:"enabled_git_access_protocol"`
}

// Project represents a GitLab project from the API.
type Project struct {
	ID                                      int        `json:"id"`
	Name                                    string     `json:"name"`
	PathWithNamespace                       string     `json:"path_with_namespace"`
	Visibility                              string     `json:"visibility"`
	Archived                                bool       `json:"archived"`
	DefaultBranch                           string     `json:"default_branch"`
	CreatedAt                               *time.Time `json:"created_at"`
	LastActivityAt                          *time.Time `json:"last_activity_at"`
	OnlyAllowMergeIfPipelineSucceeds        bool       `json:"only_allow_merge_if_pipeline_succeeds"`
	OnlyAllowMergeIfAllDiscussionsResolved  bool       `json:"only_allow_merge_if_all_discussions_are_resolved"`
	MergeMethod                             string     `json:"merge_method"`
	ApprovalsBeforeMerge                    int        `json:"approvals_before_merge"`
	SecretPushProtectionEnabled             *bool      `json:"secret_push_protection_enabled"`
	RemoveSourceBranchAfterMerge            bool       `json:"remove_source_branch_after_merge"`
	ForksCount                              int        `json:"forks_count"`
	StarCount                               int        `json:"star_count"`
	Statistics                              *ProjectStatistics `json:"statistics,omitempty"`
}

// ProjectStatistics contains project size info.
type ProjectStatistics struct {
	RepositorySize int64 `json:"repository_size"`
}

// ProtectedBranch represents a branch protection rule.
type ProtectedBranch struct {
	ID                        int                     `json:"id"`
	Name                      string                  `json:"name"`
	AllowForcePush            bool                    `json:"allow_force_push"`
	CodeOwnerApprovalRequired bool                    `json:"code_owner_approval_required"`
	PushAccessLevels          []BranchAccessLevel     `json:"push_access_levels"`
	MergeAccessLevels         []BranchAccessLevel     `json:"merge_access_levels"`
	UnprotectAccessLevels     []BranchAccessLevel     `json:"unprotect_access_levels"`
}

// BranchAccessLevel represents an access level on a protected branch.
type BranchAccessLevel struct {
	ID                 int    `json:"id"`
	AccessLevel        int    `json:"access_level"`
	AccessLevelDesc    string `json:"access_level_description"`
	DeployKeyID        *int   `json:"deploy_key_id"`
	UserID             *int   `json:"user_id"`
	GroupID            *int   `json:"group_id"`
	MemberRoleID       *int   `json:"member_role_id"`
}

// ApprovalSettings represents project-level approval configuration.
type ApprovalSettings struct {
	ApprovalsBeforeMerge                   int  `json:"approvals_before_merge"`
	ResetApprovalsOnPush                   bool `json:"reset_approvals_on_push"`
	DisableOverridingApproversPerMR        bool `json:"disable_overriding_approvers_per_merge_request"`
	MergeRequestsAuthorApproval            bool `json:"merge_requests_author_approval"`
	MergeRequestsDisableCommittersApproval bool `json:"merge_requests_disable_committers_approval"`
}

// ApprovalRule represents a merge request approval rule.
type ApprovalRule struct {
	ID                            int                  `json:"id"`
	Name                          string               `json:"name"`
	RuleType                      string               `json:"rule_type"`
	ApprovalsRequired             int                  `json:"approvals_required"`
	AppliesToAllProtectedBranches bool                 `json:"applies_to_all_protected_branches"`
	ProtectedBranches             []ApprovalRuleBranch `json:"protected_branches"`
}

// ApprovalRuleBranch identifies a branch that an approval rule applies to.
type ApprovalRuleBranch struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Member represents a group or project member.
type Member struct {
	ID               int        `json:"id"`
	Username         string     `json:"username"`
	Name             string     `json:"name"`
	State            string     `json:"state"`
	AccessLevel      int        `json:"access_level"`
	ExpiresAt        *string    `json:"expires_at"`
	TwoFactorEnabled *bool      `json:"two_factor_enabled"`
	CreatedAt        *time.Time `json:"created_at"`
}

// Webhook represents a project or group webhook.
type Webhook struct {
	ID                    int        `json:"id"`
	URL                   string     `json:"url"`
	PushEvents            bool       `json:"push_events"`
	TagPushEvents         bool       `json:"tag_push_events"`
	MergeRequestsEvents   bool       `json:"merge_requests_events"`
	RepositoryUpdateEvents bool      `json:"repository_update_events"`
	EnableSSLVerification bool       `json:"enable_ssl_verification"`
	AlertStatus           string     `json:"alert_status"`
	CreatedAt             *time.Time `json:"created_at"`
}

// DeployKey represents a project deploy key.
type DeployKey struct {
	ID          int        `json:"id"`
	Title       string     `json:"title"`
	Key         string     `json:"key"`
	Fingerprint string     `json:"fingerprint"`
	CanPush     bool       `json:"can_push"`
	CreatedAt   *time.Time `json:"created_at"`
}

// Runner represents a GitLab runner.
type Runner struct {
	ID          int      `json:"id"`
	Description string   `json:"description"` // LINT-ALLOW: runner description is a name, not customer content
	Status      string   `json:"status"`
	Paused      bool     `json:"paused"`
	RunnerType  string   `json:"runner_type"`
	TagList     []string `json:"tag_list"`
	Online      bool     `json:"online"`
	IPAddress   string   `json:"ip_address"`
}

// AuditEvent represents a group audit event.
type AuditEvent struct {
	ID        int        `json:"id"`
	AuthorID  int        `json:"author_id"`
	EntityID  int        `json:"entity_id"`
	EntityType string    `json:"entity_type"`
	Details   AuditEventDetails `json:"details"`
	CreatedAt *time.Time `json:"created_at"`
}

// AuditEventDetails contains audit event detail fields.
type AuditEventDetails struct {
	CustomMessage string `json:"custom_message"`
	AuthorName    string `json:"author_name"`
	TargetType    string `json:"target_type"`
	EntityPath    string `json:"entity_path"`
}

// VulnerabilityFinding represents a project vulnerability finding.
type VulnerabilityFinding struct {
	ID         int    `json:"id"`
	ReportType string `json:"report_type"`
	Severity   string `json:"severity"`
	State      string `json:"state"`
	Name       string `json:"name"`
}
