package gitlab

import (
	"encoding/json"
	"time"
)

// Group represents a GitLab group from the API. The settings the collector
// reports are pointers, so a field GitLab left out reads as unknown rather
// than as false. ParentID is nil for a top-level group.
// IPRestrictionRanges holds the group's own IP restriction, which GitLab
// enforces only on a top-level group, and is empty without one.
type Group struct {
	ID                             int     `json:"id"`
	Name                           string  `json:"name"`
	FullPath                       string  `json:"full_path"`
	ParentID                       *int    `json:"parent_id"`
	Visibility                     string  `json:"visibility"`
	RequireTwoFactorAuthentication *bool   `json:"require_two_factor_authentication"`
	RequireTwoFactorFromAncestor   *bool   `json:"require_two_factor_authentication_from_ancestor"`
	ProjectCreationLevel           *string `json:"project_creation_level"`
	SubgroupCreationLevel          string  `json:"subgroup_creation_level"`
	ShareWithGroupLock             *bool   `json:"share_with_group_lock"`
	PreventSharingGroupsOutside    bool    `json:"prevent_sharing_groups_outside_hierarchy"`
	MembershipLock                 bool    `json:"membership_lock"`
	PreventForkingOutsideGroup     bool    `json:"prevent_forking_outside_group"`
	DefaultBranchProtection        int     `json:"default_branch_protection"`
	IPRestrictionRanges            string  `json:"ip_restriction_ranges"`
	EnabledGitAccessProtocol       string  `json:"enabled_git_access_protocol"`
}

// Project represents a GitLab project from the API.
type Project struct {
	ID                                     int                `json:"id"`
	Name                                   string             `json:"name"`
	PathWithNamespace                      string             `json:"path_with_namespace"`
	Visibility                             string             `json:"visibility"`
	Archived                               bool               `json:"archived"`
	DefaultBranch                          string             `json:"default_branch"`
	CreatedAt                              *time.Time         `json:"created_at"`
	LastActivityAt                         *time.Time         `json:"last_activity_at"`
	OnlyAllowMergeIfPipelineSucceeds       *bool              `json:"only_allow_merge_if_pipeline_succeeds"`
	OnlyAllowMergeIfAllDiscussionsResolved bool               `json:"only_allow_merge_if_all_discussions_are_resolved"`
	MergeMethod                            string             `json:"merge_method"`
	ApprovalsBeforeMerge                   int                `json:"approvals_before_merge"`
	SecretPushProtectionEnabled            *bool              `json:"secret_push_protection_enabled"`
	RemoveSourceBranchAfterMerge           bool               `json:"remove_source_branch_after_merge"`
	ForksCount                             int                `json:"forks_count"`
	StarCount                              int                `json:"star_count"`
	Statistics                             *ProjectStatistics `json:"statistics,omitempty"`
}

// ProjectStatistics contains project size info.
type ProjectStatistics struct {
	RepositorySize int64 `json:"repository_size"`
}

// ProtectedBranch represents a branch protection rule.
type ProtectedBranch struct {
	ID                        int                 `json:"id"`
	Name                      string              `json:"name"`
	AllowForcePush            bool                `json:"allow_force_push"`
	CodeOwnerApprovalRequired bool                `json:"code_owner_approval_required"`
	PushAccessLevels          []BranchAccessLevel `json:"push_access_levels"`
	MergeAccessLevels         []BranchAccessLevel `json:"merge_access_levels"`
	UnprotectAccessLevels     []BranchAccessLevel `json:"unprotect_access_levels"`
}

// BranchAccessLevel represents an access level on a protected branch.
type BranchAccessLevel struct {
	ID              int    `json:"id"`
	AccessLevel     int    `json:"access_level"`
	AccessLevelDesc string `json:"access_level_description"`
	DeployKeyID     *int   `json:"deploy_key_id"`
	UserID          *int   `json:"user_id"`
	GroupID         *int   `json:"group_id"`
	MemberRoleID    *int   `json:"member_role_id"`
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
	ReportType                    string               `json:"report_type"`
	ApprovalsRequired             int                  `json:"approvals_required"`
	AppliesToAllProtectedBranches bool                 `json:"applies_to_all_protected_branches"`
	ProtectedBranches             []ApprovalRuleBranch `json:"protected_branches"`
}

// ApprovalRuleBranch identifies a branch that an approval rule applies to.
type ApprovalRuleBranch struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// Member represents a group or project member. Only group Owners can see
// two_factor_enabled, group_saml_identity, and group_scim_identity. The two
// identities appear only in groups with SAML SSO.
type Member struct {
	ID                int        `json:"id"`
	Username          string     `json:"username"`
	Name              string     `json:"name"`
	State             string     `json:"state"`
	AccessLevel       int        `json:"access_level"`
	ExpiresAt         *string    `json:"expires_at"`
	TwoFactorEnabled  *bool      `json:"two_factor_enabled"`
	CreatedAt         *time.Time `json:"created_at"`
	GroupSAMLIdentity *Identity  `json:"group_saml_identity"`
	GroupSCIMIdentity *Identity  `json:"group_scim_identity"`
	// MemberRole is the member's custom role, nil for a default role.
	MemberRole *MemberRole `json:"member_role"`
}

// MemberRole is a custom role. AdminGroupMember lets whoever holds it add,
// remove, and assign the group's members, and RemoveGroup lets them delete
// the group.
type MemberRole struct {
	ID               int  `json:"id"`
	AdminGroupMember bool `json:"admin_group_member"`
	RemoveGroup      bool `json:"remove_group"`
}

// BillableMember is one user in a top-level group's billable members list,
// which holds the users with a role in the group, its subgroups, or its
// projects, except Guests on Ultimate. LastActivityOn is the date of the
// user's last activity anywhere in GitLab, or nil when GitLab has none
// recorded.
type BillableMember struct {
	ID             int    `json:"id"`
	Username       string `json:"username"`
	State          string `json:"state"`
	LastActivityOn *Date  `json:"last_activity_on"`
}

// Identity is a member's link to the group's SAML or SCIM provider.
type Identity struct {
	Provider string `json:"provider"`
}

// Webhook represents a project or group webhook.
type Webhook struct {
	ID                     int        `json:"id"`
	URL                    string     `json:"url"`
	PushEvents             bool       `json:"push_events"`
	TagPushEvents          bool       `json:"tag_push_events"`
	MergeRequestsEvents    bool       `json:"merge_requests_events"`
	RepositoryUpdateEvents bool       `json:"repository_update_events"`
	EnableSSLVerification  bool       `json:"enable_ssl_verification"`
	AlertStatus            string     `json:"alert_status"`
	CreatedAt              *time.Time `json:"created_at"`
}

// DeployKey represents a project deploy key.
type DeployKey struct {
	ID          int        `json:"id"`
	Title       string     `json:"title"`
	Key         string     `json:"key"`
	Fingerprint string     `json:"fingerprint"`
	CanPush     bool       `json:"can_push"`
	CreatedAt   *time.Time `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
}

// AccessToken is a group or project access token. Its expiry is a date with
// no time of day.
type AccessToken struct {
	ID          int        `json:"id"`
	UserID      int        `json:"user_id"`
	Scopes      []string   `json:"scopes"`
	Active      bool       `json:"active"`
	Revoked     bool       `json:"revoked"`
	AccessLevel int        `json:"access_level"`
	CreatedAt   *time.Time `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	ExpiresAt   *Date      `json:"expires_at"`
}

// Date is a calendar date that GitLab writes as 2006-01-02.
type Date struct {
	time.Time
}

const dateLayout = "2006-01-02"

// UnmarshalJSON reads a date such as "2026-01-31".
func (d *Date) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	t, err := time.Parse(dateLayout, s)
	if err != nil {
		return err
	}
	d.Time = t
	return nil
}

// MarshalJSON writes the date as GitLab does.
func (d Date) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Format(dateLayout))
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
	ID         int               `json:"id"`
	AuthorID   int               `json:"author_id"`
	EntityID   int               `json:"entity_id"`
	EntityType string            `json:"entity_type"`
	Details    AuditEventDetails `json:"details"`
	CreatedAt  *time.Time        `json:"created_at"`
}

// AuditEventDetails contains audit event detail fields.
type AuditEventDetails struct {
	CustomMessage string `json:"custom_message"`
	AuthorName    string `json:"author_name"`
	TargetType    string `json:"target_type"`
	EntityPath    string `json:"entity_path"`
}
