package collector

import "time"

const SchemaVersion = "1.0.0"

// GroupPosture represents the collected security posture of a GitLab group.
// A value the collector could not read is null or absent, with a gap in the
// collector result that says why.
type GroupPosture struct {
	SchemaVersion    string `json:"schema_version"`
	CollectedAt      string `json:"collected_at"`
	CollectedAtLevel string `json:"collected_at_level"`
	Group            string `json:"group,omitempty"`

	Scope                 Scope                 `json:"scope"`
	Posture               Posture               `json:"posture"`
	AccessControl         AccessControl         `json:"access_control"`
	BranchProtectionRules BranchProtectionRules `json:"branch_protection_rules"`
	SecurityFeatures      SecurityFeatures      `json:"security_features"`

	// Audit/internal surfaces (nil at trust).
	Members    *Members    `json:"members,omitempty"`
	Projects   *Projects   `json:"projects,omitempty"`
	Webhooks   *Webhooks   `json:"webhooks,omitempty"`
	DeployKeys *DeployKeys `json:"deploy_keys,omitempty"`
	Runners    *Runners    `json:"runners,omitempty"`
	AuditLog   *AuditLog   `json:"audit_log,omitempty"`

	Diagnostics *Diagnostics `json:"diagnostics,omitempty"`

	// counts holds the numerators of the rule percentages, for the
	// normalized artifact's counts.
	counts ruleCounts
	// fullPath is the group's full_path from GitLab, which names the
	// organization in the normalized artifact. Group is the configured
	// value, which can be a numeric ID from the audit level. Below it, a
	// numeric ID gives way to the full path.
	fullPath string
}

// ruleCounts counts the selected projects that meet each rule. A count is
// complete only when the rule's percentage was written.
type ruleCounts struct {
	mergeRequestRequired int
	approvingReviews     int
	pipelineRequired     int
}

type Diagnostics struct {
	PermissionErrors []string `json:"permission_errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

type Scope struct {
	IncludePatterns      []string `json:"include_patterns"`
	ExcludePatterns      []string `json:"exclude_patterns"`
	ProjectsCoverage     *int     `json:"projects_coverage"`
	ProjectCount         *int     `json:"project_count"`
	IncludedProjectCount *int     `json:"included_project_count"`
}

type Posture struct {
	BranchProtectionCoverage *int `json:"branch_protection_coverage"`
	SecurityFeaturesCoverage *int `json:"security_features_coverage"`
}

type AccessControl struct {
	TwoFactorRequired    *bool   `json:"two_factor_required"`
	ProjectCreationLevel *string `json:"project_creation_level,omitempty"`
	ShareWithGroupLock   *bool   `json:"share_with_group_lock,omitempty"`
}

type BranchProtectionRules struct {
	MergeRequestRequired *int `json:"merge_request_required"`
	ApprovingReviews     *int `json:"approving_reviews"`
	CodeOwnerApproval    *int `json:"code_owner_approval"`
	NoForcePush          *int `json:"no_force_push"`
}

type SecurityFeatures struct {
	SecretPushProtection *int `json:"secret_push_protection"`
	PipelineRequired     *int `json:"pipeline_required"`
}

// --- Audit/internal surfaces ---

type Members struct {
	TotalCount       int         `json:"total_count"`
	OwnerCount       int         `json:"owner_count"`
	MaintainerCount  int         `json:"maintainer_count"`
	DeveloperCount   int         `json:"developer_count"`
	PerMember        []MemberRow `json:"per_member"`
	Truncated        bool        `json:"truncated,omitempty"`
	TruncatedDropped int         `json:"truncated_dropped,omitempty"`
}

type MemberRow struct {
	Username         string `json:"username"`
	Name             string `json:"name,omitempty"`
	Role             string `json:"role"`
	AccessLevel      int    `json:"access_level"`
	TwoFactorEnabled *bool  `json:"two_factor_enabled"`
	State            string `json:"state,omitempty"`
}

type Projects struct {
	TotalCount       int          `json:"total_count"`
	PublicCount      int          `json:"public_count"`
	PrivateCount     int          `json:"private_count"`
	InternalCount    int          `json:"internal_count"`
	ArchivedCount    int          `json:"archived_count"`
	PerProject       []ProjectRow `json:"per_project"`
	Truncated        bool         `json:"truncated,omitempty"`
	TruncatedDropped int          `json:"truncated_dropped,omitempty"`
}

type ProjectRow struct {
	Name              string                  `json:"name"`
	PathWithNamespace string                  `json:"path_with_namespace"`
	Visibility        string                  `json:"visibility"`
	Archived          bool                    `json:"archived"`
	DefaultBranch     string                  `json:"default_branch,omitempty"`
	CreatedAt         string                  `json:"created_at,omitempty"`
	LastActivityAt    string                  `json:"last_activity_at,omitempty"`
	MergeMethod       string                  `json:"merge_method,omitempty"`
	BranchProtection  *BranchProtectionDetail `json:"branch_protection,omitempty"`
	ApprovalSettings  *ApprovalDetail         `json:"approval_settings,omitempty"`

	// Why branch_protection or approval_settings could not be read, kept
	// for the row's gaps.
	protectionErr error
	approvalErr   error
}

type BranchProtectionDetail struct {
	AllowForcePush            bool `json:"allow_force_push"`
	CodeOwnerApprovalRequired bool `json:"code_owner_approval_required"`
	MergeAccessRestricted     bool `json:"merge_access_restricted"`
	PushAccessRestricted      bool `json:"push_access_restricted"`
	MergeRequestRequired      bool `json:"merge_request_required"`
}

type ApprovalDetail struct {
	ApprovalsRequired                      int  `json:"approvals_required"`
	ResetApprovalsOnPush                   bool `json:"reset_approvals_on_push"`
	MergeRequestsDisableCommittersApproval bool `json:"merge_requests_disable_committers_approval"`
}

// Webhooks lists rows only at internal; a list that was read and is empty is
// [], so an absent list means the level left it out or a gap did.
type Webhooks struct {
	GroupCount   *int         `json:"group_count"`
	ProjectCount *int         `json:"project_count"`
	Group        []WebhookRow `json:"group,omitzero"`
	Project      []WebhookRow `json:"project,omitzero"`
}

type WebhookRow struct {
	Project   string `json:"project,omitempty"`
	ID        int    `json:"id"`
	Active    bool   `json:"active"`
	URLHost   string `json:"url_host,omitempty"`
	SSLVerify bool   `json:"ssl_verify"`

	// Why url_host is not known, kept for the row's gap.
	hostErr error
}

// DeployKeys lists rows only at internal, as Webhooks does.
type DeployKeys struct {
	TotalCount     *int           `json:"total_count"`
	ReadWriteCount *int           `json:"read_write_count"`
	PerKey         []DeployKeyRow `json:"per_key,omitzero"`
}

type DeployKeyRow struct {
	Project     string `json:"project"`
	ID          int    `json:"id"`
	Title       string `json:"title,omitempty"`
	ReadOnly    bool   `json:"read_only"`
	Fingerprint string `json:"fingerprint,omitempty"`
	CreatedAt   string `json:"created_at,omitempty"`
}

type Runners struct {
	GroupRunnerCount int         `json:"group_runner_count"`
	PerRunner        []RunnerRow `json:"per_runner"`
}

type RunnerRow struct {
	ID     int      `json:"id"`
	Name   string   `json:"name,omitempty"`
	Status string   `json:"status,omitempty"`
	Type   string   `json:"type,omitempty"`
	Online bool     `json:"online"`
	Paused bool     `json:"paused"`
	Tags   []string `json:"tags,omitzero"`
}

type AuditLog struct {
	WindowDays       int            `json:"window_days"`
	CountByAction    map[string]int `json:"count_by_action"`
	Events           []AuditLogRow  `json:"events"`
	Truncated        bool           `json:"truncated,omitempty"`
	TruncatedDropped int            `json:"truncated_dropped,omitempty"`
}

type AuditLogRow struct {
	Action    string `json:"action"`
	Actor     string `json:"actor,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

// NewGroupPosture creates a new GroupPosture stamped with now.
func NewGroupPosture(group string, now time.Time) *GroupPosture {
	return &GroupPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   now.UTC().Format(time.RFC3339),
		Group:         group,
	}
}
