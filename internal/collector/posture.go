package collector

import "time"

const SchemaVersion = "1.0.0"

// GroupPosture represents the collected security posture of a GitLab group.
type GroupPosture struct {
	SchemaVersion    string `json:"schema_version"`
	CollectedAt      string `json:"collected_at"`
	CollectedAtLevel string `json:"collected_at_level"`
	Group            string `json:"group"`

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
}

type Diagnostics struct {
	PermissionErrors []string `json:"permission_errors,omitempty"`
	Warnings         []string `json:"warnings,omitempty"`
}

type Scope struct {
	IncludePatterns  []string `json:"include_patterns"`
	ExcludePatterns  []string `json:"exclude_patterns"`
	ProjectsCoverage int      `json:"projects_coverage"`
}

type Posture struct {
	BranchProtectionCoverage int `json:"branch_protection_coverage"`
	SecurityFeaturesCoverage int `json:"security_features_coverage"`
}

type AccessControl struct {
	TwoFactorRequired    *bool  `json:"two_factor_required"`
	ProjectCreationLevel string `json:"project_creation_level,omitempty"`
	ShareWithGroupLock   *bool  `json:"share_with_group_lock,omitempty"`
}

type BranchProtectionRules struct {
	MergeRequestRequired int `json:"merge_request_required"`
	ApprovingReviews     int `json:"approving_reviews"`
	CodeOwnerApproval    int `json:"code_owner_approval"`
	NoForcePush          int `json:"no_force_push"`
}

type SecurityFeatures struct {
	SecretPushProtection int `json:"secret_push_protection"`
	PipelineRequired     int `json:"pipeline_required"`

	PerProject []SecurityFeaturesRow `json:"per_project,omitempty"`
}

type SecurityFeaturesRow struct {
	Project              string `json:"project"`
	SecretPushProtection bool   `json:"secret_push_protection"`
	PipelineRequired     bool   `json:"pipeline_required"`
}

// --- Audit/internal surfaces ---

type Members struct {
	TotalCount       int         `json:"total_count"`
	OwnerCount       int         `json:"owner_count"`
	MaintainerCount  int         `json:"maintainer_count"`
	DeveloperCount   int         `json:"developer_count"`
	PerMember        []MemberRow `json:"per_member,omitempty"`
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
	TotalCount    int          `json:"total_count"`
	PublicCount   int          `json:"public_count"`
	PrivateCount  int          `json:"private_count"`
	InternalCount int          `json:"internal_count"`
	ArchivedCount int          `json:"archived_count"`
	PerProject    []ProjectRow `json:"per_project,omitempty"`
	Truncated     bool         `json:"truncated,omitempty"`
	TruncatedDropped int       `json:"truncated_dropped,omitempty"`
}

type ProjectRow struct {
	Name             string                  `json:"name"`
	PathWithNamespace string                 `json:"path_with_namespace"`
	Visibility       string                  `json:"visibility"`
	Archived         bool                    `json:"archived"`
	DefaultBranch    string                  `json:"default_branch,omitempty"`
	CreatedAt        string                  `json:"created_at,omitempty"`
	LastActivityAt   string                  `json:"last_activity_at,omitempty"`
	MergeMethod      string                  `json:"merge_method,omitempty"`
	BranchProtection *BranchProtectionDetail `json:"branch_protection,omitempty"`
	ApprovalSettings *ApprovalDetail         `json:"approval_settings,omitempty"`
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

type Webhooks struct {
	GroupCount   int          `json:"group_count"`
	ProjectCount int         `json:"project_count"`
	Group        []WebhookRow `json:"group,omitempty"`
	Project      []WebhookRow `json:"project,omitempty"`
}

type WebhookRow struct {
	Project   string `json:"project,omitempty"`
	ID        int    `json:"id"`
	Active    bool   `json:"active"`
	URLHost   string `json:"url_host,omitempty"`
	SSLVerify bool   `json:"ssl_verify"`
}

type DeployKeys struct {
	TotalCount     int            `json:"total_count"`
	ReadWriteCount int            `json:"read_write_count"`
	PerKey         []DeployKeyRow `json:"per_key,omitempty"`
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
	PerRunner        []RunnerRow `json:"per_runner,omitempty"`
}

type RunnerRow struct {
	ID     int      `json:"id"`
	Name   string   `json:"name,omitempty"`
	Status string   `json:"status,omitempty"`
	Type   string   `json:"type,omitempty"`
	Online bool     `json:"online"`
	Paused bool     `json:"paused"`
	Tags   []string `json:"tags,omitempty"`
}

type AuditLog struct {
	WindowDays       int              `json:"window_days"`
	CountByAction    map[string]int   `json:"count_by_action,omitempty"`
	Events           []AuditLogRow    `json:"events,omitempty"`
	Truncated        bool             `json:"truncated,omitempty"`
	TruncatedDropped int              `json:"truncated_dropped,omitempty"`
}

type AuditLogRow struct {
	Action    string `json:"action"`
	Actor     string `json:"actor,omitempty"`
	Timestamp int64  `json:"timestamp"`
}

// NewGroupPosture creates a new GroupPosture with the current timestamp.
func NewGroupPosture(group string) *GroupPosture {
	return &GroupPosture{
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().UTC().Format(time.RFC3339),
		Group:         group,
	}
}
