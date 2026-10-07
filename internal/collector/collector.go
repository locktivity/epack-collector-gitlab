package collector

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
	"github.com/locktivity/epack/componentsdk"
)

// GitLabClient is the interface the collector uses to talk to GitLab.
type GitLabClient interface {
	GetGroup(ctx context.Context, groupID string) (*gitlab.Group, error)
	ListProjects(ctx context.Context, groupID string) ([]gitlab.Project, error)
	ListProtectedBranches(ctx context.Context, projectID int) ([]gitlab.ProtectedBranch, error)
	GetApprovalSettings(ctx context.Context, projectID int) (*gitlab.ApprovalSettings, error)
	ListApprovalRules(ctx context.Context, projectID int) ([]gitlab.ApprovalRule, error)
	ListGroupMembers(ctx context.Context, groupID string) ([]gitlab.Member, error)
	ListGroupWebhooks(ctx context.Context, groupID string) ([]gitlab.Webhook, error)
	ListProjectWebhooks(ctx context.Context, projectID int) ([]gitlab.Webhook, error)
	ListProjectDeployKeys(ctx context.Context, projectID int) ([]gitlab.DeployKey, error)
	ListGroupRunners(ctx context.Context, groupID string) ([]gitlab.Runner, error)
	ListGroupAuditEvents(ctx context.Context, groupID string, since time.Time) ([]gitlab.AuditEvent, error)
	ListVulnerabilityFindings(ctx context.Context, projectID int) ([]gitlab.VulnerabilityFinding, error)
}

// Collector collects GitLab group security posture.
type Collector struct {
	client GitLabClient
	config Config
}

// New creates a new Collector.
func New(config Config, client GitLabClient) *Collector {
	return &Collector{
		client: client,
		config: config,
	}
}

func (c *Collector) status(message string) {
	if c.config.OnStatus != nil {
		c.config.OnStatus(message)
	}
}

func (c *Collector) progress(current, total int64, message string) {
	if c.config.OnProgress != nil {
		c.config.OnProgress(current, total, message)
	}
}

// Collect fetches and aggregates security posture metrics for the group.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*GroupPosture, error) {
	if c.config.Group == "" {
		return nil, fmt.Errorf("group is required")
	}

	includePatterns := c.config.IncludePatterns
	if len(includePatterns) == 0 {
		includePatterns = []string{DefaultIncludePattern}
	}
	excludePatterns := c.config.ExcludePatterns
	if excludePatterns == nil {
		excludePatterns = []string{}
	}

	posture := NewGroupPosture(c.config.Group)
	posture.CollectedAtLevel = string(level)
	diag := &diagnosticsTracker{}

	c.status(fmt.Sprintf("Connecting to GitLab group %s...", c.config.Group))

	group, err := c.client.GetGroup(ctx, c.config.Group)
	if err != nil {
		if isUnauthorized(err) {
			return nil, errAuthFailed
		}
		if isDenied(err) {
			diag.surfacePermissionDenied("group_settings", "permission denied (requires read_api scope)")
			group = &gitlab.Group{}
		} else {
			return nil, fmt.Errorf("fetching group: %s", safeDiagError(err))
		}
	}

	c.status("Fetching projects...")

	allProjects, err := c.client.ListProjects(ctx, c.config.Group)
	if err != nil {
		if isUnauthorized(err) {
			return nil, errAuthFailed
		}
		if isDenied(err) {
			diag.surfacePermissionDenied("projects", "permission denied (requires read_api scope)")
			allProjects = nil
		} else {
			return nil, fmt.Errorf("fetching projects: %s", safeDiagError(err))
		}
	}

	var included []gitlab.Project
	for _, p := range allProjects {
		name := p.Name
		if matchesAny(name, excludePatterns) {
			continue
		}
		if matchesAny(name, includePatterns) {
			included = append(included, p)
		}
	}

	c.status(fmt.Sprintf("Found %d projects (%d after filtering)...", len(allProjects), len(included)))

	metrics, err := c.computeMetrics(ctx, included, level, diag)
	if err != nil {
		return nil, err
	}

	c.populatePosture(posture, group, metrics, included, includePatterns, excludePatterns, len(allProjects))

	if err := c.collectSurfaces(ctx, posture, group, included, metrics, level, diag); err != nil {
		return nil, err
	}

	posture.Diagnostics = diag.toDiagnostics()

	c.status("Collection complete")
	return posture, nil
}

type projectMetrics struct {
	branchProtected    int
	mergeRestricted    int
	approvingReviews   int
	codeOwnerApproval  int
	noForcePush        int
	secretPushProt     int
	pipelineRequired   int
	branchProtections  map[int]*BranchProtectionDetail
	approvalDetails    map[int]*ApprovalDetail
}

func (c *Collector) computeMetrics(ctx context.Context, projects []gitlab.Project, level componentsdk.Level, diag *diagnosticsTracker) (*projectMetrics, error) {
	m := &projectMetrics{
		branchProtections: make(map[int]*BranchProtectionDetail),
		approvalDetails:   make(map[int]*ApprovalDetail),
	}

	total := int64(len(projects))
	for i, proj := range projects {
		c.progress(int64(i+1), total, fmt.Sprintf("Analyzing %s", proj.Name))

		if proj.SecretPushProtectionEnabled { // LINT-ALLOW: boolean setting, not a secret value
			m.secretPushProt++
		}
		if proj.OnlyAllowMergeIfPipelineSucceeds {
			m.pipelineRequired++
		}

		branches, err := c.client.ListProtectedBranches(ctx, proj.ID)
		if err != nil {
			if isUnauthorized(err) {
				return nil, errAuthFailed
			}
			if isDenied(err) {
				diag.surfacePermissionDenied("protected_branches", "permission denied (requires read_api scope)")
			} else {
				diag.surfaceUnavailable("protected_branches", projectDiagLabel(proj, level))
			}
			continue
		}

		detail := c.analyzeProtection(branches, proj.DefaultBranch)
		if detail != nil {
			m.branchProtected++
			m.branchProtections[proj.ID] = detail

			if detail.MergeRequestRequired {
				m.mergeRestricted++
			}
			if detail.CodeOwnerApprovalRequired {
				m.codeOwnerApproval++
			}
			if !detail.AllowForcePush {
				m.noForcePush++
			}
		}

		approvals, err := c.client.GetApprovalSettings(ctx, proj.ID)
		if isUnauthorized(err) {
			return nil, errAuthFailed
		}
		approvalsDenied := isDenied(err) || isNotFound(err)
		if err != nil && !approvalsDenied {
			diag.surfaceUnavailable("approval_settings", projectDiagLabel(proj, level))
		}

		rules, rulesErr := c.client.ListApprovalRules(ctx, proj.ID)
		if isUnauthorized(rulesErr) {
			return nil, errAuthFailed
		}
		rulesDenied := isDenied(rulesErr) || isNotFound(rulesErr)
		if rulesErr != nil && !rulesDenied {
			diag.surfaceUnavailable("approval_rules", projectDiagLabel(proj, level))
		}

		if approvalsDenied || rulesDenied {
			if approvalsDenied && rulesDenied {
				diag.surfacePermissionDenied("approvals", "approval settings and rules both inaccessible (may require Maintainer role or Premium tier)")
			} else if approvalsDenied {
				diag.surfacePermissionDenied("approval_settings", "approval settings inaccessible (may require Maintainer role or Premium tier)")
			} else {
				diag.surfacePermissionDenied("approval_rules", "approval rules inaccessible (may require Premium tier)")
			}
		}

		requiredApprovals := 0
		if err == nil && approvals != nil {
			requiredApprovals = approvals.ApprovalsBeforeMerge
		}
		defaultBranchProtected := detail != nil
		for _, rule := range rules {
			if !ruleAppliesToBranch(rule, proj.DefaultBranch, defaultBranchProtected) {
				continue
			}
			if rule.ApprovalsRequired > requiredApprovals {
				requiredApprovals = rule.ApprovalsRequired
			}
		}

		if requiredApprovals > 0 {
			m.approvingReviews++
			ad := &ApprovalDetail{
				ApprovalsRequired: requiredApprovals,
			}
			if err == nil && approvals != nil {
				ad.ResetApprovalsOnPush = approvals.ResetApprovalsOnPush
				ad.MergeRequestsDisableCommittersApproval = approvals.MergeRequestsDisableCommittersApproval
			}
			m.approvalDetails[proj.ID] = ad
		}
	}

	return m, nil
}

// ruleAppliesToBranch returns true if the approval rule applies to the given
// branch. A rule applies when:
//   - it has no branch scope (neither ProtectedBranches nor
//     AppliesToAllProtectedBranches is set), meaning it is project-wide, OR
//   - AppliesToAllProtectedBranches is true AND the branch is actually
//     protected (an unprotected default branch does not qualify), OR
//   - ProtectedBranches explicitly lists a matching branch name or pattern.
func ruleAppliesToBranch(rule gitlab.ApprovalRule, branch string, branchIsProtected bool) bool {
	if rule.AppliesToAllProtectedBranches {
		return branchIsProtected
	}
	if len(rule.ProtectedBranches) == 0 {
		return true
	}
	for _, pb := range rule.ProtectedBranches {
		if pb.Name == branch || matchesWildcard(pb.Name, branch) {
			return true
		}
	}
	return false
}

// projectDiagLabel returns a privacy-safe label for a project in diagnostics.
// At trust level, only the project ID is included; at audit+ the name is used.
func projectDiagLabel(proj gitlab.Project, level componentsdk.Level) string {
	if level.AtLeast(componentsdk.LevelAudit) {
		return fmt.Sprintf("project %s: fetch failed", proj.Name)
	}
	return fmt.Sprintf("project %d: fetch failed", proj.ID)
}

// analyzeProtection merges all protection rules that match the default branch.
// GitLab evaluates every matching rule: a permissive rule can widen access
// granted by a restrictive one. The merged result reflects the effective
// protection the branch actually has.
func (c *Collector) analyzeProtection(branches []gitlab.ProtectedBranch, defaultBranch string) *BranchProtectionDetail {
	matching := matchingProtectionRules(branches, defaultBranch)
	if len(matching) == 0 {
		return nil
	}
	return mergeProtectionRules(matching)
}

// matchingProtectionRules returns all protection rules whose name matches
// the given branch, whether by exact name or wildcard.
func matchingProtectionRules(branches []gitlab.ProtectedBranch, branch string) []*gitlab.ProtectedBranch {
	var result []*gitlab.ProtectedBranch
	for i := range branches {
		b := &branches[i]
		if b.Name == branch || matchesWildcard(b.Name, branch) {
			result = append(result, b)
		}
	}
	return result
}

// mergeProtectionRules combines multiple matching rules into the effective
// protection. GitLab merges rules permissively: if any rule allows force
// push, force push is allowed. Push/merge access levels are unioned across
// all rules so the least restrictive grant wins.
func mergeProtectionRules(rules []*gitlab.ProtectedBranch) *BranchProtectionDetail {
	allowForcePush := false
	codeOwnerApproval := false
	var allPushLevels []gitlab.BranchAccessLevel
	var allMergeLevels []gitlab.BranchAccessLevel

	for _, r := range rules {
		if r.AllowForcePush {
			allowForcePush = true
		}
		if r.CodeOwnerApprovalRequired {
			codeOwnerApproval = true
		}
		allPushLevels = append(allPushLevels, r.PushAccessLevels...)
		allMergeLevels = append(allMergeLevels, r.MergeAccessLevels...)
	}

	return &BranchProtectionDetail{
		AllowForcePush:            allowForcePush,
		CodeOwnerApprovalRequired: codeOwnerApproval,
		MergeAccessRestricted:     isMergeRestricted(allMergeLevels),
		PushAccessRestricted:      isPushRestricted(allPushLevels),
		MergeRequestRequired:      isMRRequired(allPushLevels),
	}
}

// matchesWildcard checks if a GitLab wildcard pattern matches a branch name.
// GitLab uses * as a glob that matches zero or more characters (including /).
// Patterns may contain multiple * segments (e.g. *gitlab*).
func matchesWildcard(pattern, name string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == name
	}
	segments := strings.Split(pattern, "*")
	pos := 0
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		idx := strings.Index(name[pos:], seg)
		if idx < 0 {
			return false
		}
		if i == 0 && idx != 0 {
			return false
		}
		pos += idx + len(seg)
	}
	if last := segments[len(segments)-1]; last != "" {
		return strings.HasSuffix(name, last)
	}
	return true
}

// isMergeRestricted returns true when merge access is limited to Developer (30) or above.
func isMergeRestricted(levels []gitlab.BranchAccessLevel) bool {
	for _, mal := range levels {
		if mal.AccessLevel >= 30 {
			return true
		}
	}
	return false
}

// isPushRestricted returns true when push access is limited (no direct push
// to anyone below Developer).
func isPushRestricted(levels []gitlab.BranchAccessLevel) bool {
	for _, pal := range levels {
		if pal.AccessLevel >= 30 {
			return true
		}
	}
	return false
}

// isMRRequired returns true when no one can push directly to the branch,
// meaning all changes must go through a merge request.
//
// GitLab sets access_level=0 with no user/group/deploy_key grants to mean
// "No one". If any level > 0 exists, or any individual user/group/deploy_key
// grant exists, direct push is possible.
func isMRRequired(levels []gitlab.BranchAccessLevel) bool {
	if len(levels) == 0 {
		return false
	}
	for _, pal := range levels {
		if pal.AccessLevel > 0 {
			return false
		}
		if pal.UserID != nil || pal.GroupID != nil || pal.DeployKeyID != nil {
			return false
		}
	}
	return true
}

func (c *Collector) populatePosture(posture *GroupPosture, group *gitlab.Group, metrics *projectMetrics, included []gitlab.Project, includePatterns, excludePatterns []string, totalProjects int) {
	twoFA := group.RequireTwoFactorAuthentication
	posture.AccessControl = AccessControl{
		TwoFactorRequired: &twoFA,
	}

	total := len(included)
	posture.Scope = Scope{
		IncludePatterns:  includePatterns,
		ExcludePatterns:  excludePatterns,
		ProjectsCoverage: percent(total, totalProjects),
	}

	posture.Posture = Posture{
		BranchProtectionCoverage: percent(metrics.branchProtected, total),
		SecurityFeaturesCoverage: c.securityFeaturesCoverage(metrics, total),
	}

	posture.BranchProtectionRules = BranchProtectionRules{
		MergeRequestRequired: percent(metrics.mergeRestricted, total),
		ApprovingReviews:     percent(metrics.approvingReviews, total),
		CodeOwnerApproval:    percent(metrics.codeOwnerApproval, total),
		NoForcePush:          percent(metrics.noForcePush, total),
	}

	posture.SecurityFeatures = SecurityFeatures{
		SecretPushProtection: percent(metrics.secretPushProt, total),
		PipelineRequired:    percent(metrics.pipelineRequired, total),
	}
}

func (c *Collector) securityFeaturesCoverage(metrics *projectMetrics, total int) int {
	if total == 0 {
		return 0
	}
	features := []int{metrics.secretPushProt, metrics.pipelineRequired}
	sum := 0
	for _, f := range features {
		sum += f
	}
	return percent(sum, total*len(features))
}

func percent(count, total int) int {
	if total == 0 {
		return 0
	}
	return (count * MaxPercentage) / total
}

var errAuthFailed = fmt.Errorf("authentication failed: invalid or expired token")

func isUnauthorized(err error) bool {
	return err != nil && errors.Is(err, gitlab.ErrUnauthorized)
}

func isDenied(err error) bool {
	return err != nil && errors.Is(err, gitlab.ErrPermissionDenied)
}

func isNotFound(err error) bool {
	return err != nil && errors.Is(err, gitlab.ErrNotFound)
}

func webhookHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}
