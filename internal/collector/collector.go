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
			return nil, fmt.Errorf("authentication failed: invalid or expired token")
		}
		if isDenied(err) {
			diag.surfacePermissionDenied("group_settings", "permission denied (requires read_api scope)")
			group = &gitlab.Group{}
		} else {
			return nil, fmt.Errorf("fetching group: %w", err)
		}
	}

	c.status("Fetching projects...")

	allProjects, err := c.client.ListProjects(ctx, c.config.Group)
	if err != nil {
		if isUnauthorized(err) {
			return nil, fmt.Errorf("authentication failed: invalid or expired token")
		}
		if isDenied(err) {
			diag.surfacePermissionDenied("projects", "permission denied (requires read_api scope)")
			allProjects = nil
		} else {
			return nil, fmt.Errorf("fetching projects: %w", err)
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

	metrics := c.computeMetrics(ctx, included, diag)

	c.populatePosture(posture, group, metrics, included, includePatterns, excludePatterns, len(allProjects))

	c.collectSurfaces(ctx, posture, group, included, metrics, level, diag)

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

func (c *Collector) computeMetrics(ctx context.Context, projects []gitlab.Project, diag *diagnosticsTracker) *projectMetrics {
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
			if isDenied(err) {
				diag.surfacePermissionDenied("protected_branches", "permission denied (requires read_api scope)")
			} else {
				diag.surfaceUnavailable("protected_branches", fmt.Sprintf("project %s: %v", proj.Name, err))
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
		if err != nil && !isDenied(err) && !isNotFound(err) {
			diag.surfaceUnavailable("approval_settings", fmt.Sprintf("project %d: %v", proj.ID, err))
		}

		rules, rulesErr := c.client.ListApprovalRules(ctx, proj.ID)
		if rulesErr != nil && !isDenied(rulesErr) && !isNotFound(rulesErr) {
			diag.surfaceUnavailable("approval_rules", fmt.Sprintf("project %d: %v", proj.ID, rulesErr))
		}

		requiredApprovals := 0
		if err == nil && approvals != nil {
			requiredApprovals = approvals.ApprovalsBeforeMerge
		}
		for _, rule := range rules {
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

	return m
}

func (c *Collector) analyzeProtection(branches []gitlab.ProtectedBranch, defaultBranch string) *BranchProtectionDetail {
	rule := matchProtectionRule(branches, defaultBranch)
	if rule == nil {
		return nil
	}

	return &BranchProtectionDetail{
		AllowForcePush:            rule.AllowForcePush,
		CodeOwnerApprovalRequired: rule.CodeOwnerApprovalRequired,
		MergeAccessRestricted:     isMergeRestricted(rule),
		PushAccessRestricted:      isPushRestricted(rule),
		MergeRequestRequired:      isMRRequired(rule),
	}
}

// matchProtectionRule finds the most specific protection rule that applies to
// the default branch, following GitLab's precedence: exact name > wildcard.
func matchProtectionRule(branches []gitlab.ProtectedBranch, defaultBranch string) *gitlab.ProtectedBranch {
	var bestWildcard *gitlab.ProtectedBranch
	bestSpecificity := -1

	for i := range branches {
		b := &branches[i]
		if b.Name == defaultBranch {
			return b
		}
		if matchesWildcard(b.Name, defaultBranch) {
			specificity := wildcardSpecificity(b.Name)
			if specificity > bestSpecificity {
				bestSpecificity = specificity
				bestWildcard = b
			}
		}
	}
	return bestWildcard
}

// matchesWildcard checks if a GitLab wildcard pattern matches a branch name.
// GitLab uses simple * glob matching (not full regex).
func matchesWildcard(pattern, name string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == name
	}
	parts := strings.SplitN(pattern, "*", 2)
	return strings.HasPrefix(name, parts[0]) && strings.HasSuffix(name, parts[1])
}

// wildcardSpecificity returns the length of non-wildcard characters in a
// pattern. More specific patterns take precedence.
func wildcardSpecificity(pattern string) int {
	return len(strings.ReplaceAll(pattern, "*", ""))
}

// isMergeRestricted returns true when merge access is limited to Developer (30) or above.
func isMergeRestricted(b *gitlab.ProtectedBranch) bool {
	for _, mal := range b.MergeAccessLevels {
		if mal.AccessLevel >= 30 {
			return true
		}
	}
	return false
}

// isPushRestricted returns true when push access is limited (no direct push
// to anyone below Developer).
func isPushRestricted(b *gitlab.ProtectedBranch) bool {
	for _, pal := range b.PushAccessLevels {
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
// "No one". If any individual grants exist alongside access_level=0, direct
// push is still possible for those grantees.
func isMRRequired(b *gitlab.ProtectedBranch) bool {
	if len(b.PushAccessLevels) == 0 {
		return false
	}
	for _, pal := range b.PushAccessLevels {
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

func isUnauthorized(err error) bool {
	return err != nil && errors.Is(err, gitlab.ErrUnauthorized)
}

func isDenied(err error) bool {
	return err != nil && (errors.Is(err, gitlab.ErrPermissionDenied) || errors.Is(err, gitlab.ErrUnauthorized))
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
