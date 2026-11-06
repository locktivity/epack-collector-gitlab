package collector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
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
	ListBillableMembers(ctx context.Context, groupID string) ([]gitlab.BillableMember, error)
	ListGroupWebhooks(ctx context.Context, groupID string) ([]gitlab.Webhook, error)
	ListProjectWebhooks(ctx context.Context, projectID int) ([]gitlab.Webhook, error)
	ListProjectDeployKeys(ctx context.Context, projectID int) ([]gitlab.DeployKey, error)
	ListGroupRunners(ctx context.Context, groupID string) ([]gitlab.Runner, error)
	ListGroupAuditEvents(ctx context.Context, groupID string, since time.Time) ([]gitlab.AuditEvent, error)
	ListGroupAccessTokens(ctx context.Context, groupID string) ([]gitlab.AccessToken, error)
	ListProjectAccessTokens(ctx context.Context, projectID int) ([]gitlab.AccessToken, error)
	ListSecurityScanners(ctx context.Context, projectIDs []int) (map[int]gitlab.SecurityScanners, error)
	ListGroupVulnerabilities(ctx context.Context, fullPath string) (*gitlab.Vulnerabilities, error)
}

// Collector collects GitLab group security posture.
type Collector struct {
	client GitLabClient
	config Config
	gaps   *gapLog
	diag   *diagnosticsTracker
	reads  *reads
}

// reads holds what the run read that the access-posture and vuln-scanning
// artifacts are built from. subgroup is true when the configured group is a
// subgroup, and ipRestricted when it is a top-level group that restricts
// access by IP address.
type reads struct {
	subgroup, ipRestricted bool

	projectsErr error
	included    []gitlab.Project

	members     []gitlab.Member
	membersErr  error
	billable    []gitlab.BillableMember
	billableErr error
	deployKeys  projectLists[gitlab.DeployKey]

	groupTokens    []gitlab.AccessToken
	groupTokensErr error
	projectTokens  projectLists[gitlab.AccessToken]

	scanners       map[int]gitlab.SecurityScanners
	scannersFailed int
	scannersErr    error
	vulns          *gitlab.Vulnerabilities
	vulnsErr       error
}

// projectLists holds one list read from each assessed project, and how many
// of those reads failed.
type projectLists[T any] struct {
	lists       []projectList[T]
	failed      int
	err         error
	failedNames []string
}

type projectList[T any] struct {
	project gitlab.Project
	items   []T
}

// New creates a new Collector.
func New(config Config, client GitLabClient) *Collector {
	return &Collector{
		client: client,
		config: config,
		gaps:   newGapLog(config.Recorder, componentsdk.LevelTrust),
		diag:   &diagnosticsTracker{},
		reads:  &reads{},
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

func (c *Collector) now() time.Time {
	if c.config.Now != nil {
		return c.config.Now()
	}
	return time.Now()
}

// Collect fetches and aggregates security posture metrics for the group. It
// returns an error only for invalid configuration or a failed sign-in. Any
// value it cannot read after the sign-in is left out of the artifact and
// recorded as a gap.
func (c *Collector) Collect(ctx context.Context, level componentsdk.Level) (*GroupPosture, error) {
	if c.config.Group == "" {
		return nil, componentsdk.NewConfigError("group is required")
	}

	includePatterns := c.config.IncludePatterns
	if len(includePatterns) == 0 {
		includePatterns = []string{DefaultIncludePattern}
	}
	excludePatterns := c.config.ExcludePatterns
	if excludePatterns == nil {
		excludePatterns = []string{}
	}

	if err := validatePatterns(includePatterns); err != nil {
		return nil, componentsdk.NewConfigError("include_patterns: %v", err)
	}
	if err := validatePatterns(excludePatterns); err != nil {
		return nil, componentsdk.NewConfigError("exclude_patterns: %v", err)
	}

	c.gaps = newGapLog(c.config.Recorder, level)
	c.diag = &diagnosticsTracker{}
	c.reads = &reads{}

	c.status(fmt.Sprintf("Connecting to GitLab group %s...", c.config.Group))
	group, err := c.signIn(ctx)
	if err != nil {
		return nil, err
	}
	c.reads.subgroup = group.ParentID != nil
	c.reads.ipRestricted = !c.reads.subgroup && group.IPRestrictionRanges != ""

	posture := NewGroupPosture(c.config.Group, c.now())
	posture.fullPath = groupPath(group, c.config.Group)
	posture.CollectedAtLevel = string(level)
	posture.Scope.IncludePatterns = includePatterns
	posture.Scope.ExcludePatterns = excludePatterns
	c.fillAccessControl(posture, group, level)

	c.status("Fetching projects...")
	allProjects, projectsErr := c.client.ListProjects(ctx, c.config.Group)
	var included []gitlab.Project
	if projectsErr != nil {
		c.leaveOutProjects(projectsErr, level)
	} else {
		included = filterProjects(allProjects, includePatterns, excludePatterns)
		c.status(fmt.Sprintf("Found %d projects (%d after filtering)...", len(allProjects), len(included)))
		metrics := c.computeMetrics(ctx, included, level)
		c.fillProjectMetrics(posture, metrics, len(allProjects), len(included))
		if level.AtLeast(componentsdk.LevelAudit) {
			c.collectProjects(posture, included, metrics)
		}
	}
	c.reads.projectsErr, c.reads.included = projectsErr, included

	// The access-posture artifact reads members and deploy keys at every
	// level. The detailed artifact holds them from the audit level.
	audit := level.AtLeast(componentsdk.LevelAudit)
	if audit || c.config.AccessPosture {
		c.readMembers(ctx)
		if projectsErr == nil {
			c.readDeployKeys(ctx, included)
		}
	}
	if audit {
		c.collectMembers(posture)
		c.collectWebhooks(ctx, posture, included, projectsErr, level)
		c.collectDeployKeys(posture, projectsErr, level)
		c.collectRunners(ctx, posture)
	}
	if c.config.AccessPosture {
		c.readBillableMembers(ctx)
		c.readAccessTokens(ctx, included, projectsErr)
	}
	if c.config.VulnScanning && projectsErr == nil {
		c.readVulnerabilities(ctx, groupPath(group, c.config.Group), included)
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		c.collectAuditLog(ctx, posture)
	}
	if ctx.Err() != nil {
		c.diag.warn("collection stopped before it finished; values it had not read are left out")
	}

	posture.Diagnostics = c.diag.toDiagnostics()

	c.status("Collection complete")
	return posture, nil
}

// signIn reads the configured group, the only call whose failure fails the
// run: a rejected token, a token that cannot read the group, or a group that
// does not exist leaves nothing worth emitting.
func (c *Collector) signIn(ctx context.Context) (*gitlab.Group, error) {
	group, err := c.client.GetGroup(ctx, c.config.Group)
	switch {
	case gitlab.GroupNotFound(err):
		return nil, componentsdk.CodeError(componentsdk.CodeConfigInvalid,
			fmt.Errorf("group %q was not found, or the token cannot see it; check group and base_url: %w", c.config.Group, err))
	case err != nil:
		return nil, fmt.Errorf("reading group %q: %w", c.config.Group, err)
	case group.ID == 0:
		return nil, componentsdk.CodeError(componentsdk.CodeInvalidResponse,
			fmt.Errorf("reading group %q: the response has no id", c.config.Group))
	}
	c.gaps.rec.SignedInAs(componentsdk.Principal{
		Provider: "gitlab",
		Kind:     "access_token",
		TenantID: c.tenantID(group),
	})
	return group, nil
}

// tenantID names the group with its instance, such as gitlab.com/acme.
func (c *Collector) tenantID(group *gitlab.Group) string {
	path := group.FullPath
	if path == "" {
		path = c.config.Group
	}
	if host, err := gitlab.Host(c.config.BaseURL); err == nil {
		return host + "/" + path
	}
	return path
}

func (c *Collector) fillAccessControl(posture *GroupPosture, group *gitlab.Group, level componentsdk.Level) {
	twoFactor := twoFactorRequired(group)
	if twoFactor == nil {
		c.gaps.leaveOut(groupFieldMissing("require_two_factor_authentication"), "/access_control/two_factor_required")
	}
	posture.AccessControl.TwoFactorRequired = twoFactor
	if !level.AtLeast(componentsdk.LevelAudit) {
		return
	}
	if group.ProjectCreationLevel == nil {
		c.gaps.leaveOut(groupFieldMissing("project_creation_level"), "/access_control/project_creation_level")
	}
	posture.AccessControl.ProjectCreationLevel = group.ProjectCreationLevel
	if group.ShareWithGroupLock == nil {
		c.gaps.leaveOut(groupFieldMissing("share_with_group_lock"), "/access_control/share_with_group_lock")
	}
	posture.AccessControl.ShareWithGroupLock = group.ShareWithGroupLock
}

// twoFactorRequired returns whether members of the group must set up 2FA.
// They must when an ancestor group requires it, even if the group's own
// setting is false. The ancestor's setting is in the response from GitLab
// 19.6. On older versions only the group's own setting is read.
func twoFactorRequired(group *gitlab.Group) *bool {
	if ancestor := group.RequireTwoFactorFromAncestor; ancestor != nil && *ancestor {
		return ancestor
	}
	return group.RequireTwoFactorAuthentication
}

func groupFieldMissing(field string) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("the group response has no %s", field))
}

// leaveOutProjects records every value the project list feeds as left out.
func (c *Collector) leaveOutProjects(err error, level componentsdk.Level) {
	if gitlab.StatusOf(err) == http.StatusForbidden {
		c.diag.surfacePermissionDenied("projects", "permission denied (requires read_api scope)")
	} else {
		c.diag.surfaceUnavailable("projects", "fetch failed: "+safeDiagError(err))
	}
	c.gaps.leaveOut(err,
		"/scope/projects_coverage", "/scope/project_count", "/scope/included_project_count",
		"/posture/branch_protection_coverage", "/posture/security_features_coverage",
		"/branch_protection_rules/merge_request_required", "/branch_protection_rules/approving_reviews",
		"/branch_protection_rules/code_owner_approval", "/branch_protection_rules/no_force_push",
		"/security_features/secret_push_protection", "/security_features/pipeline_required")
	if level.AtLeast(componentsdk.LevelAudit) {
		c.gaps.leaveOut(err, "/projects", "/webhooks/project_count", "/deploy_keys")
	}
	if level.AtLeast(componentsdk.LevelInternal) {
		c.gaps.leaveOut(err, "/webhooks/project")
	}
}

func filterProjects(all []gitlab.Project, includePatterns, excludePatterns []string) []gitlab.Project {
	included := []gitlab.Project{}
	for _, p := range all {
		if matchesAny(p.Name, excludePatterns) {
			continue
		}
		if matchesAny(p.Name, includePatterns) {
			included = append(included, p)
		}
	}
	return included
}

// projectMetrics counts the included projects for each rollup, and the
// projects whose value for a rollup could not be read.
type projectMetrics struct {
	branchProtected      int
	mergeRequestRequired int
	codeOwnerApproval    int
	noForcePush          int
	approvingReviews     int
	secretPushProtection int
	pipelineRequired     int

	branchUnknown     int
	branchErr         error
	approvingUnknown  int
	approvingErr      error
	secretPushUnknown int
	pipelineUnknown   int
	featuresUnknown   int

	results map[int]*projectResult
}

// projectResult is what the collector read about one project's default
// branch, or why it could not.
type projectResult struct {
	protection    *BranchProtectionDetail
	protectionErr error
	approval      *ApprovalDetail
	approvalErr   error
}

func (c *Collector) computeMetrics(ctx context.Context, projects []gitlab.Project, level componentsdk.Level) *projectMetrics {
	m := &projectMetrics{results: make(map[int]*projectResult)}

	total := int64(len(projects))
	for i, proj := range projects {
		c.progress(int64(i+1), total, fmt.Sprintf("Analyzing %s", proj.Name))
		m.countFeatures(proj)

		if proj.DefaultBranch == "" {
			continue
		}
		r := &projectResult{}
		m.results[proj.ID] = r

		branches, err := c.client.ListProtectedBranches(ctx, proj.ID)
		if err != nil {
			c.protectionDiagnostics(ctx, proj, err, level)
			r.protectionErr, r.approvalErr = err, err
			m.branchUnknown++
			m.approvingUnknown++
			m.branchErr = firstError(m.branchErr, err)
			m.approvingErr = firstError(m.approvingErr, err)
			continue
		}

		r.protection = c.analyzeProtection(branches, proj.DefaultBranch)
		m.countProtection(r.protection)

		var approving *bool
		approving, r.approval, r.approvalErr = c.approvalStatus(ctx, proj, r.protection != nil, level)
		switch {
		case approving == nil:
			m.approvingUnknown++
			m.approvingErr = firstError(m.approvingErr, r.approvalErr)
		case *approving:
			m.approvingReviews++
		}
	}

	return m
}

func (m *projectMetrics) countFeatures(proj gitlab.Project) {
	secretPush := proj.SecretPushProtectionEnabled // LINT-ALLOW: boolean setting, not a secret value
	pipeline := proj.OnlyAllowMergeIfPipelineSucceeds
	switch {
	case secretPush == nil:
		m.secretPushUnknown++
	case *secretPush:
		m.secretPushProtection++
	}
	switch {
	case pipeline == nil:
		m.pipelineUnknown++
	case *pipeline:
		m.pipelineRequired++
	}
	if secretPush == nil || pipeline == nil {
		m.featuresUnknown++
	}
}

func (m *projectMetrics) countProtection(detail *BranchProtectionDetail) {
	if detail == nil {
		return
	}
	m.branchProtected++
	if detail.MergeRequestRequired {
		m.mergeRequestRequired++
	}
	if detail.CodeOwnerApprovalRequired {
		m.codeOwnerApproval++
	}
	if !detail.AllowForcePush {
		m.noForcePush++
	}
}

func (c *Collector) protectionDiagnostics(ctx context.Context, proj gitlab.Project, err error, level componentsdk.Level) {
	switch {
	case ctx.Err() != nil:
		// Out of time: Collect notes that once, not once per project.
	case gitlab.StatusOf(err) == http.StatusForbidden:
		c.diag.surfacePermissionDenied("protected_branches", "permission denied (requires read_api scope)")
	default:
		c.diag.surfaceUnavailable("protected_branches", projectDiagLabel(proj, level))
	}
}

// approvalStatus reads a project's approval settings and rules. It returns
// whether merge requests to the default branch need an approval, or nil when
// a read that failed could have said so; the approval detail; and the error
// that kept the detail from being read.
func (c *Collector) approvalStatus(ctx context.Context, proj gitlab.Project, protected bool, level componentsdk.Level) (*bool, *ApprovalDetail, error) {
	settings, settingsErr := c.client.GetApprovalSettings(ctx, proj.ID)
	rules, rulesErr := c.client.ListApprovalRules(ctx, proj.ID)
	c.approvalDiagnostics(proj, settingsErr, rulesErr, level)

	required := 0
	if settingsErr == nil {
		required = settings.ApprovalsBeforeMerge
	}
	if rulesErr == nil {
		for _, rule := range rules {
			if ruleIsUnconditional(rule) && ruleAppliesToBranch(rule, proj.DefaultBranch, protected) && rule.ApprovalsRequired > required {
				required = rule.ApprovalsRequired
			}
		}
	}

	approving := required > 0
	err := firstError(settingsErr, rulesErr)
	switch {
	case err == nil && approving:
		return &approving, &ApprovalDetail{
			ApprovalsRequired:                      required,
			ResetApprovalsOnPush:                   settings.ResetApprovalsOnPush,
			MergeRequestsDisableCommittersApproval: settings.MergeRequestsDisableCommittersApproval,
		}, nil
	case err == nil:
		return &approving, nil, nil
	case approving:
		// The read that failed may require more approvals than the one that
		// answered, so only the yes is known.
		return &approving, nil, err
	default:
		return nil, nil, err
	}
}

func (c *Collector) approvalDiagnostics(proj gitlab.Project, settingsErr, rulesErr error, level componentsdk.Level) {
	settingsDenied := deniedOrMissing(settingsErr)
	rulesDenied := deniedOrMissing(rulesErr)
	if settingsErr != nil && !settingsDenied {
		c.diag.surfaceUnavailable("approval_settings", projectDiagLabel(proj, level))
	}
	if rulesErr != nil && !rulesDenied {
		c.diag.surfaceUnavailable("approval_rules", projectDiagLabel(proj, level))
	}
	switch {
	case settingsDenied && rulesDenied:
		c.diag.surfacePermissionDenied("approvals", "approval settings and rules both inaccessible (may require Maintainer role or Premium tier)")
	case settingsDenied:
		c.diag.surfacePermissionDenied("approval_settings", "approval settings inaccessible (may require Maintainer role or Premium tier)")
	case rulesDenied:
		c.diag.surfacePermissionDenied("approval_rules", "approval rules inaccessible (may require Premium tier)")
	}
}

func deniedOrMissing(err error) bool {
	status := gitlab.StatusOf(err)
	return status == http.StatusForbidden || status == http.StatusNotFound
}

func (c *Collector) fillProjectMetrics(posture *GroupPosture, m *projectMetrics, listed, included int) {
	posture.Scope.ProjectCount = &listed
	posture.Scope.IncludedProjectCount = &included
	posture.Scope.ProjectsCoverage = percent(included, listed)
	posture.counts = ruleCounts{
		mergeRequestRequired: m.mergeRequestRequired,
		approvingReviews:     m.approvingReviews,
		pipelineRequired:     m.pipelineRequired,
	}

	if m.branchUnknown > 0 {
		c.gaps.partial(m.branchUnknown, m.branchErr,
			"/posture/branch_protection_coverage", "/branch_protection_rules/merge_request_required",
			"/branch_protection_rules/code_owner_approval", "/branch_protection_rules/no_force_push")
	} else {
		posture.Posture.BranchProtectionCoverage = percent(m.branchProtected, included)
		posture.BranchProtectionRules.MergeRequestRequired = percent(m.mergeRequestRequired, included)
		posture.BranchProtectionRules.CodeOwnerApproval = percent(m.codeOwnerApproval, included)
		posture.BranchProtectionRules.NoForcePush = percent(m.noForcePush, included)
	}
	if m.approvingUnknown > 0 {
		c.gaps.partial(m.approvingUnknown, m.approvingErr, "/branch_protection_rules/approving_reviews")
	} else {
		posture.BranchProtectionRules.ApprovingReviews = percent(m.approvingReviews, included)
	}

	var featuresErr error
	if m.secretPushUnknown > 0 {
		c.diag.surfaceUnavailable("secret_push_protection",
			fmt.Sprintf("%d of %d projects did not report secret push protection status (may require Ultimate tier or Maintainer role)", m.secretPushUnknown, included))
		featuresErr = secretPushHidden(m.secretPushUnknown, included)
		c.gaps.partial(m.secretPushUnknown, featuresErr, "/security_features/secret_push_protection")
	} else {
		posture.SecurityFeatures.SecretPushProtection = percent(m.secretPushProtection, included) // LINT-ALLOW: coverage percentage, not a secret value
	}
	if m.pipelineUnknown > 0 {
		err := componentsdk.CodeError(componentsdk.CodeInvalidResponse,
			fmt.Errorf("%d of %d projects in the project list have no only_allow_merge_if_pipeline_succeeds", m.pipelineUnknown, included))
		featuresErr = firstError(featuresErr, err)
		c.gaps.partial(m.pipelineUnknown, err, "/security_features/pipeline_required")
	} else {
		posture.SecurityFeatures.PipelineRequired = percent(m.pipelineRequired, included)
	}
	if m.featuresUnknown > 0 {
		c.gaps.partial(m.featuresUnknown, featuresErr, "/posture/security_features_coverage")
	} else {
		posture.Posture.SecurityFeaturesCoverage = percent(m.secretPushProtection+m.pipelineRequired, 2*included)
	}
}

// secretPushHidden explains projects listed without
// secret_push_protection_enabled, which GitLab returns only with Ultimate, to
// the Developer role and above. When no project has it the plan most likely
// lacks the feature; when only some lack it, the token's role differs
// between projects.
func secretPushHidden(unknown, total int) error {
	err := fmt.Errorf("GitLab did not return secret_push_protection_enabled for %d of %d projects; it returns it with Ultimate, to the Developer role and above", unknown, total)
	if unknown == total {
		return componentsdk.CodeError(componentsdk.CodeNotLicensed, err)
	}
	return componentsdk.CodeError(componentsdk.CodePermissionDenied, err)
}

// ruleIsUnconditional reports whether the rule's approvals are required on
// every merge request it applies to. A report_approver rule comes from a
// merge request approval policy or from Coverage-Check. Its approvals are
// required only when its condition is met, such as a scan finding or a drop
// in coverage. A report_approver rule whose report_type is any_merge_request
// applies to every merge request.
func ruleIsUnconditional(rule gitlab.ApprovalRule) bool {
	return rule.RuleType != "report_approver" || rule.ReportType == "any_merge_request"
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
// GitLab sets access_level=0 with no user/group/deploy_key/member_role grants
// to mean "No one". A rule with no push access levels at all, as after every
// push selection is cleared, also lets no one push. If any level > 0 exists,
// or any individual grant exists (user, group, deploy key, or custom member
// role), direct push is possible.
func isMRRequired(levels []gitlab.BranchAccessLevel) bool {
	for _, pal := range levels {
		if pal.AccessLevel > 0 {
			return false
		}
		if pal.UserID != nil || pal.GroupID != nil || pal.DeployKeyID != nil || pal.MemberRoleID != nil {
			return false
		}
	}
	return true
}

// percent returns count as a whole percentage of total, or nil when total is
// 0, since a percentage of nothing has no value.
func percent(count, total int) *int {
	if total == 0 {
		return nil
	}
	p := (count * MaxPercentage) / total
	return &p
}

// Artifacts returns the detailed artifact and the normalized vcs-posture
// artifact derived from it, whose values carry the gaps of the detailed
// values they copy. It adds the access-posture and vuln-scanning artifacts
// when the run collects them.
func (c *Collector) Artifacts(posture *GroupPosture) []componentsdk.CollectedArtifact {
	c.gaps.mirrorNormalized()
	vcs := posture.ToVCSPosture()
	artifacts := []componentsdk.CollectedArtifact{
		{Data: posture, Path: DetailedPath},
		{Data: vcs, Schema: NormalizedSchema, Path: NormalizedPath},
	}
	if c.config.AccessPosture {
		artifacts = append(artifacts, componentsdk.CollectedArtifact{Data: c.accessPosture(posture), Schema: AccessSchema, Path: AccessPath})
	}
	if c.config.VulnScanning {
		vs := c.vulnScanning(posture)
		vcs.SecurityFeatures = c.securityFeatures(vs)
		artifacts = append(artifacts, componentsdk.CollectedArtifact{Data: vs, Schema: VulnSchema, Path: VulnPath})
	}
	return artifacts
}

// groupPath is the group's full path, which the GraphQL group query takes.
// configured is the group as the config names it, which can be a numeric
// ID.
func groupPath(group *gitlab.Group, configured string) string {
	if group.FullPath != "" {
		return group.FullPath
	}
	return configured
}

// urlPlaceholder matches a masked part of a webhook URL, such as {token}.
var urlPlaceholder = regexp.MustCompile(`\{[a-z0-9_]+\}`)

// The errors for a webhook row without url_host. Neither one holds the URL.
var (
	errMaskedHost = componentsdk.CodeError(componentsdk.CodeUnsupported, errors.New("the webhook URL's host is masked"))
	errNoHost     = componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("a webhook URL in the response has no readable host"))
)

// webhookHost returns the host of a webhook's URL, with its port. The URL is
// read twice, with each placeholder set to 1 and then to 2. A host that
// differs between the two holds a masked part, so it is not known.
func webhookHost(rawURL string) (string, error) {
	one, errOne := url.Parse(urlPlaceholder.ReplaceAllString(rawURL, "1"))
	two, errTwo := url.Parse(urlPlaceholder.ReplaceAllString(rawURL, "2"))
	switch {
	case errOne != nil || errTwo != nil || one.Host == "":
		return "", errNoHost
	case one.Host != two.Host:
		return "", errMaskedHost
	}
	return one.Host, nil
}
