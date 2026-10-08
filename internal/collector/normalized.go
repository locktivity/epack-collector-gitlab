package collector

import "time"

// VCSPosture represents the normalized version control system posture.
// This follows the evidencepack/vcs-posture@v1 schema specification.
type VCSPosture struct {
	SchemaVersion      string                     `json:"schema_version"`
	CollectedAt        string                     `json:"collected_at"`
	Provider           string                     `json:"provider"`
	Organization       string                     `json:"organization"`
	OrgSecurity        VCSPostureOrgSecurity      `json:"org_security"`
	RepoCoveragePct    float64                    `json:"repo_coverage_pct"`
	BranchProtection   VCSPostureBranchProtection `json:"branch_protection"`
	SecurityFeatures   VCSPostureSecurityFeatures `json:"security_features"`
	UnavailableSources []string                   `json:"unavailable_sources,omitempty"`
}

type VCSPostureOrgSecurity struct {
	TwoFactorRequired bool `json:"two_factor_required"`
}

type VCSPostureBranchProtection struct {
	PRRequiredPct       float64 `json:"pr_required_pct"`
	ApprovingReviewsPct float64 `json:"approving_reviews_pct"`
	StatusChecksPct     float64 `json:"status_checks_pct"`
	SignedCommitsPct    float64 `json:"signed_commits_pct"`
}

type VCSPostureSecurityFeatures struct {
	VulnAlertsPct     float64 `json:"vuln_alerts_pct"`
	SecretScanningPct float64 `json:"secret_scanning_pct"`
	CodeScanningPct   float64 `json:"code_scanning_pct"`
}

// ToVCSPosture transforms detailed GitLab output to normalized vcs-posture format.
func (g *GroupPosture) ToVCSPosture() *VCSPosture {
	twoFA := g.AccessControl.TwoFactorRequired != nil && *g.AccessControl.TwoFactorRequired

	unavailable := []string{
		"signed_commits: not available via GitLab API",
		"vuln_alerts: requires Ultimate tier; not collected",
		"code_scanning: SAST configuration not queryable via GitLab REST API",
	}
	if g.Diagnostics != nil {
		unavailable = append(unavailable, g.Diagnostics.PermissionErrors...)
		unavailable = append(unavailable, g.Diagnostics.Warnings...)
	}

	return &VCSPosture{
		SchemaVersion:   "1.0.0",
		CollectedAt:     time.Now().UTC().Format(time.RFC3339),
		Provider:        "gitlab",
		Organization:    g.Group,
		RepoCoveragePct: float64(g.Scope.ProjectsCoverage),
		OrgSecurity: VCSPostureOrgSecurity{
			TwoFactorRequired: twoFA,
		},
		BranchProtection: VCSPostureBranchProtection{
			PRRequiredPct:       float64(g.BranchProtectionRules.MergeRequestRequired),
			ApprovingReviewsPct: float64(g.BranchProtectionRules.ApprovingReviews),
			StatusChecksPct:     float64(g.SecurityFeatures.PipelineRequired),
			SignedCommitsPct:    0,
		},
		SecurityFeatures: VCSPostureSecurityFeatures{
			VulnAlertsPct:     0,
			SecretScanningPct: float64(g.SecurityFeatures.SecretPushProtection), // LINT-ALLOW: coverage percentage, not a secret value
			CodeScanningPct:   0,
		},
		UnavailableSources: unavailable,
	}
}
