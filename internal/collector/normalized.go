package collector

import (
	"encoding/json"

	"github.com/locktivity/epack/componentsdk"
)

// VCSPosture represents the normalized version control system posture.
// This follows the evidencepack/vcs-posture@v1 schema specification. A value
// the detailed artifact left out is absent here too, with the same gap, and
// so is a section whose every value is. A percentage over no selected
// projects is null. RepositoriesPresent is written at every level and is
// false when the filters select no project. The project counts are written
// from the audit level, as the schema specifies. Values this collector does
// not read are absent, with a not_read gap, and named in
// unavailable_sources. OrgSecurity and SecurityFeatures are deprecated
// blocks, written at every level as before epack v0.10.0 (see
// deprecated.go).
type VCSPosture struct {
	SchemaVersion          string                     `json:"schema_version"`
	CollectedAt            string                     `json:"collected_at"`
	Provider               string                     `json:"provider"`
	Organization           string                     `json:"organization,omitempty"`
	RepositoriesPresent    *bool                      `json:"repositories_present,omitempty"`
	RepositoryCount        *int                       `json:"repository_count,omitempty"`
	ScannedRepositoryCount *int                       `json:"scanned_repository_count,omitempty"`
	RepoCoveragePct        Reading[float64]           `json:"repo_coverage_pct,omitzero"`
	BranchProtection       VCSPostureBranchProtection `json:"branch_protection,omitzero"`
	UnavailableSources     []string                   `json:"unavailable_sources,omitempty"`
	OrgSecurity            VCSPostureOrgSecurity      `json:"org_security,omitzero"`
	SecurityFeatures       VCSPostureSecurityFeatures `json:"security_features,omitzero"`
}

// Reading is a normalized value that may have no reading in the detailed
// artifact. It is left out when Read is false. Otherwise it is written as
// Value, which is nil for a percentage over no projects.
type Reading[T any] struct {
	Value *T
	Read  bool
}

// IsZero reports whether the value has no reading, for omitzero.
func (r Reading[T]) IsZero() bool { return !r.Read }

// MarshalJSON writes the value, or null.
func (r Reading[T]) MarshalJSON() ([]byte, error) { return json.Marshal(r.Value) }

// VCSPostureBranchProtection contains branch protection coverage metrics.
// From the audit level it also holds how many projects meet each one.
type VCSPostureBranchProtection struct {
	PRRequiredRepositoryCount       *int             `json:"pr_required_repository_count,omitempty"`
	ApprovingReviewsRepositoryCount *int             `json:"approving_reviews_repository_count,omitempty"`
	StatusChecksRepositoryCount     *int             `json:"status_checks_repository_count,omitempty"`
	PRRequiredPct                   Reading[float64] `json:"pr_required_pct,omitzero"`
	ApprovingReviewsPct             Reading[float64] `json:"approving_reviews_pct,omitzero"`
	StatusChecksPct                 Reading[float64] `json:"status_checks_pct,omitzero"`
}

// ToVCSPosture transforms detailed GitLab output to normalized vcs-posture
// format. It writes the project counts when the detailed artifact was
// collected at the audit level or above.
func (g *GroupPosture) ToVCSPosture() *VCSPosture {
	unavailable := []string{
		"signed_commits: the reject_unsigned_commits push rule is not collected",
	}
	if g.Diagnostics != nil {
		unavailable = append(unavailable, g.Diagnostics.PermissionErrors...)
		unavailable = append(unavailable, g.Diagnostics.Warnings...)
	}

	listed, included := g.Scope.ProjectCount, g.Scope.IncludedProjectCount
	var present *bool
	if included != nil {
		present = ptr(*included > 0)
	}
	none := present != nil && !*present
	pct := func(p *int) Reading[float64] { return percentage(p, none) }
	bp, sf := g.BranchProtectionRules, g.SecurityFeatures

	organization := g.fullPath
	if organization == "" {
		organization = g.Group
	}
	posture := &VCSPosture{
		SchemaVersion:       "1.0.0",
		CollectedAt:         g.CollectedAt,
		Provider:            "gitlab",
		Organization:        organization,
		RepositoriesPresent: present,
		// The coverage is over every listed project, so it is null only for
		// a group with no projects.
		RepoCoveragePct: percentage(g.Scope.ProjectsCoverage, listed != nil && *listed == 0),
		BranchProtection: VCSPostureBranchProtection{
			PRRequiredPct:       pct(bp.MergeRequestRequired),
			ApprovingReviewsPct: pct(bp.ApprovingReviews),
			StatusChecksPct:     pct(sf.PipelineRequired),
		},
		UnavailableSources: unavailable,
		OrgSecurity:        VCSPostureOrgSecurity{TwoFactorRequired: g.AccessControl.TwoFactorRequired},
	}
	if componentsdk.Level(g.CollectedAtLevel).AtLeast(componentsdk.LevelAudit) {
		n := g.counts
		posture.RepositoryCount = listed
		posture.ScannedRepositoryCount = included
		posture.BranchProtection.PRRequiredRepositoryCount = ruleCount(bp.MergeRequestRequired, n.mergeRequestRequired, none)
		posture.BranchProtection.ApprovingReviewsRepositoryCount = ruleCount(bp.ApprovingReviews, n.approvingReviews, none)
		posture.BranchProtection.StatusChecksRepositoryCount = ruleCount(sf.PipelineRequired, n.pipelineRequired, none)
	}
	return posture
}

// percentage returns the normalized reading of a detailed percentage. It
// returns pct's value when pct is set. When pct is nil, it returns null if
// none is true, meaning the population is empty. Otherwise it returns no
// reading, because the detailed artifact left the value out with a gap.
func percentage(pct *int, none bool) Reading[float64] {
	switch {
	case pct != nil:
		return Reading[float64]{Value: ptr(float64(*pct)), Read: true}
	case none:
		return Reading[float64]{Read: true}
	default:
		return Reading[float64]{}
	}
}

// ruleCount returns n when the rule's detailed percentage pct was read. n
// counts the selected projects that meet the rule. It returns 0 when none is
// true, since no project is selected. Otherwise it returns nil, because the
// percentage was left out with a gap and n covers only some projects.
func ruleCount(pct *int, n int, none bool) *int {
	switch {
	case pct != nil:
		return &n
	case none:
		return ptr(0)
	default:
		return nil
	}
}

func ptr[T any](v T) *T { return &v }
