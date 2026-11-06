package collector

import (
	"fmt"

	"github.com/locktivity/epack/componentsdk"
)

// Artifact paths in the pack, as componentsdk.ArtifactPath gives them for
// the collector's own name.
const (
	DetailedPath   = "artifacts/gitlab.details.json"
	NormalizedPath = "artifacts/gitlab.vcs-posture.json"
	// NormalizedSchema is the normalized artifact's schema.
	NormalizedSchema = "evidencepack/vcs-posture@v1"
	// AccessSchema and VulnSchema are the schemas of the access-posture and
	// vuln-scanning artifacts.
	AccessSchema = "evidencepack/access-posture@v1"
	VulnSchema   = "evidencepack/vuln-scanning@v1"
)

// The paths of the access-posture and vuln-scanning artifacts.
var (
	AccessPath = componentsdk.ArtifactPath(collectorName, AccessSchema)
	VulnPath   = componentsdk.ArtifactPath(collectorName, VulnSchema)
)

const collectorName = "gitlab"

// gapLog records each value the collector leaves out in the run's recorder.
// level is the level the run collects at. Its methods mark themselves with
// Recorder.Helper, so each gap's source is the line that called them.
type gapLog struct {
	rec   *componentsdk.Recorder
	level componentsdk.Level
}

func newGapLog(rec *componentsdk.Recorder, level componentsdk.Level) *gapLog {
	if rec == nil {
		rec = &componentsdk.Recorder{}
	}
	return &gapLog{rec: rec, level: level}
}

// leaveOut records the detailed artifact's values at pointers as left out
// because of err.
func (l *gapLog) leaveOut(err error, pointers ...string) {
	l.rec.Helper()
	for _, pointer := range pointers {
		l.rec.NotCollected(detailed(pointer), err)
	}
}

// partial records the rollups at pointers as left out because unmeasured of
// the projects they cover could not be read, err being one of the failures.
func (l *gapLog) partial(unmeasured int, err error, pointers ...string) {
	l.rec.Helper()
	for _, pointer := range pointers {
		l.rec.Partial(detailed(pointer), unmeasured, err)
	}
}

func detailed(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: DetailedPath, Pointer: pointer}
}

func normalized(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: NormalizedPath, Pointer: pointer}
}

// normalizedSources maps each normalized field to the detailed field it
// comes from, so a gap on the detailed value carries over. A count behind a
// percentage comes from the same reads as the percentage. audit is true for
// the counts, which the normalized artifact holds from the audit level.
var normalizedSources = []struct {
	normalized, detailed string
	audit                bool
}{
	{"/repositories_present", "/scope/included_project_count", false},
	{"/repository_count", "/scope/project_count", true},
	{"/scanned_repository_count", "/scope/included_project_count", true},
	{"/repo_coverage_pct", "/scope/projects_coverage", false},
	{"/branch_protection/pr_required_pct", "/branch_protection_rules/merge_request_required", false},
	{"/branch_protection/pr_required_repository_count", "/branch_protection_rules/merge_request_required", true},
	{"/branch_protection/approving_reviews_pct", "/branch_protection_rules/approving_reviews", false},
	{"/branch_protection/approving_reviews_repository_count", "/branch_protection_rules/approving_reviews", true},
	{"/branch_protection/status_checks_pct", "/security_features/pipeline_required", false},
	{"/branch_protection/status_checks_repository_count", "/security_features/pipeline_required", true},
	// The deprecated block in deprecated.go.
	{"/org_security/two_factor_required", "/access_control/two_factor_required", false},
}

// normalizedNotRead lists the normalized values GitLab reports through a
// call this collector does not make, each with that call. audit is true for
// the counts.
var normalizedNotRead = []struct {
	pointer, reason string
	audit           bool
}{
	{"/branch_protection/signed_commits_pct", noSignedCommits, false},
	{"/branch_protection/signed_commits_repository_count", noSignedCommits, true},
}

const noSignedCommits = "GitLab's push rules API has reject_unsigned_commits for each project, which this collector does not read."

// mirrorNormalized copies each detailed value's gap to the normalized value
// that comes from it. It gives each normalized value the collector does not
// read a not_read gap. Below the audit level the normalized artifact has no
// counts, so they get neither.
func (l *gapLog) mirrorNormalized() {
	audit := l.level.AtLeast(componentsdk.LevelAudit)
	for _, source := range normalizedSources {
		if source.audit && !audit {
			continue
		}
		l.rec.Mirror(detailed(source.detailed), normalized(source.normalized))
	}
	for _, u := range normalizedNotRead {
		if u.audit && !audit {
			continue
		}
		l.rec.NotCollectedCode(normalized(u.pointer), componentsdk.CodeNotRead, u.reason)
	}
}

// rowPointer is the pointer to a field of one row of a list.
func rowPointer(list string, index int, field string) string {
	return fmt.Sprintf("%s/%d/%s", list, index, field)
}

// firstError returns the first non-nil error.
func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
