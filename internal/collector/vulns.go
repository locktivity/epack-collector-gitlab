package collector

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
	"github.com/locktivity/epack/componentsdk"
)

// VulnScanning is the normalized evidencepack/vuln-scanning@v1 artifact
// for the group. It has one entry for each scanner the collector reports.
type VulnScanning struct {
	SchemaVersion string        `json:"schema_version"`
	CollectedAt   string        `json:"collected_at"`
	Provider      string        `json:"provider"`
	Scanners      []VulnScanner `json:"scanners"`
}

// VulnScanner is one scanner's coverage of the assessed projects and its
// open findings. The counts are written from the audit level.
type VulnScanner struct {
	Scanner              string       `json:"scanner"`
	Category             string       `json:"category"`
	Enabled              *bool        `json:"enabled,omitempty"`
	ResourcesPresent     *bool        `json:"resources_present,omitempty"`
	ResourceCount        *int         `json:"resource_count,omitempty"`
	ScannedResourceCount *int         `json:"scanned_resource_count,omitempty"`
	CoveragePct          Reading[int] `json:"coverage_pct,omitzero"`
	OpenCriticalPresent  *bool        `json:"open_critical_present,omitempty"`
	OpenHighPresent      *bool        `json:"open_high_present,omitempty"`
	OverduePresent       *bool        `json:"overdue_present,omitempty"`
	OpenCriticalCount    *int         `json:"open_critical_count,omitempty"`
	OpenHighCount        *int         `json:"open_high_count,omitempty"`
	OpenMediumCount      *int         `json:"open_medium_count,omitempty"`
	OpenLowCount         *int         `json:"open_low_count,omitempty"`
	OverdueCriticalCount *int         `json:"overdue_critical_count,omitempty"`
	OverdueHighCount     *int         `json:"overdue_high_count,omitempty"`
}

// scannerKind is a scanner the artifact reports. types are its names in
// securityScanners, and reportType is the type of its findings.
type scannerKind struct {
	name, category, reportType string
	types                      []string
}

var scannerKinds = []scannerKind{
	{name: "dependency_scanning", category: "dependencies", reportType: "DEPENDENCY_SCANNING", types: []string{"DEPENDENCY_SCANNING"}},
	{name: "sast", category: "code", reportType: "SAST", types: []string{"SAST", "SAST_ADVANCED"}},
	{name: "secret_detection", category: "secrets", reportType: "SECRET_DETECTION", types: []string{"SECRET_DETECTION"}},
}

const (
	// A finding is overdue when it is critical and open more than 30 days,
	// or high and open more than 90 days.
	criticalOverdueAfter = 30 * 24 * time.Hour
	highOverdueAfter     = 90 * 24 * time.Hour

	// ultimateScanner is a scanner type that securityScanners lists as
	// available only with GitLab Ultimate.
	ultimateScanner = "DEPENDENCY_SCANNING"

	noFindings      = "The group's vulnerability report needs GitLab Ultimate."
	findingsDenied  = "Reading the group's vulnerability report needs the Developer role or above."
	developerRole   = "Developer"
	scannersMissing = "the security scanner query has no securityScanners for %d of %d projects"
)

// readVulnerabilities reads the security scanners of each assessed project
// and the group's open vulnerabilities. fullPath is the group's full path.
func (c *Collector) readVulnerabilities(ctx context.Context, fullPath string, projects []gitlab.Project) {
	c.status("Fetching security scanners and vulnerabilities...")
	ids := make([]int, len(projects))
	for i, p := range projects {
		ids[i] = p.ID
	}
	// Sorted batches keep each query the same whatever order the project
	// list comes in.
	slices.Sort(ids)
	c.reads.scanners = map[int]gitlab.SecurityScanners{}
	for batch := range slices.Chunk(ids, gitlab.ScannerBatch) {
		scanners, err := c.client.ListSecurityScanners(ctx, batch)
		if err != nil {
			c.reads.scannersFailed += len(batch)
			c.reads.scannersErr = firstError(c.reads.scannersErr, err)
			continue
		}
		missing := 0
		for _, id := range batch {
			if s, ok := scanners[id]; ok {
				c.reads.scanners[id] = s
			} else {
				missing++
			}
		}
		if missing > 0 {
			c.reads.scannersFailed += missing
			c.reads.scannersErr = firstError(c.reads.scannersErr, componentsdk.CodeError(componentsdk.CodeInvalidResponse,
				fmt.Errorf(scannersMissing, missing, len(batch))))
		}
	}
	c.reads.vulns, c.reads.vulnsErr = c.client.ListGroupVulnerabilities(ctx, fullPath)
}

// findingCounts counts one scanner's open findings in the assessed
// projects.
type findingCounts struct {
	critical, high, medium, low  int
	overdueCritical, overdueHigh int
}

func countFindings(vulns []gitlab.Vulnerability, reportType string, projects map[int]bool, now time.Time) findingCounts {
	var f findingCounts
	for _, v := range vulns {
		if v.ReportType != reportType || !projects[v.ProjectID] {
			continue
		}
		age := now.Sub(v.DetectedAt)
		switch v.Severity {
		case "CRITICAL":
			f.critical++
			if age > criticalOverdueAfter {
				f.overdueCritical++
			}
		case "HIGH":
			f.high++
			if age > highOverdueAfter {
				f.overdueHigh++
			}
		case "MEDIUM":
			f.medium++
		case "LOW":
			f.low++
		}
	}
	return f
}

// coverage counts the assessed projects whose latest default branch
// pipeline ran the scanner. unknown counts the projects whose scanners were
// not read.
type coverage struct {
	scanned, unknown int
}

func countCoverage(projects []gitlab.Project, scanners map[int]gitlab.SecurityScanners, kind scannerKind) coverage {
	var cv coverage
	has := func(list []string) bool {
		return slices.ContainsFunc(list, func(t string) bool { return slices.Contains(kind.types, t) })
	}
	for _, p := range projects {
		s, ok := scanners[p.ID]
		switch {
		case !ok:
			cv.unknown++
		case has(s.PipelineRun):
			cv.scanned++
		}
	}
	return cv
}

// vulnScanning builds the vuln-scanning artifact from what the run read,
// with a gap for each value it leaves out.
func (c *Collector) vulnScanning(posture *GroupPosture) *VulnScanning {
	vs := &VulnScanning{
		SchemaVersion: "1.0.0",
		CollectedAt:   posture.CollectedAt,
		Provider:      "gitlab",
		Scanners:      make([]VulnScanner, len(scannerKinds)),
	}
	audit := c.gaps.level.AtLeast(componentsdk.LevelAudit)
	r := c.reads
	assessed := make(map[int]bool, len(r.included))
	for _, p := range r.included {
		assessed[p.ID] = true
	}
	for i, kind := range scannerKinds {
		out := &vs.Scanners[i]
		out.Scanner, out.Category = kind.name, kind.category
		at := func(field string) string { return fmt.Sprintf("/scanners/%d/%s", i, field) }
		v := vulnLog{gaps: c.gaps, audit: audit, at: at}

		c.gaps.rec.Mirror(detailed("/scope/included_project_count"), vuln(at("resources_present")))
		if audit {
			c.gaps.rec.Mirror(detailed("/scope/included_project_count"), vuln(at("resource_count")))
		}
		if r.projectsErr != nil {
			v.leaveOut(r.projectsErr, []string{"enabled", "coverage_pct", "open_critical_present", "open_high_present", "overdue_present"}, findingCountFields...)
			if audit {
				v.leaveOut(r.projectsErr, nil, "scanned_resource_count")
			}
			continue
		}
		n := len(r.included)
		out.ResourcesPresent = ptr(n > 0)
		out.ResourceCount = v.count(n)

		// A scanner is enabled when it covers at least one project.
		cv := countCoverage(r.included, r.scanners, kind)
		switch {
		case cv.scanned > 0:
			out.Enabled = ptr(true)
		case cv.unknown > 0:
			v.partial(cv.unknown, r.scannersErr, "enabled")
		default:
			out.Enabled = ptr(false)
		}
		if cv.unknown > 0 {
			v.partial(cv.unknown, r.scannersErr, "coverage_pct")
			if audit {
				v.partial(cv.unknown, r.scannersErr, "scanned_resource_count")
			}
		} else {
			out.ScannedResourceCount = v.count(cv.scanned)
			out.CoveragePct = share(cv.scanned, n, componentsdk.RoundDown)
		}

		c.fillFindings(out, v, kind, assessed)
	}
	return vs
}

// findingCountFields are the audit-level finding counts.
var findingCountFields = []string{
	"open_critical_count", "open_high_count", "open_medium_count", "open_low_count",
	"overdue_critical_count", "overdue_high_count",
}

var findingFlagFields = []string{"open_critical_present", "open_high_present", "overdue_present"}

func (c *Collector) fillFindings(out *VulnScanner, v vulnLog, kind scannerKind, assessed map[int]bool) {
	r := c.reads
	switch {
	case r.vulnsErr != nil:
		v.leaveOut(r.vulnsErr, findingFlagFields, findingCountFields...)
		return
	case !r.vulns.Readable:
		code, detail, opts := componentsdk.CodeNotLicensed, noFindings, []componentsdk.AdviceOption(nil)
		if c.ultimate() {
			code, detail, opts = componentsdk.CodePermissionDenied, findingsDenied, []componentsdk.AdviceOption{componentsdk.MissingPermission(developerRole)}
		}
		v.leaveOutCode(code, detail, opts, findingFlagFields, findingCountFields...)
		return
	}
	f := countFindings(r.vulns.Items, kind.reportType, assessed, c.now())
	out.OpenCriticalPresent = ptr(f.critical > 0)
	out.OpenHighPresent = ptr(f.high > 0)
	out.OverduePresent = ptr(f.overdueCritical+f.overdueHigh > 0)
	out.OpenCriticalCount = v.count(f.critical)
	out.OpenHighCount = v.count(f.high)
	out.OpenMediumCount = v.count(f.medium)
	out.OpenLowCount = v.count(f.low)
	out.OverdueCriticalCount = v.count(f.overdueCritical)
	out.OverdueHighCount = v.count(f.overdueHigh)
}

// ultimate reports whether an assessed project lists a scanner as available
// that only GitLab Ultimate has.
func (c *Collector) ultimate() bool {
	for _, s := range c.reads.scanners {
		if slices.Contains(s.Available, ultimateScanner) {
			return true
		}
	}
	return false
}

// vulnLog records the gaps of one scanner entry. audit is true from the
// audit level, where the entry holds counts, and at gives a field's
// pointer.
type vulnLog struct {
	gaps  *gapLog
	audit bool
	at    func(field string) string
}

func (v vulnLog) count(n int) *int {
	if !v.audit {
		return nil
	}
	return &n
}

// leaveOut records fields, and from the audit level counts, as left out
// because of err.
func (v vulnLog) leaveOut(err error, fields []string, counts ...string) {
	v.gaps.rec.Helper()
	if v.audit {
		fields = append(slices.Clone(fields), counts...)
	}
	for _, field := range fields {
		v.gaps.rec.NotCollected(vuln(v.at(field)), err)
	}
}

// leaveOutCode records fields, and from the audit level counts, as left out
// with code.
func (v vulnLog) leaveOutCode(code componentsdk.Code, detail string, opts []componentsdk.AdviceOption, fields []string, counts ...string) {
	v.gaps.rec.Helper()
	if v.audit {
		fields = append(slices.Clone(fields), counts...)
	}
	for _, field := range fields {
		v.gaps.rec.NotCollectedCode(vuln(v.at(field)), code, detail, opts...)
	}
}

func (v vulnLog) partial(unmeasured int, err error, fields ...string) {
	v.gaps.rec.Helper()
	for _, field := range fields {
		v.gaps.rec.Partial(vuln(v.at(field)), unmeasured, err)
	}
}

func vuln(pointer string) componentsdk.Location {
	return componentsdk.Location{Path: VulnPath, Pointer: pointer}
}
