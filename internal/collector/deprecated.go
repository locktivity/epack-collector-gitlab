package collector

import "fmt"

// The blocks in this file are the ones epack v0.10.0 moved out of
// vcs-posture, into access-posture and vuln-scanning. The schema keeps them
// as deprecated, and the collector writes them again so profiles written
// before v0.10.0 grade the same. A later minor removes them.

// VCSPostureOrgSecurity holds the group's 2FA requirement, left out when the
// detailed artifact reports it as unknown.
type VCSPostureOrgSecurity struct {
	TwoFactorRequired *bool `json:"two_factor_required,omitempty"`
}

// VCSPostureSecurityFeatures holds the share of assessed projects each
// scanner covers, copied from the vuln-scanning artifact. Each is left out
// when the run collects no vuln-scanning artifact, when its scanner's
// coverage was not read, and over no projects.
type VCSPostureSecurityFeatures struct {
	VulnAlertsPct     *float64 `json:"vuln_alerts_pct,omitempty"`
	SecretScanningPct *float64 `json:"secret_scanning_pct,omitempty"`
	CodeScanningPct   *float64 `json:"code_scanning_pct,omitempty"`
}

// securityFeatures copies each scanner's coverage from vs into the
// deprecated security_features block, recording each copy so a gap on the
// coverage carries over.
func (c *Collector) securityFeatures(vs *VulnScanning) VCSPostureSecurityFeatures {
	var out VCSPostureSecurityFeatures
	for i, s := range vs.Scanners {
		coverage := vuln(fmt.Sprintf("/scanners/%d/coverage_pct", i))
		switch s.Scanner {
		case "dependency_scanning":
			c.gaps.rec.Mirror(coverage, normalized("/security_features/vuln_alerts_pct"))
			out.VulnAlertsPct = coverageCopy(s.CoveragePct)
		case "sast":
			c.gaps.rec.Mirror(coverage, normalized("/security_features/code_scanning_pct"))
			out.CodeScanningPct = coverageCopy(s.CoveragePct)
		case "secret_detection":
			c.gaps.rec.Mirror(coverage, normalized("/security_features/secret_scanning_pct"))
			out.SecretScanningPct = coverageCopy(s.CoveragePct)
		}
	}
	return out
}

// coverageCopy is a scanner's coverage as the deprecated block writes it,
// left out when it was not read and over no projects.
func coverageCopy(pct Reading[int]) *float64 {
	if !pct.Read || pct.Value == nil {
		return nil
	}
	return ptr(float64(*pct.Value))
}
