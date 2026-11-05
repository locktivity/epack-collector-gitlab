package collector

import (
	"fmt"

	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
	"github.com/locktivity/epack/componentsdk"
)

type diagnosticsTracker struct {
	permissionErrors []string
	warnings         []string
}

func (d *diagnosticsTracker) surfacePermissionDenied(surface, reason string) {
	d.permissionErrors = append(d.permissionErrors,
		"surface "+surface+" skipped: "+reason)
}

func (d *diagnosticsTracker) surfaceUnavailable(surface, reason string) {
	d.warnings = append(d.warnings,
		"surface "+surface+" skipped: "+reason)
}

func (d *diagnosticsTracker) tierRequired(surface, tier string) {
	d.warnings = append(d.warnings,
		"surface "+surface+" skipped: requires "+tier+" tier")
}

func (d *diagnosticsTracker) warn(message string) {
	d.warnings = append(d.warnings, message)
}

func (d *diagnosticsTracker) toDiagnostics() *Diagnostics {
	if len(d.permissionErrors) == 0 && len(d.warnings) == 0 {
		return nil
	}
	return &Diagnostics{
		PermissionErrors: d.permissionErrors,
		Warnings:         d.warnings,
	}
}

// safeDiagError returns a bounded error description suitable for artifact
// output: the HTTP status, or the error's code. API response bodies are left
// out to prevent leaking server content.
func safeDiagError(err error) string {
	if status := gitlab.StatusOf(err); status != 0 {
		return fmt.Sprintf("HTTP %d", status)
	}
	return string(componentsdk.Classify(err))
}
