package collector

import (
	"errors"
	"fmt"

	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
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
// output. API response bodies are stripped to prevent leaking server content.
func safeDiagError(err error) string {
	var apiErr *gitlab.APIError
	if errors.As(err, &apiErr) {
		return fmt.Sprintf("HTTP %d", apiErr.StatusCode)
	}
	return "unexpected error"
}
