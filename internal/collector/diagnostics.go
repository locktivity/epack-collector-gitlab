package collector

type diagnosticsTracker struct {
	permissionErrors []string
	warnings         []string
}

func (d *diagnosticsTracker) surfacePermissionDenied(surface, missingScope string) {
	d.permissionErrors = append(d.permissionErrors,
		"surface "+surface+" skipped: permission denied (scope "+missingScope+")")
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
