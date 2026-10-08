# GitLab Collector

The collector reads the GitLab REST API v4 for a configured group and emits security posture evidence. It includes projects in subgroups and excludes projects shared into the group.

## What it collects

- Default-branch protection and matching wildcard rules
- Project merge request approval settings and branch-scoped approval rules
- Secret push protection and the pipeline-required setting
- Group 2FA enforcement and, at audit+, project-creation policy and sharing lock
- Group member and project inventories at audit+
- Webhook counts, deploy-key counts, and available-runner inventory at audit+
- Webhook hosts, deploy-key details, and seven-day group audit events at internal

It does not inspect repository contents, CI configuration, or CODEOWNERS files. It does not collect SAST/dependency-scanning adoption or vulnerability findings. See [collection levels](levels.md) for the emitted fields and limits.

## Hosting modes

- **GitLab.com:** default instance URL
- **Self-managed:** configure `base_url`
- **GitLab Dedicated:** configure the dedicated instance URL

The available fields depend on GitLab version, license, and token permissions.

## Output

Successful runs emit two artifacts at every collection level:

1. `artifacts/gitlab.json`: detailed GitLab-specific posture
2. `artifacts/gitlab.vcs-posture.json`: normalized `evidencepack/vcs-posture@v1` posture

The normalized output maps group 2FA, project selection coverage, MR/approval percentages, and pipeline-required percentages from the detailed artifact. `secret_scanning_pct` currently uses secret push protection adoption as a proxy; it does not measure pipeline secret detection.

## Output limitations

Percentages describe the projects visible to the token after filtering. `projects_coverage` is the percentage of API-listed projects selected by the filters, not a measurement of all projects the organization owns. Archived and empty projects remain in the denominator. `security_features_coverage` is the arithmetic mean of secret push protection and pipeline-required coverage, rounded down to an integer.

Pipeline coverage reports the project's `only_allow_merge_if_pipeline_succeeds` flag. It does not inspect pipeline contents or prove that every change ran checks. Code owner coverage reports the branch flag; it does not verify that a CODEOWNERS file exists or covers all paths. Approval inventory records the maximum applicable approval count, not a complete copy of approval rules or approver identities.

The normalized `signed_commits_pct`, `vuln_alerts_pct`, and `code_scanning_pct` are fixed at zero because this collector does not measure them. Each is listed in `unavailable_sources` with an explanation. `unavailable_sources` also includes runtime diagnostics from permission errors and endpoint failures. Projects that omit `secret_push_protection_enabled` (due to tier or role restrictions) emit a diagnostic noting how many projects could not report the field.

Endpoint failures appear in diagnostics where collection can continue. A failed optional endpoint can lower coverage or counts, and counts of zero can reflect inaccessible data. Inspect diagnostics alongside the metrics. HTTP 401 fails collection at every surface; non-permission errors retrieving the group or project list also fail collection.

Group members, group hooks, runners, and group audit events retain their group scope when projects are filtered. For complete group audit events, use Owner: lower roles can return an apparently successful list containing only the token owner's actions.
