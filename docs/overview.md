# GitLab Collector

The collector reads the GitLab REST API v4 and GraphQL API for a configured group and emits security posture evidence. It includes projects in subgroups and excludes projects shared into the group.

## What it collects

- Default-branch protection and matching wildcard rules
- Project merge request approval settings and branch-scoped approval rules
- Secret push protection and the pipeline-required setting
- Group 2FA enforcement by the group or an ancestor group and, at audit+, project-creation policy and sharing lock
- Members, Owners, and their 2FA and SAML identities, with each member's last activity from the billable members list
- Group and project access tokens and deploy keys, with their expiry, last use, and write access
- Dependency scanning, SAST, and secret detection coverage, and open vulnerabilities by severity
- Group member and project inventories at audit+
- Webhook counts, deploy-key counts, and group-runner inventory at audit+
- Webhook hosts, deploy-key details, and seven-day group audit events at internal

It does not inspect repository contents, CI configuration, or CODEOWNERS files. See [collection levels](levels.md) for the emitted fields and limits.

## Not collected

GitLab offers the following through its API, and the collector does not read them.

- **Container scanning and DAST findings.** GitLab's vulnerability report lists them alongside the dependency scanning, SAST and secret detection findings the collector reads. The `vuln-scanning` output has no entry for either scanner.
- **Personal access tokens and SSH keys.** GitLab lists the personal access tokens of a group's service accounts. On GitLab.com, the Owner of a top-level group can also list the personal access tokens and SSH keys of the group's enterprise users. The credentials the collector counts are group and project access tokens and deploy keys.

## Hosting modes

- **GitLab.com:** default instance URL
- **Self-managed:** configure `base_url`
- **GitLab Dedicated:** configure the dedicated instance URL

The available fields depend on GitLab version, license, and token permissions.

## Output

Successful runs emit five artifacts at every collection level:

1. `artifacts/gitlab.details.json`: detailed GitLab-specific posture, described by [schema/v1.0.0.json](schema/v1.0.0.json)
2. `artifacts/gitlab.vcs-posture.json`: normalized `evidencepack/vcs-posture@v1` posture
3. `artifacts/gitlab.access-posture.json`: normalized `evidencepack/access-posture@v1` access to the group
4. `artifacts/gitlab.vuln-scanning.json`: normalized `evidencepack/vuln-scanning@v1` scanner coverage and open findings
5. `artifacts/gitlab.collector-result.json`: the collector result, which lists each value left out with a code that says why, counts the calls made to each GitLab endpoint, and names the group the token signed in to

The `collect` config key can leave out any of the first four. The collector then skips the calls that only that artifact needs.

The vcs-posture output maps project selection coverage, MR/approval percentages, and pipeline-required percentages from the detailed artifact. A value the detailed artifact left out is absent from the normalized artifact too, with the same gap. The collector does not read GitLab's push rules, which have `reject_unsigned_commits`. The signed commit values are absent, each with a `not_read` gap.

The access-posture output has the group's 2FA requirement, its members and Owners, and its machine credentials. Members are the active users in the group's member list, including inherited and invited members. Bot users for access tokens and service accounts are not counted as members. Owners are the admins. A member with a SAML identity counts as linked to SSO. GitLab's API has no field for whether a group enforces SSO-only sign-in, so every member also counts as able to sign in without SSO. The local MFA percentages therefore cover every member and every Owner.

A member is inactive when their `last_activity_on` in the group's billable members list is empty or before the date 90 days before the run. A sign-in sets `last_activity_on`, and so does Git or API use. GitLab has this list only for a top-level group, and only an Owner can read it. The list has no Guests on GitLab Ultimate, so a group on Ultimate with a Guest has its inactive values left out.

A GitLab group has no built-in root account. So `root.root_accounts_present` and `root.root_access_keys_present` are false and `root.root_mfa_coverage_pct` is null. From the audit level the root counts are 0.

Credentials are the active access tokens of the group and of the assessed projects. They also include the deploy keys enabled in those projects. A deploy key enabled in several projects counts once, and an expired deploy key is not counted. GitLab access tokens always expire, so the never-expiring credentials are deploy keys without an expiry date. An access token with the `api` scope counts as unrestricted. When the group restricts access by IP address, the restriction applies to every token and deploy key, so none counts as unrestricted.

The vuln-scanning output has one entry each for dependency scanning, SAST, and secret detection. A project counts as scanned when the scanner's job succeeded in its latest pipeline on the default branch. A scanner is enabled when it scanned at least one assessed project. Open findings are the detected and confirmed vulnerabilities in the group's vulnerability report, for the assessed projects. A finding is overdue when it is critical and open more than 30 days, or high and open more than 90 days.

These values have no source in GitLab's API, so each is left out with an `unsupported` gap:

- `sign_in.sso_required`, since the API does not say whether a group enforces SAML SSO
- `sign_in.sso_configured` and `sign_in.scim_enabled` when no member has a SAML or SCIM identity

These values come from GitLab API calls the collector does not make, so each is left out with a `not_read` gap that names the call:

- `members.external_members_present`, which the Users API's `external` filter has
- `connected_apps`, which the group integrations API lists
- `members.inactive_pct` for a subgroup, since the billable members list is only for a top-level group
- `members.inactive_pct` when a member is not in the billable members list. GitLab's GraphQL API has their `lastActivityOn`.
- `credentials.unrestricted_pct` for a subgroup, since the top-level group's IP restriction applies to its credentials

## Output limitations

Percentages describe the projects visible to the token after filtering. `projects_coverage` is the percentage of API-listed projects selected by the filters, not a measurement of all projects the organization owns. `scope.project_count` and `scope.included_project_count` give the two counts. Archived and empty projects remain in the denominator. A percentage over no projects is `null`. `security_features_coverage` is the arithmetic mean of secret push protection and pipeline-required coverage, rounded down to an integer.

Pipeline coverage reports the project's `only_allow_merge_if_pipeline_succeeds` flag. It does not inspect pipeline contents or prove that every change ran checks. Code owner coverage reports the branch flag; it does not verify that a CODEOWNERS file exists or covers all paths. Approval inventory records the maximum applicable approval count, not a complete copy of approval rules or approver identities. A rule from a merge request approval policy or Coverage-Check counts only when its report type is `any_merge_request`. Other rules of that kind need approval only when their condition is met.

The normalized `signed_commits_pct` is left out because this collector does not read push rules. It is listed in `unavailable_sources` with an explanation. `unavailable_sources` also includes runtime diagnostics from permission errors and endpoint failures. When projects omit `secret_push_protection_enabled` (due to tier or role restrictions), `secret_push_protection` is left out, with a diagnostic noting how many projects could not report the field. Its gap is `not_licensed` when no project reports it and `permission_denied` when only some do.

A value the collector could not read is left out, as `null` or an absent field, with a gap in the collector result; a failed endpoint never lowers a percentage or a count. A percentage needs an answer for every included project: when one project's protected branches, approval settings, or approval rules could not be read, the percentage is left out with a `partial` gap that counts the projects left unmeasured. The same project's row in the audit inventory leaves out `branch_protection` or `approval_settings` with a gap. Diagnostics still describe skipped surfaces in prose. Only a failure reading the configured group fails the run; HTTP 401 from any other endpoint leaves that endpoint's values out with `auth_failed`. A 401 from an access token list means the token's role cannot read it, so its gap is `permission_denied`.

Group members, group hooks, runners, and group audit events retain their group scope when projects are filtered. For complete group audit events, use Owner: lower roles can return an apparently successful list containing only the token owner's actions.

The access-posture MFA, SSO, and inactive values need a token with the Owner role, and the 2FA values need GitLab 19.4 or later. With another role they are left out with a `permission_denied` gap. On GitLab before 19.4, an Owner token whose group has SAML or SCIM identities gets the SSO values, and the MFA values are left out as `unsupported`. A request for billable members from another role gets HTTP 400, and its gap is `permission_denied`. Only an Owner can list the group's access tokens, so the credential values are left out the same way for any other role. The vulnerability values need GitLab Ultimate and the Developer role or above. Without Ultimate they are left out as `not_licensed`, and the coverage values stay.
