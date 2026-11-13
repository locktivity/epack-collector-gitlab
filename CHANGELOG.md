# Changelog

## Unreleased

## v0.2.6

- The collector is built on epack v0.12.2.

## v0.2.5

- In the access file, the members of a top-level group include the active users in its billable members list, who hold a role only in a subgroup or a project. The group's member list has no SAML identity or two-factor authentication for them, so with such a member the MFA values, and the SSO values in a group with SAML identities, are left out with a `partial` gap. When the billable members list can't be read, the member counts and the percentages over every member are left out with its gap.
- A member whose custom role can manage the group's members (`admin_group_member`) or delete the group (`remove_group`) counts as an admin beside the Owners. The collector reads the group's custom roles from `/groups/:id/member_roles` when a member has one, which needs the Owner role and GitLab Ultimate on GitLab.com. When they can't be read, the admin counts are left out with a `partial` gap.

## v0.2.4

- The collector is built on Go 1.26.11.
- `artifacts/gitlab.access-posture.json` has `root` now. A GitLab group has no built-in root account, so `root_accounts_present` and `root_access_keys_present` are false and `root_mfa_coverage_pct` is null. From the audit level, `root_account_count` and `root_mfa_account_count` are 0. Before, `root` was left out with an `unsupported` gap. A profile test that applies only when `root.root_accounts_present` is true no longer applies to GitLab.

## v0.2.3

- The collector is built on epack v0.10.5.
- At trust, a diagnostic about one project, such as a failed protected branches read, says `a project: fetch failed`. It named the project's numeric ID before, and `unavailable_sources` in `artifacts/gitlab.vcs-posture.json` copied it. Audit and internal diagnostics still name the project.
- At trust, a group configured by its numeric ID is named by its full path in `group` in `artifacts/gitlab.details.json` and in `organization` in `artifacts/gitlab.vcs-posture.json`. A trust run wrote the configured ID in `group` before. When GitLab's group response has no full path, both are left out with an `invalid_response` gap. Audit and internal runs write the configured value as before.
- The collector result has `targets` now. They name the group, at `group` in `artifacts/gitlab.details.json`, and the projects the run assessed, at `projects.per_project` in the same file, with how each was chosen.

## v0.2.2

- The collector is built on epack v0.10.2.
- The deprecated `org_security` block is left out when `collect` leaves out `access-posture`, with a `not_shared` gap. v0.2.1 wrote it whatever `collect` listed.
- The deprecated `security_features` block has a `not_shared` gap when `collect` leaves out `vuln-scanning`. v0.2.1 left it out with no gap.

## v0.2.1

- The collector is built on epack v0.10.1.
- `artifacts/gitlab.vcs-posture.json` has `org_security` and `security_features` again, as deprecated blocks that epack v0.10.1 declares. A later minor removes them.
- `org_security.two_factor_required` is the group's 2FA requirement, left out when it is unknown. v0.1 wrote false then.
- `security_features.vuln_alerts_pct`, `code_scanning_pct`, and `secret_scanning_pct` copy the coverage of the vuln-scanning file's dependency scanning, SAST, and secret detection entries, with their gaps. They are left out when `collect` leaves out `vuln-scanning`. v0.1 wrote 0 for the first two and secret push protection coverage for the third.

## v0.2.0

- The collector is built on epack v0.10.0. The detailed artifact moves from `artifacts/gitlab.json` to `artifacts/gitlab.details.json`, the path epack's `ArtifactPath` gives it. A reader of the old path needs the new one
- `artifacts/gitlab.vcs-posture.json` no longer has `org_security` or `security_features`, which `evidencepack/vcs-posture@v1` no longer defines. The group's 2FA requirement, formerly `org_security.two_factor_required`, is now `sign_in.mfa_required` in the new access-posture artifact. `security_features.secret_scanning_pct` and its count measured secret push protection. They have no new field. The detailed artifact still has `security_features.secret_push_protection` and `security_features.pipeline_required`. `unavailable_sources` no longer lists `vuln_alerts` or `code_scanning`.
- New `evidencepack/access-posture@v1` artifact at `artifacts/gitlab.access-posture.json`. It has the group's 2FA requirement, its members and Owners with their 2FA and SAML identities, and its machine credentials. The credentials are the active access tokens of the group and of the assessed projects, and the deploy keys enabled in those projects. The present flags and percentages are written at every level, and the counts from the audit level.
- In the access-posture artifact, every member and Owner counts as able to sign in without SSO, including those with a SAML identity. GitLab's API has no field for whether a group enforces SSO-only sign-in. The local MFA percentages therefore cover every member and every Owner.
- The access-posture artifact's inactive members come from the group's billable members list. A member is inactive when their `last_activity_on` is empty or before the date 90 days before the run. GitLab has the list only for a top-level group, so a subgroup's inactive values are left out as `not_read`. When the list does not have a member, such as a Guest on Ultimate, the inactive values are left out the same way.
- An access token with the `api` scope counts as unrestricted, unless the group restricts access by IP address. That restriction applies to every token and deploy key. For a subgroup, the top-level group's restriction applies, so the unrestricted values are left out as `not_read`.
- Values GitLab has behind a call the collector does not make are left out with a `not_read` gap that names the call. These are the signed commit values in the vcs-posture artifact, and `members.external_members_present`, its count, and `connected_apps` in the access-posture artifact. `unsupported` now marks only values GitLab's API never has.
- New `evidencepack/vuln-scanning@v1` artifact at `artifacts/gitlab.vuln-scanning.json`, with entries for dependency scanning, SAST, and secret detection. Each entry has the share of assessed projects whose latest default branch pipeline ran the scanner. A scanner is enabled when it ran in at least one of them. It also has the open vulnerabilities in the group's vulnerability report by severity, and the overdue ones. A critical finding open more than 30 days is overdue, and so is a high one open more than 90 days. The finding values need GitLab Ultimate and are left out as `not_licensed` without it.
- The collector now lists the access tokens of the group and of each assessed project, and the group's billable members. It also sends two GraphQL queries, for each project's security scanners and for the group's vulnerabilities. The group's members and the projects' deploy keys are now read at every level, for the access-posture artifact. A `collect` list that leaves out `access-posture` or `vuln-scanning` skips the calls only that artifact needs.
- The access-posture values need the Owner role, and the 2FA values need GitLab 19.4 or later. With another role, the MFA, SSO, inactive, and credential values are left out as `permission_denied`. A 401 from an access token list means the token's role cannot read it, so it is recorded as `permission_denied`. So is a 400 from the billable members list.
- On GitLab before 19.4, an Owner token whose group has SAML or SCIM identities now gets the access-posture SSO values. Its MFA values are left out as `unsupported`, since `two_factor_enabled` needs 19.4. They were left out as `permission_denied` for the Owner role before.
- A protected branch rule with no push access levels now counts as requiring a merge request. No one can push to a branch under such a rule. This raises `merge_request_required` in the detailed artifact and `pr_required_pct` in the vcs-posture artifact for groups with such rules.
- The vcs-posture artifact's `organization` is now the group's full path from GitLab. It was the configured `group` before, which can be a numeric ID. The detailed artifact's `group` stays as configured.
- Each call declares the token scope or GitLab role it needs, as GitLab's API docs give it. The collector result lists it with the call, and a `permission_denied` gap names it. A call that needs only `read_api` names it only when GitLab answers `insufficient_scope`.
- `docs/schema/methods.json` is keyed by schema ID, with sentences for the vcs-posture, access-posture, and vuln-scanning fields.

## v0.1.0

Initial release of the GitLab collector for epack.
