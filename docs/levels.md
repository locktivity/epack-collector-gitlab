# Collection levels

Set `config.level` to `trust`, `audit`, or `internal` in `epack.yaml`. Levels are cumulative. The default is `trust`; invalid values fall back to `trust` with an SDK warning.

## Trust

Group-wide settings and aggregate percentages:

- Group 2FA requirement, set by the group or an ancestor group
- Project selection coverage
- Default-branch protection, merge request requirement, approval requirement, code owner approval, and force-push restriction percentages
- Secret push protection and pipeline-required setting percentages
- In the access-posture artifact, whether the group has members, Owners, and credentials, with the MFA, SSO, inactive member, and credential percentages
- In the vuln-scanning artifact, each scanner's coverage and whether it has open critical, open high, or overdue findings

No collected project or member inventory is emitted. The configured group, include/exclude patterns, and diagnostics are included. A group configured by its numeric ID is named by its full path instead, in the detailed artifact's `group` and the vcs-posture artifact's `organization`. From audit, `group` holds the configured ID. A trust-level diagnostic about one project names it by neither name nor ID. From audit, it names the project. Progress messages can contain project names.

Use `read_api` scope. Secret push protection status requires Ultimate and a role that can see the field. The access-posture values need the Owner role, and the vulnerability values need Ultimate. See [configuration](configuration.md) for permission and version requirements.

## Audit

Everything in trust, plus:

- The counts behind each access-posture and vuln-scanning percentage, and the open findings by severity
- Group project-creation policy and share-with-group lock
- Project inventory: name, namespace path, visibility, archived state, default branch, timestamps, merge method, branch protection, and approval settings when available
- Member inventory: username, name, role, access level, state, and nullable 2FA status
- Group and project webhook counts
- Total and read-write deploy key counts
- Inventory of the group runners available to the group, including those of ancestor groups: ID, name, status, type, online/paused flags, and tags only if the list endpoint returns them

Webhook destinations and per-key details are omitted. Group webhooks require Premium+ and Owner; project webhooks and deploy keys require Maintainer. The group-runner endpoint has separate role and scope requirements. Member 2FA can be unavailable because of version or role restrictions; `null` means unknown, not disabled.

## Internal

Everything in audit, plus:

- Webhook rows: project display name where applicable, ID, active flag, destination host (with port if present), and SSL verification flag
- Deploy key rows: project display name, ID, title, read-only flag, MD5 fingerprint when returned, and creation time
- Seven-day group audit summary and event rows containing the API's custom message, actor name, and timestamp

Full webhook URLs and public key material are not emitted. A webhook row has no host when part of the host is masked, and its gap is `unsupported`. SHA256 deploy-key fingerprints are not currently decoded, so FIPS-enabled instances can have no fingerprint in the output. Runner rows have the same fields as audit.

Audit events require Premium+. Use Owner for a summary covering all users; a Developer or Maintainer can receive only their own actions. Group audit events are not an inventory of each project's audit events. The summary counts custom messages verbatim; events without a custom message use `unknown`.

## Row limits

Project rows are limited to 5,000, member rows to 10,000, and audit-event rows to 5,000. These sections include `truncated` and `truncated_dropped` when the limit is reached. Counts and aggregate metrics are computed before truncation. Webhook, deploy-key, and runner rows have no current output cap. These output limits do not limit API pagination or requests.

A list that was read and is empty is written as `[]`. A section or count missing at a level that includes it could not be read, and the collector result has a gap for it. When any project's webhooks or deploy keys could not be read, the project webhook count, the deploy key counts, and their rows are left out, since the rest would understate them.
