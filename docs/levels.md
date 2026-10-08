# Collection levels

Set `config.level` to `trust`, `audit`, or `internal` in `epack.yaml`. Levels are cumulative. The default is `trust`; invalid values fall back to `trust` with an SDK warning.

## Trust

Group-wide settings and aggregate percentages:

- Group 2FA requirement
- Project selection coverage
- Default-branch protection, merge request requirement, approval requirement, code owner approval, and force-push restriction percentages
- Secret push protection and pipeline-required setting percentages

No collected project or member inventory is emitted. The configured group, include/exclude patterns, and diagnostics are included. Trust-level project diagnostics use numeric project IDs. Progress messages can contain project names.

Use `read_api` scope. Secret push protection status requires Ultimate and a role that can see the field. See [configuration](configuration.md) for permission and version requirements.

## Audit

Everything in trust, plus:

- Group project-creation policy and share-with-group lock
- Project inventory: name, namespace path, visibility, archived state, default branch, timestamps, merge method, branch protection, and approval settings when available
- Member inventory: username, name, role, access level, state, and nullable 2FA status
- Group and project webhook counts
- Total and read-write deploy key counts
- Inventory of runners available to the group: ID, name, status, type, online/paused flags, and tags only if the list endpoint returns them

Webhook destinations and per-key details are omitted. Group webhooks require Premium+ and Owner; project webhooks and deploy keys require Maintainer. The group-runner endpoint has separate role and scope requirements. Member 2FA can be unavailable because of version or role restrictions; `null` means unknown, not disabled.

## Internal

Everything in audit, plus:

- Webhook rows: project display name where applicable, ID, active flag, destination host (with port if present), and SSL verification flag
- Deploy key rows: project display name, ID, title, read-only flag, MD5 fingerprint when returned, and creation time
- Seven-day group audit summary and event rows containing the API's custom message, actor name, and timestamp

Full webhook URLs and public key material are not emitted. SHA256 deploy-key fingerprints are not currently decoded, so FIPS-enabled instances can have no fingerprint in the output. Runner rows have the same fields as audit.

Audit events require Premium+. Use Owner for a summary covering all users; a Developer or Maintainer can receive only their own actions. Group audit events are not an inventory of each project's audit events. The summary counts custom messages verbatim; events without a custom message use `unknown`.

## Row limits

Project rows are limited to 5,000, member rows to 10,000, and audit-event rows to 5,000. These sections include `truncated` and `truncated_dropped` when the limit is reached. Counts and aggregate metrics are computed before truncation. Webhook, deploy-key, and runner rows have no current output cap. These output limits do not limit API pagination or requests.
