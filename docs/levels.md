# Collection levels

The GitLab collector supports three cumulative collection levels.

## Trust (default)

Aggregate percentages only. No project names, member identities, or per-resource detail.

**Surfaces:**
- Group security settings (2FA enforcement)
- Project list (counted, not named)
- Branch protection coverage percentage
- Security feature adoption percentage
- Merge request approval coverage percentage

**Required scopes:** `read_api`

## Audit

Everything in trust, plus per-project and per-member inventories.

**Additional surfaces:**
- Project inventory (name, visibility, archived status, branch protection detail)
- Member inventory (username, name, role, 2FA status)
- Approval rule summaries per project
- Webhook counts (group + project)
- Deploy key counts (requires Maintainer)
- Runner inventory
- Audit event counts by category (Premium+)

**Required scopes:** `read_api`, `read_user` (recommended)

## Internal

Everything in audit, plus sensitive operational detail.

**Additional surfaces:**
- Full webhook detail (ID, active, events, URL host)
- Full deploy key detail (ID, title, read-only, fingerprint, created at)
- Full runner detail (ID, name, status, tags)
- Audit event rows (action, actor, timestamp)

**Required scopes:** `read_api`, `read_user`
