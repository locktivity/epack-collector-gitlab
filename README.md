# epack-collector-gitlab

GitLab group security posture collector for [epack](https://github.com/locktivity/epack).

It collects group-wide posture metrics from the GitLab REST API and emits:

- a detailed GitLab artifact at `artifacts/gitlab.json` (always)
- a normalized `evidencepack/vcs-posture@v1` artifact at `artifacts/gitlab.vcs-posture.json` (always)

## What It Collects

- **Branch protection:** default-branch protection coverage, merge request enforcement, code owner approval, force push restrictions
- **Approval rules:** project-level approval settings and approval rules (Premium+)
- **Security features:** secret push protection, pipeline-required enforcement
- **Access control:** 2FA requirement, project creation level, share-with-group lock
- **Members:** group members with roles, 2FA status, and state (audit+)
- **Projects:** per-project inventory with visibility, branch protection details, and approval settings (audit+)
- **Webhooks:** group and project webhook counts (audit+), with host/SSL detail (internal)
- **Deploy keys:** read-write vs read-only counts (audit+), per-key fingerprints (internal)
- **Runners:** group runner inventory with status and tags (audit+)
- **Audit log:** 7-day audit event summary with action counts (internal)

## Collection Levels

The collector accepts an optional `level` config knob (`trust` / `audit` / `internal`) controlling collection depth. Levels are cumulative: `internal` is a strict superset of `audit`, which is a strict superset of `trust`.

| Level | Question it answers | What is in the artifact |
|---|---|---|
| `trust` (default) | Do they pass? | Org-wide percentages and on/off flags. No usernames, project names, or webhook URLs. |
| `audit` | Where is the gap? | Per-resource inventories (projects, members, runners, deploy keys) and webhook/deploy-key counts. No webhook destination hosts or audit-log events. |
| `internal` | Who or what specifically? | Webhook detail rows (host, SSL), deploy key fingerprints, and 7-day audit log events with actor names. |

## Quick Start

```yaml
stream: myorg/gitlab-posture

collectors:
  gitlab:
    source: locktivity/epack-collector-gitlab@^0.1
    config:
      group: my-org
    secrets:
      - GITLAB_TOKEN
```

```bash
export GITLAB_TOKEN="glpat-..."
epack collect
```

## Configuration

`group` is required. It should be the group path (e.g., `my-org` or `my-org/sub-group`).

Optional config keys:

- `base_url`: GitLab instance URL for self-managed instances. Defaults to `https://gitlab.com`.
- `level`: Collection depth. One of `trust`, `audit`, `internal`. Defaults to `trust`.
- `include_patterns`: List of glob patterns to include projects. Defaults to `["*"]` (all projects).
- `exclude_patterns`: List of glob patterns to exclude projects. Applied before include patterns.

```yaml
collectors:
  gitlab:
    source: locktivity/epack-collector-gitlab@^0.1
    config:
      group: my-org
      base_url: https://gitlab.example.com
      level: audit
      include_patterns:
        - "backend-*"
        - "frontend-*"
      exclude_patterns:
        - "archived-*"
    secrets:
      - GITLAB_TOKEN
```

## Authentication

The collector uses a GitLab access token (group or personal) passed via the `GITLAB_TOKEN` environment variable.

### Recommended setup

Create a **service account** in your GitLab group and generate a group access token with the `read_api` scope. The role you assign determines which surfaces are collected:

| Role | Surfaces available |
|---|---|
| Reporter | Group settings, projects, branches, members, deploy keys |
| Maintainer | All Reporter surfaces + project webhooks, runners |
| Owner | All Maintainer surfaces + group webhooks, complete audit events |

For the most complete collection, invite the service account as **Owner**. For a minimal setup, **Reporter** works but several surfaces will be skipped with diagnostic warnings.

### Required token scope

| Scope | What it covers |
|---|---|
| `read_api` | All collector surfaces (group, projects, branches, members, webhooks, deploy keys, runners, audit events) |

If a surface is inaccessible due to insufficient role or tier requirements (e.g., audit events require Premium), the collector emits a diagnostic warning and continues. It does not fail the run unless the token itself is invalid (401).

## Development

```bash
# Build
make build

# Run tests
make test

# Lint
make lint

# SDK conformance test
make sdk-test

# Run with epack SDK
make sdk-run
```

## Testing

```bash
# Unit tests
go test ./...

# Unit tests with race detector
go test -race ./...

# End-to-end tests against real GitLab API
GITLAB_TOKEN=glpat-... GITLAB_E2E_GROUP=my-org make e2e
```

## Release

Tag a version to trigger the release workflow:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## License

Apache-2.0
