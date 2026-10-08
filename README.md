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
- **Members:** group members with roles and state, plus 2FA status when the API exposes it (audit+)
- **Projects:** per-project inventory with visibility, branch protection details, and approval settings (audit+)
- **Webhooks:** group and project webhook counts (audit+), with host/SSL detail (internal)
- **Deploy keys:** read-write vs read-only counts (audit+, requires Maintainer), per-key fingerprints (internal)
- **Runners:** inventory of runners available to the group, with status (audit+); tags are included only if returned by the list endpoint
- **Audit log:** 7-day audit event summary with action counts (internal)

## Collection Levels

The collector accepts an optional `level` config knob (`trust` / `audit` / `internal`) controlling collection depth. Levels are cumulative: `internal` is a strict superset of `audit`, which is a strict superset of `trust`.

| Level | Question it answers | What is in the artifact |
|---|---|---|
| `trust` (default) | Do they pass? | Group-wide percentages and on/off flags. No collected member or project inventory, or webhook URLs. Configured group and filter patterns are included. |
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

`group` is required. Use a group path (e.g., `my-org` or `my-org/sub-group`) or a numeric group ID as a string (e.g., `"123"`). Projects in subgroups are included; projects shared into the group are excluded.

Optional config keys:

- `base_url`: GitLab instance URL for self-managed instances. Defaults to `https://gitlab.com`.
- `level`: Collection depth. One of `trust`, `audit`, `internal`. Defaults to `trust`.
- `include_patterns`: List of glob patterns to include projects. Defaults to `["*"]` (all projects).
- `exclude_patterns`: List of glob patterns to exclude projects. Applied before include patterns.

Patterns are case-sensitive and match the project's display name (`name`), not its path or namespace. Use valid glob syntax. Project filters affect project metrics and inventories; group members, group webhooks, runners, and group audit events retain their group scope.

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

Generate a group access token, or use a personal access token belonging to a dedicated service account, with the `read_api` scope. The role you assign determines which surfaces are collected:

| Role | Surfaces available |
|---|---|
| Reporter | Group settings, projects, branches, members; some security fields may be omitted |
| Developer | All Reporter surfaces + secret push protection status where exposed (Ultimate) |
| Maintainer | All Developer surfaces + project webhooks and deploy keys |
| Owner | All Maintainer surfaces + group webhooks and complete group audit events (Premium+) |

For the most complete collection, use **Owner**. For a minimal setup, **Reporter** works but several surfaces will be skipped with diagnostic warnings. Missing fields within successful API responses may not produce warnings; see [output limitations](docs/overview.md#output-limitations).

The group-runner list endpoint has separate requirements: GitLab currently documents **Owner** or **Auditor** (or a custom role with `admin_runners`), plus `manage_runner` scope. `read_api` alone should not be assumed to cover runners. See the [GitLab Runners API](https://docs.gitlab.com/api/runners/#list-all-of-a-groups-runners); requirements can differ on older self-managed versions.

### Required token scope

| Scope | What it covers |
|---|---|
| `read_api` | Group, projects, branches, members, webhooks, deploy keys, audit events, subject to role and tier |
| `manage_runner` | Additional scope documented for the group-runner endpoint; requires an appropriate role |

Optional surface failures emit diagnostics and collection continues. Any API response with HTTP 401 fails the run. Non-permission failures fetching the group or project list also fail the run. Successful responses can still be incomplete: for example, a Developer or Maintainer sees only their own group audit events. Use Owner for a group-wide audit summary. See [configuration](docs/configuration.md) for field visibility and tier requirements.

## Development

Use the Go toolchain pinned in `go.mod`. SDK commands require an epack build with component support. Install the matching conformance runner before `make sdk-test`:

```bash
go install -tags conformance github.com/locktivity/epack/cmd/epack-conformance@"$(go list -m -f '{{.Version}}' github.com/locktivity/epack)"
```

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
