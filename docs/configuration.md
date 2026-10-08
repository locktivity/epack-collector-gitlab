# Configuration

## Authentication

Set `GITLAB_TOKEN` to a group or personal access token with `read_api` scope. A group access token creates its own bot identity; a personal token can belong to a dedicated service account. Assign a role appropriate to the surfaces you need.

For a group access token, navigate to your GitLab group > Settings > Access tokens, create the token, and provide it through the `GITLAB_TOKEN` environment variable and the `secrets` entry below. Personal tokens can be created under your GitLab profile's access-token settings.

The collector does not call the Users API, so it does not require `read_user`. Adding that scope does not make hidden member 2FA fields available.

## epack.yaml

```yaml
stream: myorg/gitlab-posture

collectors:
  gitlab:
    source: locktivity/epack-collector-gitlab@^0.1
    config:
      group: my-organization
      level: trust
      # base_url: https://gitlab.example.com
      # include_patterns: ["backend-*"]
      # exclude_patterns: ["archived-*"]
    secrets:
      - GITLAB_TOKEN
```

## Configuration options

| Key | Required | Default | Description |
|---|---|---|---|
| `group` | Yes | | Group path, including a subgroup path, or numeric ID supplied as a string |
| `base_url` | No | `https://gitlab.com` | Instance URL; the collector appends `/api/v4` |
| `level` | No | `trust` | `trust`, `audit`, or `internal`; unknown values fall back to `trust` with an SDK warning |
| `include_patterns` | No | `["*"]` | Case-sensitive globs matching project display names |
| `exclude_patterns` | No | `[]` | Project display-name globs evaluated before includes |

Filters match `name`, not `path_with_namespace`. For example, `backend-*` matches a project named `backend-api`, regardless of its namespace. Projects in subgroups are included; projects shared into the group are excluded. Archived projects are included unless filtered out. Percentages use all included projects as their denominator.

Project filters apply to project metrics, project inventory, project webhooks, and deploy keys. Group members, group webhooks, runners, and group audit events keep their group scope. The configured group and filter patterns appear in trust output too.

Supply pattern lists as arrays of strings with valid glob syntax. Invalid globs and non-string list entries are rejected before collection begins.

## Secrets

| Secret | Required | Description |
|---|---|---|
| `GITLAB_TOKEN` | Yes | GitLab access token; never written into the artifacts |

## Self-managed and Dedicated instances

Set `base_url` to the instance URL, without an `/api/v4` suffix:

```yaml
config:
  group: my-org
  base_url: https://gitlab.example.com
```

For GitLab Dedicated, use the URL of your dedicated instance in the same way.

## Roles, scopes, and tiers

| Surface | Collection level | Requirements and limitations |
|---|---|---|
| Group settings, projects, branch protection | trust+ | `read_api`; visibility depends on token membership and role |
| Approval settings and rules | trust+ | Premium+; permissions can vary between the two endpoints |
| Secret push protection status | trust+ | Ultimate; status is exposed to Developer, Security Manager, Maintainer, or Owner where supported |
| Members | audit+ | `read_api`; inherited and invited membership follows the API's visibility rules |
| Member 2FA status | audit+ | API field introduced in GitLab 19.4 and visible to group Owners and administrators; missing values remain `null` |
| Project webhooks and deploy keys | audit+ | Maintainer or above |
| Group webhooks | audit+ | Premium+, Owner or administrator |
| Runners available to the group | audit+ | Current API documentation requires Owner/Auditor or custom `admin_runners`, and `manage_runner` scope |
| Group audit events | internal | Premium+; Owner for all users' events; Developer/Maintainer can receive only their own events |

Requirements vary with GitLab version. Consult the [Projects API](https://docs.gitlab.com/api/projects/#secret-push-protection-status), [Groups members API](https://docs.gitlab.com/api/group_members/), [Runners API](https://docs.gitlab.com/api/runners/#list-all-of-a-groups-runners), and [Audit events API](https://docs.gitlab.com/api/audit_events/#group-audit-events).

Optional endpoint failures emit diagnostics. HTTP 401 is always fatal; non-permission failures fetching the group or project list are fatal too. A successful response can omit restricted fields without a diagnostic. Group webhook and audit-event HTTP 403 diagnostics currently mention Premium even when the cause is insufficient role. Runner permission diagnostics currently mention Maintainer, although the group-list endpoint has stricter documented requirements.
