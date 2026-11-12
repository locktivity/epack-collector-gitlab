# Configuration

## Authentication

Set `GITLAB_TOKEN` to a group or personal access token with `read_api` scope. A group access token creates its own bot identity; a personal token can belong to a dedicated service account. Assign a role appropriate to the surfaces you need. The access-posture values need the Owner role. Each call's scope or role is in the collector result, and a `permission_denied` gap names it. The collector reads scanners and vulnerabilities through the GraphQL API, which `read_api` also covers.

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
| `base_url` | No | `https://gitlab.com` | Instance URL over https; the collector appends `/api/v4` |
| `level` | No | `trust` | `trust`, `audit`, or `internal`; unknown values fall back to `trust` with an SDK warning |
| `include_patterns` | No | `["*"]` | Case-sensitive globs matching project display names |
| `exclude_patterns` | No | `[]` | Project display-name globs evaluated before includes |
| `collect` | No | every kind | The artifacts to collect, from `details`, `vcs-posture`, `access-posture`, and `vuln-scanning` |

Filters match `name`, not `path_with_namespace`. For example, `backend-*` matches a project named `backend-api`, regardless of its namespace. Projects in subgroups are included; projects shared into the group are excluded. Archived projects are included unless filtered out. Percentages use all included projects as their denominator.

Project filters apply to project metrics, project inventory, project webhooks, deploy keys, project access tokens, scanner coverage, and vulnerabilities. Group members, group access tokens, group webhooks, runners, and group audit events keep their group scope. The configured group and filter patterns appear in trust output too. Below the audit level, a group configured by its numeric ID appears by its full path.

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

The collector never sends the token over plain http, so an `http://` URL is invalid configuration unless it names a loopback host such as `localhost`.

For GitLab Dedicated, use the URL of your dedicated instance in the same way.

## Roles, scopes, and tiers

| Surface | Collection level | Requirements and limitations |
|---|---|---|
| Group settings, projects, branch protection | trust+ | `read_api`; visibility depends on token membership and role. With Premium or Ultimate the group settings include its IP restriction, which applies to every access token and deploy key |
| Approval settings and rules | trust+ | Premium+; permissions can vary between the two endpoints |
| Secret push protection status | trust+ | Ultimate; status is exposed to Developer, Security Manager, Maintainer, or Owner where supported |
| Members | trust+ | `read_api`; inherited and invited membership follows the API's visibility rules. The detailed member inventory is audit+ |
| Member 2FA status and SAML and SCIM identities | trust+ | Owner. 2FA status needs GitLab 19.4 or later. The identities appear only in groups with SAML SSO. Without them the access-posture MFA and SSO values are left out as `permission_denied`. On GitLab before 19.4, an Owner token whose group has SAML or SCIM identities gets the SSO values, and the MFA values are left out as `unsupported`. In the detailed inventory, missing 2FA values remain `null` |
| Billable members, for each member's last activity and the people with a role only in a subgroup or a project | trust+ | Owner, and a top-level group. Other roles get HTTP 400, which leaves the member counts, the percentages over every member, and the inactive values out as `permission_denied`. A subgroup has no list of its own, so its inactive values are left out as `not_read` |
| Custom roles, when a member has one | trust+ | Owner, GitLab Ultimate on GitLab.com. A GitLab Self-Managed instance lists custom roles only to an administrator. Without them, the admin counts are left out with a `partial` gap |
| Group access tokens | trust+ | Owner. Other roles get HTTP 401, which leaves the credential values out as `permission_denied` |
| Project access tokens | trust+ | Maintainer or above |
| Deploy keys | trust+ | Maintainer or above. The detailed counts are audit+ |
| Security scanners of each project | trust+ | `read_api`, through the GraphQL API |
| Vulnerabilities | trust+ | Ultimate, and Developer or above, through the GraphQL API. Without Ultimate the finding values are left out as `not_licensed` |
| Project webhooks | audit+ | Maintainer or above |
| Group webhooks | audit+ | Premium+, Owner or administrator |
| Runners available to the group | audit+ | Current API documentation requires Owner/Auditor or custom `admin_runners`, and `manage_runner` scope |
| Group audit events | internal | Premium+; Owner for all users' events; Developer/Maintainer can receive only their own events |

Requirements vary with GitLab version. Consult the [Projects API](https://docs.gitlab.com/api/projects/#secret-push-protection-status), [Groups members API](https://docs.gitlab.com/api/group_members/), [billable members](https://docs.gitlab.com/api/members/#list-all-billable-members-of-a-group), [Group access tokens API](https://docs.gitlab.com/api/group_access_tokens/), [Project access tokens API](https://docs.gitlab.com/api/project_access_tokens/), [Deploy keys API](https://docs.gitlab.com/api/deploy_keys/), [Runners API](https://docs.gitlab.com/api/runners/#list-all-of-a-groups-runners), [Audit events API](https://docs.gitlab.com/api/audit_events/#group-audit-events), and [GraphQL API](https://docs.gitlab.com/api/graphql/).

Reading the configured group is the collector's sign-in, and the only read whose failure fails the run: a rejected token exits 3 with `auth_failed`, and a group GitLab says does not exist exits 2 with `config_invalid`. Any other endpoint that fails, including with HTTP 401, leaves its values out with a gap in `artifacts/gitlab.collector-result.json` and a diagnostic, and collection continues. GitLab Free answers the Premium endpoints (approval settings and rules, group webhooks, and group audit events) as routes it does not have, so those values are left out as `not_licensed`. A successful response can omit restricted fields: a missing group setting or project setting is left out with a gap rather than read as false. Group webhook and audit-event HTTP 403 diagnostics currently mention Premium even when the cause is insufficient role. Runner permission diagnostics currently mention Maintainer, although the group-list endpoint has stricter documented requirements.
