# Configuration

## Authentication

The collector requires a GitLab access token with `read_api` scope. For audit-level collection, `read_user` scope is also recommended.

### Recommended: Group Access Token

1. Navigate to your GitLab group > Settings > Access tokens
2. Create a token with `read_api` scope
3. Set the token as the `GITLAB_TOKEN` secret in your epack.yaml

### Alternative: Personal Access Token

1. Navigate to your GitLab profile > Access tokens
2. Create a token with `read_api` and `read_user` scopes
3. Set the token as the `GITLAB_TOKEN` secret

## epack.yaml

```yaml
collectors:
  gitlab:
    source: locktivity/epack-collector-gitlab@^0.1
    config:
      group: my-organization
      # base_url: https://gitlab.example.com  # For self-managed instances
      # include_patterns: ["backend-*"]       # Optional project filtering
      # exclude_patterns: ["archived-*"]      # Optional project exclusion
    secrets:
      - GITLAB_TOKEN
```

## Configuration options

| Key | Required | Default | Description |
|---|---|---|---|
| `group` | Yes | | GitLab group path (e.g., `my-org`) or numeric ID |
| `base_url` | No | `https://gitlab.com` | Base URL for self-managed or dedicated instances |
| `include_patterns` | No | `["*"]` | Glob patterns to filter which projects to include |
| `exclude_patterns` | No | `[]` | Glob patterns for projects to exclude |

## Secrets

| Secret | Required | Description |
|---|---|---|
| `GITLAB_TOKEN` | Yes | GitLab access token with `read_api` scope |

## Self-managed instances

Set `base_url` to your instance URL. The collector appends `/api/v4/` automatically.

```yaml
config:
  group: my-org
  base_url: https://gitlab.example.com
```

## GitLab Dedicated

Same as self-managed, using your dedicated instance URL:

```yaml
config:
  group: my-org
  base_url: https://mycompany.gitlab-dedicated.com
```

## Required permissions by tier

Some surfaces require GitLab Premium or Ultimate:

| Surface | Minimum tier | Degradation |
|---|---|---|
| Branch protection | Free | Always available |
| Approval rules | Premium | Diagnostic warning |
| Group webhooks | Premium | Diagnostic warning |
| Audit events | Premium | Diagnostic warning |
| Vulnerability findings | Ultimate | Diagnostic warning |
