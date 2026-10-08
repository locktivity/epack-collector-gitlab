# Examples

## Basic usage (GitLab.com)

```yaml
# epack.yaml
stream: myorg/gitlab-posture

collectors:
  gitlab:
    source: locktivity/epack-collector-gitlab@^0.1
    config:
      group: my-organization
    secrets:
      - GITLAB_TOKEN
```

```bash
export GITLAB_TOKEN="glpat-xxxxxxxxxxxxxxxxxxxx"
epack collect
```

## Self-managed instance

```yaml
collectors:
  gitlab:
    source: locktivity/epack-collector-gitlab@^0.1
    config:
      group: engineering
      base_url: https://gitlab.internal.company.com
    secrets:
      - GITLAB_TOKEN
```

## Filtered project collection

```yaml
collectors:
  gitlab:
    source: locktivity/epack-collector-gitlab@^0.1
    config:
      group: my-organization
      include_patterns:
        - "backend-*"
        - "frontend-*"
      exclude_patterns:
        - "*-archived"
    secrets:
      - GITLAB_TOKEN
```

## Audit-level collection

Set the collection level in the collector configuration:

```yaml
stream: myorg/gitlab-posture

collectors:
  gitlab:
    source: locktivity/epack-collector-gitlab@^0.1
    config:
      group: my-organization
      level: audit
    secrets:
      - GITLAB_TOKEN
```

```bash
epack collect
```

## Sample trust-level output

```json
{
  "schema_version": "1.0.0",
  "collected_at": "2026-09-18T12:00:00Z",
  "collected_at_level": "trust",
  "group": "my-organization",
  "scope": {
    "include_patterns": ["*"],
    "exclude_patterns": [],
    "projects_coverage": 100
  },
  "posture": {
    "branch_protection_coverage": 95,
    "security_features_coverage": 72
  },
  "access_control": {
    "two_factor_required": true
  },
  "branch_protection_rules": {
    "merge_request_required": 92,
    "approving_reviews": 78,
    "code_owner_approval": 45,
    "no_force_push": 95
  },
  "security_features": {
    "secret_push_protection": 60,
    "pipeline_required": 84
  }
}
```

This is an illustrative output. `diagnostics` is omitted when there are no warnings or permission errors. The 72% security-features coverage above is the mean of 60% secret push protection and 84% pipeline-required coverage. See [output limitations](overview.md#output-limitations) before interpreting zeros as disabled controls.
