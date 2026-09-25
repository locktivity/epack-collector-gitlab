# GitLab Collector

The GitLab collector reads the GitLab REST API (v4) for a single top-level group and emits version control system security posture evidence.

## What it collects

- Branch protection rules and enforcement across projects
- Merge request approval rules and settings
- Security scanning adoption (secret detection, dependency scanning, SAST)
- Access control posture (2FA enforcement, member roles, project creation policy)
- Member inventory with roles and 2FA status
- Project inventory with visibility and protection detail
- Webhook, deploy key, and runner surfaces
- Audit events (Premium+ tiers)

## Hosting modes

Works with all GitLab deployment types:

- **GitLab.com** (SaaS): default, no extra config
- **Self-managed**: set `base_url` to your instance URL
- **GitLab Dedicated**: set `base_url` to your dedicated instance URL

## Output

Two artifacts per run:

1. `artifacts/gitlab.json`: detailed GitLab-specific posture data
2. `artifacts/gitlab.vcs-posture.json`: normalized VCS posture following the `evidencepack/vcs-posture@v1` schema
