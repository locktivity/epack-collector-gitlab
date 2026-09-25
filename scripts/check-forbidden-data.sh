#!/usr/bin/env bash
# Fails if the collector emits forbidden GitLab data. The GitLab API exposes
# many sensitive surfaces; this guard keeps them out of the artifact.
#
# Forbidden patterns:
#   .Description  - project/MR/issue descriptions (customer data)
#   .Content      - file contents, note bodies
#   webhook_url   - full webhook URLs (can carry secrets); host only is allowed
#   .Token        - any token values
#   .Secret       - CI/CD variable secrets
#
# Suppress a deliberate, audited use with a trailing "// LINT-ALLOW: <reason>".
set -euo pipefail

violations=$(
  grep -rn -E '\.Description|\.Content|webhook_url|\.Token|\.Secret' \
    internal/collector/ \
    --include='*.go' \
    | grep -v '_test.go' \
    | grep -v '// LINT-ALLOW:' \
    || true
)

if [ -n "$violations" ]; then
  echo "FORBIDDEN GITLAB DATA EMISSION DETECTED:"
  echo "$violations"
  echo
  echo "If this use is deliberate and audited, append '// LINT-ALLOW: <reason>' to the line."
  exit 1
fi

echo "forbidden-data check: clean"
