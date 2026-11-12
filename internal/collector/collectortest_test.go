package collector

import (
	"net/http"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

var kitOperations = []string{
	"gitlab.groups.get",
	"gitlab.projects.list",
	"gitlab.protected_branches.list",
	"gitlab.approval_settings.get",
	"gitlab.approval_rules.list",
	"gitlab.group_members.list",
	"gitlab.billable_members.list",
	"gitlab.group_hooks.list",
	"gitlab.project_hooks.list",
	"gitlab.deploy_keys.list",
	"gitlab.group_runners.list",
	"gitlab.group_audit_events.list",
	"gitlab.group_access_tokens.list",
	"gitlab.project_access_tokens.list",
	"gitlab.graphql.security_scanners",
	"gitlab.graphql.vulnerabilities",
}

// kitSemantics declares the 401 the access token lists answer a token
// without the role they need with. The sign-in already worked, so the gap
// is permission_denied.
var kitSemantics = []collectortest.Semantic{
	{Operation: "gitlab.group_access_tokens.list", Fault: "401", Meaning: "the token's role cannot list the group's access tokens"},
	{Operation: "gitlab.project_access_tokens.list", Fault: "401", Meaning: "the token's role cannot list the project's access tokens"},
}

// kitIgnore keeps the diagnostics that readers parse out of the value
// comparison: a fault adds a warning by design, and the normalized artifact
// repeats them in unavailable_sources.
var kitIgnore = map[string][]string{
	DetailedPath:   {"/diagnostics"},
	NormalizedPath: {"/unavailable_sources"},
}

// kitResultPath is where the kit's runs write their collector result.
const kitResultPath = "artifacts/gitlab.collector-result.json"

func kitConfig() map[string]any {
	return map[string]any{
		"group":            kitGroup,
		"exclude_patterns": []any{"sandbox-*"},
		"level":            "internal",
	}
}

func kitSecrets() map[string]string {
	return map[string]string{"GITLAB_TOKEN": kitToken}
}

func TestCollectorKit(t *testing.T) {
	collectortest.Run(t, collectortest.Suite{
		Spec:    Spec("test", "collectortest"),
		Run:     Run,
		Config:  kitConfig(),
		Secrets: kitSecrets(),
		Clock:   kitNow,
		Scenarios: []collectortest.Scenario{
			{
				Name:      "clean",
				Responses: kitResponses(kitCleanTenant(), kitBase),
				Expect: map[string]map[string]any{
					DetailedPath: {
						"/scope/projects_coverage":                        80,
						"/scope/included_project_count":                   4,
						"/posture/branch_protection_coverage":             50,
						"/posture/security_features_coverage":             62,
						"/branch_protection_rules/merge_request_required": 25,
						"/branch_protection_rules/approving_reviews":      50,
						"/branch_protection_rules/no_force_push":          25,
						"/security_features/secret_push_protection":       75,
						"/members/per_member/3/two_factor_enabled":        nil,
						"/webhooks/project_count":                         2,
						"/deploy_keys/read_write_count":                   1,
						"/audit_log/count_by_action/unknown":              1,
					},
					NormalizedPath: {
						"/repo_coverage_pct":                       80,
						"/branch_protection/approving_reviews_pct": 50,
						"/org_security/two_factor_required":        true,
						"/security_features/vuln_alerts_pct":       25,
						"/security_features/code_scanning_pct":     50,
						"/security_features/secret_scanning_pct":   50,
					},
					AccessPath: {
						"/sign_in/mfa_required":                true,
						"/sign_in/sso_configured":              true,
						"/sign_in/scim_enabled":                true,
						"/sign_in/sso_required":                collectortest.Absent,
						"/members/member_count":                4,
						"/members/sso_coverage_pct":            25,
						"/members/local_member_count":          4,
						"/members/local_mfa_coverage_pct":      50,
						"/members/inactive_member_count":       2,
						"/members/inactive_pct":                50,
						"/members/external_members_present":    collectortest.Absent,
						"/admins/admin_count":                  2,
						"/admins/admin_share_pct":              50,
						"/admins/local_admins_present":         true,
						"/admins/local_admin_mfa_coverage_pct": 50,
						"/credentials/credential_count":        5,
						"/credentials/never_expiring_pct":      40,
						"/credentials/unused_pct":              60,
						"/credentials/unrestricted_pct":        20,
						"/credentials/write_access_pct":        60,
						"/credentials/rotation_overdue_pct":    60,
						"/root/root_accounts_present":          false,
						"/root/root_account_count":             0,
						"/root/root_mfa_account_count":         0,
						"/root/root_mfa_coverage_pct":          nil,
						"/root/root_access_keys_present":       false,
						"/connected_apps":                      collectortest.Absent,
					},
					VulnPath: {
						"/scanners/0/scanner":                "dependency_scanning",
						"/scanners/0/coverage_pct":           25,
						"/scanners/0/open_critical_count":    1,
						"/scanners/0/overdue_critical_count": 1,
						"/scanners/0/overdue_present":        true,
						"/scanners/1/enabled":                true,
						"/scanners/1/coverage_pct":           50,
						"/scanners/1/open_critical_present":  false,
						"/scanners/1/open_high_count":        1,
						"/scanners/1/overdue_high_count":     1,
						"/scanners/2/coverage_pct":           50,
						"/scanners/2/open_critical_present":  true,
						"/scanners/2/overdue_present":        false,
					},
				},
			},
			{
				Name:          "token rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses: []collectortest.Response{{
					URL:    kitBase + "/groups/" + kitGroup,
					Status: http.StatusUnauthorized,
					Body:   `{"message":"401 Unauthorized"}`,
				}},
			},
			{
				Name:      "empty group",
				Responses: kitResponses(kitEmptyTenant(), kitBase),
				Expect: map[string]map[string]any{
					DetailedPath: {
						"/scope/project_count":                       0,
						"/scope/projects_coverage":                   nil,
						"/branch_protection_rules/approving_reviews": nil,
						"/projects/per_project":                      []any{},
						"/webhooks/project_count":                    0,
						"/deploy_keys/total_count":                   0,
						"/audit_log/events":                          []any{},
					},
					NormalizedPath: {
						"/repositories_present":                           false,
						"/repo_coverage_pct":                              nil,
						"/scanned_repository_count":                       0,
						"/branch_protection/pr_required_pct":              nil,
						"/branch_protection/pr_required_repository_count": 0,
					},
					AccessPath: {
						"/members/members_present":             false,
						"/members/sso_coverage_pct":            nil,
						"/members/inactive_pct":                nil,
						"/members/inactive_member_count":       0,
						"/members/local_members_present":       false,
						"/admins/admins_present":               false,
						"/admins/local_admin_mfa_coverage_pct": nil,
						"/credentials/credentials_present":     false,
						"/credentials/credential_count":        0,
						"/credentials/never_expiring_pct":      nil,
						"/root/root_accounts_present":          false,
					},
					VulnPath: {
						"/scanners/0/resources_present":     false,
						"/scanners/0/enabled":               false,
						"/scanners/0/coverage_pct":          nil,
						"/scanners/0/open_critical_present": false,
						"/scanners/0/open_critical_count":   0,
					},
				},
			},
			{
				Name:      "no open vulnerabilities",
				Responses: kitResponses(kitNoFindingsTenant(), kitBase),
				Expect: map[string]map[string]any{
					VulnPath: {
						"/scanners/0/coverage_pct":          100,
						"/scanners/1/coverage_pct":          100,
						"/scanners/2/coverage_pct":          100,
						"/scanners/0/open_critical_present": false,
						"/scanners/1/open_high_present":     false,
						"/scanners/2/overdue_present":       false,
						"/scanners/2/open_low_count":        0,
					},
				},
			},
			{
				Name:      "token with the Maintainer role",
				Responses: kitMaintainerResponses(),
				Expect: map[string]map[string]any{
					AccessPath: {
						"/sign_in/mfa_required":                true,
						"/sign_in/sso_configured":              collectortest.Absent,
						"/members/members_present":             true,
						"/members/member_count":                4,
						"/members/local_members_present":       true,
						"/members/local_mfa_coverage_pct":      collectortest.Absent,
						"/members/inactive_pct":                collectortest.Absent,
						"/admins/admins_present":               true,
						"/admins/local_admins_present":         true,
						"/admins/local_admin_mfa_coverage_pct": collectortest.Absent,
						"/credentials/credentials_present":     true,
						"/credentials/credential_count":        collectortest.Absent,
					},
					VulnPath: {
						"/scanners/0/coverage_pct":          25,
						"/scanners/0/open_critical_present": collectortest.Absent,
					},
				},
			},
			{
				Name:          "group not found",
				ExpectFailure: componentsdk.CodeConfigInvalid,
				Responses: []collectortest.Response{{
					URL:    kitBase + "/groups/" + kitGroup,
					Status: http.StatusNotFound,
					Body:   `{"message":"404 Group Not Found"}`,
				}},
			},
			{
				Name:      "project list redirects to another host",
				Responses: kitRedirectResponses(kitMirror),
				Expect: map[string]map[string]any{
					DetailedPath: {
						"/scope/included_project_count":       nil,
						"/posture/branch_protection_coverage": nil,
						"/webhooks/group_count":               1,
					},
					NormalizedPath: {
						"/repo_coverage_pct": nil,
					},
					AccessPath: {
						"/sign_in/mfa_required":            true,
						"/members/member_count":            4,
						"/credentials/credentials_present": true,
						"/credentials/credential_count":    collectortest.Absent,
					},
					VulnPath: {
						"/scanners/0/coverage_pct":          collectortest.Absent,
						"/scanners/0/open_critical_present": collectortest.Absent,
					},
				},
			},
			{
				Name:      "GitLab Free edition",
				Responses: kitFreeEditionResponses(),
				Expect: map[string]map[string]any{
					DetailedPath: {
						"/branch_protection_rules/approving_reviews":      nil,
						"/branch_protection_rules/merge_request_required": 25,
						"/webhooks/group_count":                           nil,
						"/audit_log":                                      nil,
					},
				},
			},
			{
				Name:      "GitLab Premium edition",
				Responses: kitResponses(kitPremiumTenant(), kitBase),
				Expect: map[string]map[string]any{
					DetailedPath: {
						"/security_features/secret_push_protection": nil,
						"/security_features/pipeline_required":      50,
						"/posture/security_features_coverage":       nil,
					},
					NormalizedPath: {
						"/branch_protection/status_checks_pct": 50,
					},
					VulnPath: {
						"/scanners/0/coverage_pct":          25,
						"/scanners/0/open_critical_present": collectortest.Absent,
						"/scanners/1/open_high_count":       collectortest.Absent,
					},
				},
			},
			{
				Name:      "subgroup",
				Responses: kitResponses(kitSubgroupTenant(), kitBase),
				Expect: map[string]map[string]any{
					AccessPath: {
						"/sign_in/mfa_required":                true,
						"/members/member_count":                4,
						"/members/inactive_pct":                collectortest.Absent,
						"/admins/local_admin_mfa_coverage_pct": 50,
						"/credentials/never_expiring_pct":      40,
						"/credentials/unrestricted_pct":        collectortest.Absent,
					},
					VulnPath: {
						"/scanners/0/open_critical_count": 1,
					},
				},
			},
			{
				Name:      "group restricted by IP address",
				Responses: kitResponses(kitIPRestrictedTenant(), kitBase),
				Expect: map[string]map[string]any{
					AccessPath: {
						"/credentials/credential_count":              5,
						"/credentials/unrestricted_credential_count": 0,
						"/credentials/unrestricted_pct":              0,
						"/credentials/write_access_pct":              60,
					},
				},
			},
			{
				Name:      "Guest on GitLab Ultimate",
				Responses: kitResponses(kitUltimateGuestTenant(), kitBase),
				Expect: map[string]map[string]any{
					AccessPath: {
						"/members/member_count":           5,
						"/members/inactive_member_count":  collectortest.Absent,
						"/members/inactive_pct":           collectortest.Absent,
						"/members/local_mfa_coverage_pct": 60,
					},
				},
			},
			{
				Name:      "inventories over their caps",
				Responses: kitOverTheCapsResponses(),
				// The project list stops at the cap, below the projects the
				// run assessed, so the project targets are not complete.
				Expect: map[string]map[string]any{
					DetailedPath: {
						"/projects/total_count": MaxProjects + 1,
						"/projects/truncated":   true,
						"/members/total_count":  MaxMembers + 1,
						"/members/truncated":    true,
					},
					kitResultPath: {
						"/targets/1/kind":     "project",
						"/targets/1/count":    MaxProjects,
						"/targets/1/complete": false,
					},
				},
			},
		},
		Required:   []string{"gitlab.groups.get"},
		Semantics:  kitSemantics,
		Ignore:     kitIgnore,
		Operations: kitOperations,
		// Checks that each gap a fault leaves records the faulted call.
		GapOperations: true,
	})
}

// TestCollectorKitSelfManaged checks a self-managed instance at a host and
// port of its own: the calls go there, and a redirect never carries the token
// anywhere else. The fault matrix runs once, in the GitLab.com suite, since
// the calls are the same.
func TestCollectorKitSelfManaged(t *testing.T) {
	config := kitConfig()
	config["base_url"] = "https://gitlab.example.com:8443/"
	collectortest.Run(t, collectortest.Suite{
		Spec:    Spec("test", "collectortest"),
		Run:     Run,
		Config:  config,
		Secrets: kitSecrets(),
		Clock:   kitNow,
		Scenarios: []collectortest.Scenario{
			{Name: "clean", Responses: kitResponses(kitCleanTenant(), kitSelfManagedBase)},
			{
				Name:          "token rejected",
				ExpectFailure: componentsdk.CodeAuthFailed,
				Responses: []collectortest.Response{{
					URL:    kitSelfManagedBase + "/groups/" + kitGroup,
					Status: http.StatusUnauthorized,
					Body:   `{"error":"invalid_token","error_description":"Token is expired. You can either do re-authorization or token refresh."}`,
				}},
			},
		},
		Required:   []string{"gitlab.groups.get"},
		Semantics:  kitSemantics,
		Ignore:     kitIgnore,
		Operations: kitOperations,
		SkipChecks: []string{"faults", "sensitivity"},
	})
}
