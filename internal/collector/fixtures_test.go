package collector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

const (
	kitBase            = "https://gitlab.com/api/v4"
	kitSelfManagedBase = "https://gitlab.example.com:8443/api/v4"
	kitGroup           = "acme"
	kitToken           = "glpat-kit0123456789abcdef"
	kitMirror          = "https://gitlab-mirror.example.com"
)

var kitNow = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

// kitTenant is a group as GitLab's API answers for it, page by page.
type kitTenant struct {
	group        gitlab.Group
	projectPages [][]gitlab.Project
	branches     map[int][]gitlab.ProtectedBranch
	approvals    map[int]gitlab.ApprovalSettings
	rules        map[int][]gitlab.ApprovalRule
	memberPages  [][]gitlab.Member
	// billablePages are the pages of the billable members list, which
	// GitLab answers only for a top-level group.
	billablePages [][]gitlab.BillableMember
	groupHooks    []gitlab.Webhook
	projectHooks  map[int][]gitlab.Webhook
	deployKeys    map[int][]gitlab.DeployKey
	runners       []gitlab.Runner
	auditEvents   []gitlab.AuditEvent
	// memberRoles are the group's custom roles, listed when a member holds
	// one.
	memberRoles []gitlab.MemberRole

	groupTokens   []gitlab.AccessToken
	projectTokens map[int][]gitlab.AccessToken
	// scanners holds each project's securityScanners for the GraphQL API.
	scanners map[int]kitScanners
	// vulnPages are the pages of the group's open vulnerabilities. A nil
	// list answers as a group whose vulnerability report the token cannot
	// read.
	vulnPages [][]kitVuln
}

// kitScanners is one project's securityScanners.
type kitScanners struct {
	Available   []string `json:"available"`
	PipelineRun []string `json:"pipelineRun"`
}

// kitVuln is one open vulnerability as the GraphQL API lists it.
type kitVuln struct {
	project    int
	reportType string
	severity   string
	detectedAt time.Time
}

// kitUltimateScanners are the scanners GitLab Ultimate makes available.
var kitUltimateScanners = []string{"SAST", "SAST_ADVANCED", "DEPENDENCY_SCANNING", "CONTAINER_SCANNING", "SECRET_DETECTION", "DAST"}

// kitPremiumScanners are the scanners Free and Premium make available.
var kitPremiumScanners = []string{"SAST", "SECRET_DETECTION"}

func kitGroupDetails() gitlab.Group {
	return gitlab.Group{
		ID:                             7,
		Name:                           "Acme",
		FullPath:                       kitGroup,
		Visibility:                     "private",
		RequireTwoFactorAuthentication: boolPtr(true),
		ProjectCreationLevel:           strPtr("maintainer"),
		ShareWithGroupLock:             boolPtr(false),
	}
}

func kitProject(id int, name, visibility, defaultBranch string, secretPush, pipeline bool) gitlab.Project {
	created := time.Date(2025, 3, 1, 9, 0, 0, 0, time.UTC)
	active := time.Date(2026, 10, 16, 18, 30, 0, 0, time.UTC)
	return gitlab.Project{
		ID:                               id,
		Name:                             name,
		PathWithNamespace:                kitGroup + "/" + name,
		Visibility:                       visibility,
		DefaultBranch:                    defaultBranch,
		CreatedAt:                        &created,
		LastActivityAt:                   &active,
		MergeMethod:                      "merge",
		SecretPushProtectionEnabled:      &secretPush,
		OnlyAllowMergeIfPipelineSucceeds: &pipeline,
	}
}

func day(year int, month time.Month, d int) *time.Time {
	t := time.Date(year, month, d, 9, 0, 0, 0, time.UTC)
	return &t
}

// kitCleanTenant has five projects on two pages, one of them excluded by
// the suite's sandbox-* pattern and one with no commits. It has a blocked
// member whose two-factor status the API does not show, a bot user, and an
// Owner without MFA. Its billable members list has two members inactive for
// more than 90 days, one of them never active, and a project member from
// outside the group. Its credentials are three access tokens and two deploy
// keys, one of them enabled in two projects. A third deploy key and a
// revoked token are left out. Its open vulnerabilities come on two pages.
func kitCleanTenant() kitTenant {
	empty := kitProject(13, "empty-repo", "private", "", true, true)
	empty.Archived = true
	keyCreated := time.Date(2026, 2, 10, 8, 0, 0, 0, time.UTC)
	saml := &gitlab.Identity{Provider: "group_saml"}
	return kitTenant{
		group: kitGroupDetails(),
		projectPages: [][]gitlab.Project{
			{
				kitProject(10, "api", "private", "main", true, true),
				kitProject(11, "web", "internal", "main", false, false),
				kitProject(14, "sandbox-test", "private", "main", false, false),
			},
			{
				kitProject(12, "docs", "public", "main", true, false),
				empty,
			},
		},
		branches: map[int][]gitlab.ProtectedBranch{
			10: {{
				ID: 1, Name: "main", CodeOwnerApprovalRequired: true,
				PushAccessLevels:  []gitlab.BranchAccessLevel{{AccessLevel: 0, AccessLevelDesc: "No one"}},
				MergeAccessLevels: []gitlab.BranchAccessLevel{{AccessLevel: 40, AccessLevelDesc: "Maintainers"}},
			}},
			11: {{
				ID: 2, Name: "m*", AllowForcePush: true,
				PushAccessLevels:  []gitlab.BranchAccessLevel{{AccessLevel: 30, AccessLevelDesc: "Developers + Maintainers"}},
				MergeAccessLevels: []gitlab.BranchAccessLevel{{AccessLevel: 30, AccessLevelDesc: "Developers + Maintainers"}},
			}},
		},
		approvals: map[int]gitlab.ApprovalSettings{
			10: {ApprovalsBeforeMerge: 2, ResetApprovalsOnPush: true},
		},
		rules: map[int][]gitlab.ApprovalRule{
			11: {{ID: 1, Name: "All protected branches", RuleType: "regular", ApprovalsRequired: 1, AppliesToAllProtectedBranches: true}},
			12: {{ID: 2, Name: "Releases", RuleType: "regular", ApprovalsRequired: 2, ProtectedBranches: []gitlab.ApprovalRuleBranch{{ID: 9, Name: "release-*"}}}},
		},
		memberPages: [][]gitlab.Member{
			{
				{ID: 1, Username: "alice", Name: "Alice", State: "active", AccessLevel: 50, TwoFactorEnabled: boolPtr(true), GroupSAMLIdentity: saml, GroupSCIMIdentity: &gitlab.Identity{Provider: "group_scim"}},
				{ID: 2, Username: "bob", Name: "Bob", State: "active", AccessLevel: 40, TwoFactorEnabled: boolPtr(false), MemberRole: &gitlab.MemberRole{ID: 3}},
			},
			{
				{ID: 3, Username: "carol", Name: "Carol", State: "active", AccessLevel: 30, TwoFactorEnabled: boolPtr(true)},
				{ID: 4, Username: "dave", Name: "Dave", State: "blocked", AccessLevel: 20},
				{ID: 5, Username: "erin", Name: "Erin", State: "active", AccessLevel: 50, TwoFactorEnabled: boolPtr(false)},
				{ID: 6, Username: "group_7_bot_5c1e9a", Name: "release token", State: "active", AccessLevel: 40, TwoFactorEnabled: boolPtr(false)},
			},
		},
		// bob's custom role can neither manage the group's members nor
		// delete the group, so he is not an admin.
		memberRoles: []gitlab.MemberRole{{ID: 3}},
		billablePages: [][]gitlab.BillableMember{
			{
				{ID: 1, LastActivityOn: kitDate(2026, 10, 16)},
				// The day before the date 90 days before the run.
				{ID: 2, LastActivityOn: kitDate(2026, 7, 18)},
			},
			{
				{ID: 3},
				// The date 90 days before the run.
				{ID: 5, LastActivityOn: kitDate(2026, 7, 19)},
				// frank holds a role only on a project, so the group's
				// member list does not have him.
				{ID: 20, Username: "frank", State: "active", LastActivityOn: kitDate(2025, 1, 1)},
			},
		},
		groupHooks: []gitlab.Webhook{
			{ID: 1, URL: "https://hooks.example.com/gitlab", PushEvents: true, EnableSSLVerification: true, AlertStatus: "executable"},
		},
		projectHooks: map[int][]gitlab.Webhook{
			10: {{ID: 11, URL: "https://ci.example.com/hook", MergeRequestsEvents: true, EnableSSLVerification: true, AlertStatus: "executable"}},
			12: {{ID: 12, URL: "http://legacy.example.com:8080/hook", PushEvents: true, AlertStatus: "disabled"}},
		},
		deployKeys: map[int][]gitlab.DeployKey{
			10: {{ID: 21, Title: "release-bot", Fingerprint: "4a:7b:2c:9d:1e:6f:30:85:aa:bb:cc:dd:ee:ff:00:11", CanPush: true, CreatedAt: &keyCreated, LastUsedAt: day(2026, 10, 1)}},
			11: {{ID: 22, Title: "read-only mirror", CanPush: false, CreatedAt: &keyCreated}},
			12: {
				{ID: 21, Title: "release-bot", CanPush: false, CreatedAt: &keyCreated, LastUsedAt: day(2026, 10, 1)},
				{ID: 23, Title: "old mirror", CanPush: false, CreatedAt: &keyCreated, ExpiresAt: day(2026, 9, 1)},
			},
		},
		groupTokens: []gitlab.AccessToken{
			{ID: 51, UserID: 6, Scopes: []string{"api"}, Active: true, AccessLevel: 40, CreatedAt: day(2026, 9, 1), LastUsedAt: day(2026, 10, 15), ExpiresAt: &gitlab.Date{Time: *day(2027, 9, 1)}},
			{ID: 52, UserID: 8, Scopes: []string{"read_api"}, Active: true, AccessLevel: 20, CreatedAt: day(2025, 12, 1), ExpiresAt: &gitlab.Date{Time: *day(2026, 11, 30)}},
			{ID: 53, UserID: 9, Scopes: []string{"api"}, Revoked: true, AccessLevel: 50, CreatedAt: day(2025, 1, 1), ExpiresAt: &gitlab.Date{Time: *day(2026, 1, 1)}},
		},
		projectTokens: map[int][]gitlab.AccessToken{
			10: {{ID: 61, UserID: 10, Scopes: []string{"read_repository", "write_repository"}, Active: true, AccessLevel: 30, CreatedAt: day(2026, 8, 1), LastUsedAt: day(2026, 6, 1), ExpiresAt: &gitlab.Date{Time: *day(2027, 7, 31)}}},
		},
		scanners: map[int]kitScanners{
			10: {Available: kitUltimateScanners, PipelineRun: []string{"SAST", "DEPENDENCY_SCANNING", "SECRET_DETECTION"}},
			11: {Available: kitUltimateScanners, PipelineRun: []string{}},
			12: {Available: kitUltimateScanners, PipelineRun: []string{"SAST", "SECRET_DETECTION"}},
			13: {Available: kitUltimateScanners, PipelineRun: []string{}},
		},
		vulnPages: [][]kitVuln{
			{
				{10, "DEPENDENCY_SCANNING", "CRITICAL", *day(2026, 8, 1)},
				{10, "DEPENDENCY_SCANNING", "HIGH", *day(2026, 9, 20)},
				{10, "SAST", "HIGH", *day(2026, 5, 1)},
				{14, "SAST", "CRITICAL", *day(2026, 1, 1)},
			},
			{
				{12, "SECRET_DETECTION", "CRITICAL", *day(2026, 10, 10)},
				{12, "SAST", "MEDIUM", *day(2026, 3, 1)},
				{11, "SAST", "LOW", *day(2026, 7, 1)},
				{10, "DEPENDENCY_SCANNING", "LOW", *day(2025, 11, 1)},
			},
		},
		runners: []gitlab.Runner{
			{ID: 31, Description: "acme-shared", Status: "online", RunnerType: "group_type", Online: true},
		},
		auditEvents: []gitlab.AuditEvent{
			{ID: 41, AuthorID: 1, EntityID: 7, EntityType: "Group", Details: gitlab.AuditEventDetails{CustomMessage: "Added member carol", AuthorName: "alice"}, CreatedAt: timePtr(time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC))},
			{ID: 42, AuthorID: 2, EntityID: 7, EntityType: "Group", Details: gitlab.AuditEventDetails{AuthorName: "bob"}, CreatedAt: timePtr(time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC))},
		},
	}
}

// kitEmptyTenant is a group with nothing in it.
func kitEmptyTenant() kitTenant {
	return kitTenant{
		group:         kitGroupDetails(),
		projectPages:  [][]gitlab.Project{{}},
		memberPages:   [][]gitlab.Member{{}},
		billablePages: [][]gitlab.BillableMember{{}},
		groupHooks:    []gitlab.Webhook{},
		runners:       []gitlab.Runner{},
		auditEvents:   []gitlab.AuditEvent{},
		groupTokens:   []gitlab.AccessToken{},
		vulnPages:     [][]kitVuln{{}},
	}
}

// kitNoFindingsTenant is the clean group with every scanner set up in every
// project and no open vulnerabilities.
func kitNoFindingsTenant() kitTenant {
	t := kitCleanTenant()
	all := []string{"SAST", "DEPENDENCY_SCANNING", "SECRET_DETECTION"}
	for id := range t.scanners {
		t.scanners[id] = kitScanners{Available: kitUltimateScanners, PipelineRun: all}
	}
	t.vulnPages = [][]kitVuln{{}}
	return t
}

// kitPremiumTenant is the clean group on GitLab Premium. Its projects have
// no secret_push_protection_enabled, since the setting needs Ultimate. The
// token cannot read the group's vulnerability report, which also needs
// Ultimate.
func kitPremiumTenant() kitTenant {
	t := kitCleanTenant()
	for _, page := range t.projectPages {
		for i := range page {
			page[i].SecretPushProtectionEnabled = nil
		}
	}
	for id, s := range t.scanners {
		s.Available = kitPremiumScanners
		t.scanners[id] = s
	}
	t.vulnPages = nil
	return t
}

// kitMaintainerTenant is the clean group as a token with the Maintainer
// role sees it. The member list has no Owner-only fields, and the group's
// access tokens and vulnerability report are out of reach.
func kitMaintainerTenant() kitTenant {
	t := kitCleanTenant()
	for _, page := range t.memberPages {
		for i := range page {
			page[i].TwoFactorEnabled = nil
			page[i].GroupSAMLIdentity = nil
			page[i].GroupSCIMIdentity = nil
		}
	}
	// The billable members list answers 400, on its first page.
	t.billablePages = [][]gitlab.BillableMember{{}}
	t.vulnPages = nil
	return t
}

// kitSubgroupTenant is the clean group as a subgroup. GitLab lists billable
// members only for a top-level group, and the top-level group's IP
// restriction applies to the subgroup's credentials.
func kitSubgroupTenant() kitTenant {
	t := kitCleanTenant()
	t.group.ParentID = intPtr(3)
	t.group.FullPath = "acme-parent/" + kitGroup
	t.billablePages = nil
	return t
}

// kitIPRestrictedTenant is the clean group restricting access by IP
// address, which limits every access token and deploy key.
func kitIPRestrictedTenant() kitTenant {
	t := kitCleanTenant()
	t.group.IPRestrictionRanges = "192.0.2.0/24,198.51.100.10"
	return t
}

// kitUltimateGuestTenant is the clean group on GitLab Ultimate with a Guest
// member, whom the billable members list leaves out.
// kitMemberManagerTenant is kitCleanTenant with bob's custom role able to
// add, remove, and assign the group's members.
func kitMemberManagerTenant() kitTenant {
	t := kitCleanTenant()
	t.memberRoles = []gitlab.MemberRole{{ID: 3, AdminGroupMember: true}}
	return t
}

func kitUltimateGuestTenant() kitTenant {
	t := kitCleanTenant()
	last := len(t.memberPages) - 1
	t.memberPages[last] = append(t.memberPages[last], gitlab.Member{ID: 7, Username: "gina", Name: "Gina", State: "active", AccessLevel: 10, TwoFactorEnabled: boolPtr(true)})
	return t
}

func timePtr(t time.Time) *time.Time { return &t }

func kitDate(year int, month time.Month, d int) *gitlab.Date {
	return &gitlab.Date{Time: time.Date(year, month, d, 0, 0, 0, 0, time.UTC)}
}

// kitResponses answers every call the collector makes for t at base, the
// instance's API root.
func kitResponses(t kitTenant, base string) []collectortest.Response {
	groupURL := base + "/groups/" + kitGroup
	responses := []collectortest.Response{{URL: groupURL, Body: kitJSON(t.group)}}
	responses = append(responses, kitPages(groupURL+"/projects?include_subgroups=true&with_shared=false", t.projectPages)...)

	for _, page := range t.projectPages {
		for _, p := range page {
			projectURL := fmt.Sprintf("%s/projects/%d", base, p.ID)
			responses = append(responses,
				kitList(projectURL+"/hooks", orEmpty(t.projectHooks[p.ID])),
				kitList(projectURL+"/deploy_keys", orEmpty(t.deployKeys[p.ID])))
			if p.DefaultBranch == "" {
				continue
			}
			responses = append(responses,
				kitList(projectURL+"/protected_branches", orEmpty(t.branches[p.ID])),
				collectortest.Response{URL: projectURL + "/approvals", Body: kitJSON(t.approvals[p.ID])},
				kitList(projectURL+"/approval_rules", orEmpty(t.rules[p.ID])))
		}
	}

	responses = append(responses, kitPages(groupURL+"/members/all", t.memberPages)...)
	if t.memberRoles != nil {
		responses = append(responses, kitList(groupURL+"/member_roles", t.memberRoles))
	}
	if t.group.ParentID == nil {
		responses = append(responses, kitPages(groupURL+"/billable_members", t.billablePages)...)
	}
	responses = append(responses, kitAccessTokenResponses(t, base)...)
	responses = append(responses, kitGraphQLResponses(t, base)...)
	return append(responses,
		kitList(groupURL+"/hooks", t.groupHooks),
		kitList(groupURL+"/runners?type=group_type", t.runners),
		kitList(groupURL+"/audit_events?created_after="+kitNow.AddDate(0, 0, -auditLogWindowDays).Format(time.RFC3339), t.auditEvents))
}

// kitAccessTokenResponses answer the group's access token list and each
// project's.
func kitAccessTokenResponses(t kitTenant, base string) []collectortest.Response {
	responses := []collectortest.Response{kitList(base+"/groups/"+kitGroup+"/access_tokens?state=active", orEmpty(t.groupTokens))}
	for _, page := range t.projectPages {
		for _, p := range page {
			responses = append(responses, kitList(fmt.Sprintf("%s/projects/%d/access_tokens?state=active", base, p.ID), orEmpty(t.projectTokens[p.ID])))
		}
	}
	return responses
}

// kitGraphQLURL is the GraphQL endpoint of the instance whose REST API is
// at base.
func kitGraphQLURL(base string) string {
	return strings.TrimSuffix(base, "/api/v4") + "/api/graphql"
}

// kitGraphQLResponses answer the security scanner query for the projects
// the suite's patterns select, and the vulnerability query page by page.
func kitGraphQLResponses(t kitTenant, base string) []collectortest.Response {
	url := kitGraphQLURL(base)
	var ids []int
	for _, page := range t.projectPages {
		for _, p := range page {
			if !strings.HasPrefix(p.Name, "sandbox-") {
				ids = append(ids, p.ID)
			}
		}
	}
	slices.Sort(ids)
	var responses []collectortest.Response
	if len(ids) > 0 {
		gids := make([]string, len(ids))
		nodes := make([]map[string]any, 0, len(ids))
		for i, id := range ids {
			gids[i] = fmt.Sprintf("gid://gitlab/Project/%d", id)
			if s, ok := t.scanners[id]; ok {
				nodes = append(nodes, map[string]any{"id": gids[i], "securityScanners": s})
			}
		}
		responses = append(responses, kitGraphQL(url, "GitLabSecurityScanners", map[string]any{"ids": gids, "after": nil},
			map[string]any{"projects": map[string]any{"nodes": nodes, "pageInfo": map[string]any{"hasNextPage": false, "endCursor": nil}}}))
	}

	if t.vulnPages == nil {
		return append(responses, kitGraphQL(url, "GitLabVulnerabilities", map[string]any{"group": t.group.FullPath, "after": nil},
			map[string]any{"group": map[string]any{
				"vulnerabilitySeveritiesCount": nil,
				"vulnerabilities":              map[string]any{"nodes": []any{}, "pageInfo": map[string]any{"hasNextPage": false, "endCursor": nil}},
			}}))
	}
	var after any
	for i, page := range t.vulnPages {
		nodes := make([]map[string]any, 0, len(page))
		critical := 0
		for _, v := range page {
			nodes = append(nodes, map[string]any{
				"reportType": v.reportType,
				"severity":   v.severity,
				"detectedAt": v.detectedAt.Format(time.RFC3339),
				"project":    map[string]any{"id": fmt.Sprintf("gid://gitlab/Project/%d", v.project)},
			})
			if v.severity == "CRITICAL" {
				critical++
			}
		}
		info := map[string]any{"hasNextPage": false, "endCursor": nil}
		cursor := fmt.Sprintf("kit-cursor-%d", i+1)
		if i+1 < len(t.vulnPages) {
			info = map[string]any{"hasNextPage": true, "endCursor": cursor}
		}
		responses = append(responses, kitGraphQL(url, "GitLabVulnerabilities", map[string]any{"group": t.group.FullPath, "after": after},
			map[string]any{"group": map[string]any{
				"vulnerabilitySeveritiesCount": map[string]any{"critical": critical},
				"vulnerabilities":              map[string]any{"nodes": nodes, "pageInfo": info},
			}}))
		after = cursor
	}
	return responses
}

// kitGraphQL answers the GraphQL query named name with variables with data.
func kitGraphQL(url, name string, variables map[string]any, data any) collectortest.Response {
	return collectortest.Response{
		Method:      http.MethodPost,
		URL:         url,
		RequestBody: kitJSON(map[string]any{"operationName": name, "variables": variables}),
		Body:        kitJSON(map[string]any{"data": data}),
	}
}

// kitList answers a list that fits on one page.
func kitList[T any](url string, items []T) collectortest.Response {
	return kitPages(url, [][]T{items})[0]
}

// kitPages answers a list page by page, each pointing to the next with
// X-Next-Page as GitLab does.
func kitPages[T any](url string, pages [][]T) []collectortest.Response {
	separator := "?"
	if strings.Contains(url, "?") {
		separator = "&"
	}
	var responses []collectortest.Response
	for i, page := range pages {
		r := collectortest.Response{
			URL:  fmt.Sprintf("%s%sper_page=100&page=%d", url, separator, i+1),
			Body: kitJSON(orEmpty(page)),
		}
		if i+1 < len(pages) {
			r.Header = http.Header{"X-Next-Page": []string{fmt.Sprint(i + 2)}}
		}
		responses = append(responses, r)
	}
	return responses
}

func orEmpty[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}

func kitJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

// replaceResponse swaps the response for r's URL.
func replaceResponse(responses []collectortest.Response, r collectortest.Response) []collectortest.Response {
	out := append([]collectortest.Response(nil), responses...)
	for i := range out {
		if out[i].URL == r.URL {
			out[i] = r
			return out
		}
	}
	panic("no response for " + r.URL)
}

// kitRedirectResponses answer the project list with a redirect to the same
// path at origin. With another host as origin they reproduce the October 2026
// incident, a redirect the collector used to follow with the access token.
func kitRedirectResponses(origin string) []collectortest.Response {
	path := "/api/v4/groups/" + kitGroup + "/projects?include_subgroups=true&with_shared=false&per_page=100&page=1"
	return replaceResponse(kitResponses(kitCleanTenant(), kitBase), collectortest.Response{
		URL:    "https://gitlab.com" + path,
		Status: http.StatusMovedPermanently,
		Header: http.Header{"Location": []string{origin + path}},
	})
}

// kitFreeEditionResponses answer as GitLab Free does for the Premium
// endpoints the collector reads: as routes it does not have. The
// vulnerability report needs Ultimate, as on Premium.
func kitFreeEditionResponses() []collectortest.Response {
	responses := kitResponses(kitPremiumTenant(), kitBase)
	missing := func(url string) collectortest.Response {
		return collectortest.Response{URL: url, Status: http.StatusNotFound, Body: `{"error":"404 Not Found"}`}
	}
	groupURL := kitBase + "/groups/" + kitGroup
	responses = replaceResponse(responses, missing(groupURL+"/hooks?per_page=100&page=1"))
	responses = replaceResponse(responses, missing(groupURL+"/audit_events?created_after="+kitNow.AddDate(0, 0, -auditLogWindowDays).Format(time.RFC3339)+"&per_page=100&page=1"))
	for _, id := range []int{10, 11, 12} {
		responses = replaceResponse(responses, missing(fmt.Sprintf("%s/projects/%d/approvals", kitBase, id)))
		responses = replaceResponse(responses, missing(fmt.Sprintf("%s/projects/%d/approval_rules?per_page=100&page=1", kitBase, id)))
	}
	return responses
}

// kitOverTheCapsResponses answer for a group with one project and one member
// more than the inventories list, so per_project and per_member are cut
// short. The projects have no commits, so their only calls are the webhook
// and deploy key lists, answered by operation.
func kitOverTheCapsResponses() []collectortest.Response {
	visibilities := []string{"private", "internal", "public"}
	projects := make([]gitlab.Project, MaxProjects+1)
	for i := range projects {
		projects[i] = kitProject(1000+i, fmt.Sprintf("project-%04d", i), visibilities[i%len(visibilities)], "", true, true)
	}
	accessLevels := []int{50, 40, 30, 20}
	members := make([]gitlab.Member, MaxMembers+1)
	for i := range members {
		members[i] = gitlab.Member{ID: 1000 + i, Username: fmt.Sprintf("user-%05d", i), State: "active", AccessLevel: accessLevels[i%len(accessLevels)]}
	}

	groupURL := kitBase + "/groups/" + kitGroup
	noProjects := map[string]any{"projects": map[string]any{"nodes": []any{}, "pageInfo": map[string]any{"hasNextPage": false}}}
	noVulns := map[string]any{"group": map[string]any{
		"vulnerabilitySeveritiesCount": map[string]any{"critical": 0},
		"vulnerabilities":              map[string]any{"nodes": []any{}, "pageInfo": map[string]any{"hasNextPage": false}},
	}}
	responses := []collectortest.Response{
		{Operation: "gitlab.billable_members.list", Body: "[]"},
		{Operation: "gitlab.project_hooks.list", Body: "[]"},
		{Operation: "gitlab.deploy_keys.list", Body: "[]"},
		{Operation: "gitlab.project_access_tokens.list", Body: "[]"},
		{Operation: "gitlab.graphql.security_scanners", Body: kitJSON(map[string]any{"data": noProjects})},
		{Operation: "gitlab.graphql.vulnerabilities", Body: kitJSON(map[string]any{"data": noVulns})},
		{URL: groupURL, Body: kitJSON(kitGroupDetails())},
		kitList(groupURL+"/access_tokens?state=active", []gitlab.AccessToken{}),
	}
	responses = append(responses, kitPages(groupURL+"/projects?include_subgroups=true&with_shared=false", slices.Collect(slices.Chunk(projects, 100)))...)
	responses = append(responses, kitPages(groupURL+"/members/all", slices.Collect(slices.Chunk(members, 100)))...)
	return append(responses,
		kitList(groupURL+"/hooks", []gitlab.Webhook{}),
		kitList(groupURL+"/runners?type=group_type", []gitlab.Runner{}),
		kitList(groupURL+"/audit_events?created_after="+kitNow.AddDate(0, 0, -auditLogWindowDays).Format(time.RFC3339), []gitlab.AuditEvent{}))
}

// kitMaintainerResponses answer as GitLab does a token with the Maintainer
// role. The group's access token list answers 401, and its billable members
// list 400, as each does a role that cannot read it.
func kitMaintainerResponses() []collectortest.Response {
	responses := replaceResponse(kitResponses(kitMaintainerTenant(), kitBase), collectortest.Response{
		URL:    kitBase + "/groups/" + kitGroup + "/access_tokens?state=active&per_page=100&page=1",
		Status: http.StatusUnauthorized,
		Body:   `{"message":"401 Unauthorized"}`,
	})
	return replaceResponse(responses, collectortest.Response{
		URL:    kitBase + "/groups/" + kitGroup + "/billable_members?per_page=100&page=1",
		Status: http.StatusBadRequest,
		Body:   `{"message":"400 Bad request"}`,
	})
}
