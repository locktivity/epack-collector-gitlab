package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/locktivity/epack/componentsdk"
)

func TestNewClient_DefaultBaseURL(t *testing.T) {
	c := NewClient(http.DefaultClient, "", "test-token")
	if c.baseURL != "https://gitlab.com/api/v4" {
		t.Errorf("expected default base URL, got %s", c.baseURL)
	}
}

func TestNewClient_CustomBaseURL(t *testing.T) {
	c := NewClient(http.DefaultClient, "https://gitlab.example.com", "test-token")
	if c.baseURL != "https://gitlab.example.com/api/v4" {
		t.Errorf("expected custom base URL, got %s", c.baseURL)
	}
}

func TestNewClient_TrimsTrailingSlash(t *testing.T) {
	c := NewClient(http.DefaultClient, "https://gitlab.example.com/", "test-token")
	if c.baseURL != "https://gitlab.example.com/api/v4" {
		t.Errorf("expected trimmed base URL, got %s", c.baseURL)
	}
}

func TestHost(t *testing.T) {
	cases := []struct {
		baseURL string
		want    string
		wantErr bool
	}{
		{"", "gitlab.com", false},
		{"https://GitLab.Example.com:8443/", "gitlab.example.com", false},
		{"http://gitlab.internal/gitlab", "", true},
		{"http://localhost:8080/", "localhost", false},
		{"http://127.0.0.1:8080", "127.0.0.1", false},
		{"gitlab.example.com", "", true},
		{"ftp://gitlab.example.com", "", true},
		{"https://", "", true},
	}
	for _, tc := range cases {
		got, err := Host(tc.baseURL)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("Host(%q) = %q, %v; want %q, error %v", tc.baseURL, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestGetGroup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("PRIVATE-TOKEN") != "test-token" {
			t.Error("missing auth header")
		}
		if r.URL.Path != "/api/v4/groups/my-group" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"id":42,"name":"My Group","require_two_factor_authentication":true,"require_two_factor_authentication_from_ancestor":false}`))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, "test-token")
	group, err := c.GetGroup(context.Background(), "my-group")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if group.ID != 42 {
		t.Errorf("expected group ID 42, got %d", group.ID)
	}
	if group.RequireTwoFactorAuthentication == nil || !*group.RequireTwoFactorAuthentication {
		t.Error("expected 2FA required")
	}
	if group.RequireTwoFactorFromAncestor == nil || *group.RequireTwoFactorFromAncestor {
		t.Error("expected 2FA from an ancestor to read false")
	}
	if group.ShareWithGroupLock != nil {
		t.Error("a setting the response left out should read as unknown, not false")
	}
}

func TestListApprovalRules_ReadsReportType(t *testing.T) {
	c := answer(t, http.StatusOK, `[{"id":1,"name":"Coverage-Check","rule_type":"report_approver","report_type":"code_coverage","approvals_required":1},
		{"id":2,"name":"Reviewers","rule_type":"regular","report_type":null,"approvals_required":1}]`)
	rules, err := c.ListApprovalRules(context.Background(), 10)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 2 || rules[0].ReportType != "code_coverage" || rules[1].ReportType != "" {
		t.Errorf("rules = %+v, want report types code_coverage and none", rules)
	}
}

func TestListGroupRunners_AsksForGroupRunners(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("type"); got != "group_type" {
			t.Errorf("type = %q, want group_type", got)
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, "test-token")
	if _, err := c.ListGroupRunners(context.Background(), "my-group"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListProjects_Pagination(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if got := r.URL.Query().Get("page"); got != map[int]string{1: "1", 2: "2"}[page] {
			t.Errorf("request %d asked for page %q", page, got)
		}
		if page == 1 {
			w.Header().Set("X-Next-Page", "2")
			_ = json.NewEncoder(w).Encode([]Project{{ID: 1, Name: "project-1"}})
		} else {
			_ = json.NewEncoder(w).Encode([]Project{{ID: 2, Name: "project-2"}})
		}
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, "test-token")
	projects, err := c.ListProjects(context.Background(), "my-group")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(projects) != 2 {
		t.Errorf("expected 2 projects, got %d", len(projects))
	}
}

func TestListProjects_LinkHeaderFallback(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			w.Header().Set("Link", `<https://gitlab.com/api/v4/groups/my-group/projects?page=2&per_page=100>; rel="next"`)
			_ = json.NewEncoder(w).Encode([]Project{{ID: 1, Name: "project-1"}})
		} else {
			_ = json.NewEncoder(w).Encode([]Project{{ID: 2, Name: "project-2"}})
		}
	}))
	defer srv.Close()

	c := NewClient(srv.Client(), srv.URL, "test-token")
	projects, err := c.ListProjects(context.Background(), "my-group")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(projects) != 2 {
		t.Errorf("expected 2 projects via Link header fallback, got %d", len(projects))
	}
}

func TestParseLinkNextPage(t *testing.T) {
	tests := []struct {
		name   string
		header string
		want   int
		wantOK bool
	}{
		{"valid next", `<https://gitlab.com/api/v4/groups/1/projects?page=3&per_page=100>; rel="next"`, 3, true},
		{"with other rels", `<https://gitlab.com/api/v4/groups/1/projects?page=1>; rel="first", <https://gitlab.com/api/v4/groups/1/projects?page=2>; rel="next"`, 2, true},
		{"no next", `<https://gitlab.com/api/v4/groups/1/projects?page=1>; rel="first"`, 0, false},
		{"empty", "", 0, false},
		{"malformed url", `<://bad>; rel="next"`, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseLinkNextPage(tt.header)
			if ok != tt.wantOK || got != tt.want {
				t.Errorf("parseLinkNextPage(%q) = (%d, %v), want (%d, %v)", tt.header, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// answer serves one status and body for every request.
func answer(t *testing.T, status int, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.Client(), srv.URL, "test-token")
}

func TestGetGroup_PermissionDenied(t *testing.T) {
	c := answer(t, http.StatusForbidden, `{"error":"insufficient_scope","error_description":"The request requires higher privileges than provided by the access token.","scope":"api read_api","trace":"internal detail"}`)
	_, err := c.GetGroup(context.Background(), "my-group")

	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusForbidden {
		t.Fatalf("expected a 403 APIError, got %v", err)
	}
	if got := componentsdk.Classify(err); got != componentsdk.CodePermissionDenied {
		t.Errorf("code = %s, want permission_denied", got)
	}
	if got := componentsdk.VendorCodeOf(err); got != "insufficient_scope" {
		t.Errorf("vendor code = %q, want insufficient_scope", got)
	}
	if !strings.Contains(err.Error(), "requires higher privileges") || strings.Contains(err.Error(), "internal detail") {
		t.Errorf("error = %q, want GitLab's description and none of the rest of the body", err)
	}
}

func TestGetGroup_NotFound(t *testing.T) {
	c := answer(t, http.StatusNotFound, `{"message":"404 Group Not Found"}`)
	_, err := c.GetGroup(context.Background(), "nonexistent")
	if !GroupNotFound(err) {
		t.Fatalf("expected GroupNotFound, got %v", err)
	}
	if got := componentsdk.Classify(err); got != componentsdk.CodeInvalidResponse {
		t.Errorf("code = %s, want invalid_response", got)
	}
}

func TestMissingRouteIsNotLicensed(t *testing.T) {
	c := answer(t, http.StatusNotFound, `{"error":"404 Not Found"}`)
	_, err := c.ListGroupWebhooks(context.Background(), "my-group")
	if got := componentsdk.Classify(err); got != componentsdk.CodeNotLicensed {
		t.Errorf("code = %s, want not_licensed for a route the edition does not have", got)
	}

	c = answer(t, http.StatusNotFound, `{"message":"404 Project Not Found"}`)
	_, err = c.ListProjectWebhooks(context.Background(), 7)
	if got := componentsdk.Classify(err); got != componentsdk.CodeInvalidResponse {
		t.Errorf("code = %s, want invalid_response for a missing project", got)
	}
}

func TestListWithoutAnArrayIsInvalid(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"message":"ok"}`} {
		_, err := answer(t, http.StatusOK, body).ListGroupMembers(context.Background(), "my-group")
		if got := componentsdk.Classify(err); got != componentsdk.CodeInvalidResponse {
			t.Errorf("body %s: code = %s (%v), want invalid_response rather than an empty list", body, got, err)
		}
	}
}

func TestApprovalSettingsWithoutTheirFieldsAreInvalid(t *testing.T) {
	_, err := answer(t, http.StatusOK, `{}`).GetApprovalSettings(context.Background(), 7)
	if got := componentsdk.Classify(err); got != componentsdk.CodeInvalidResponse {
		t.Errorf("code = %s (%v), want invalid_response", got, err)
	}

	settings, err := answer(t, http.StatusOK, `{"approvals_before_merge":2,"reset_approvals_on_push":true,"merge_requests_disable_committers_approval":false}`).GetApprovalSettings(context.Background(), 7)
	if err != nil || settings.ApprovalsBeforeMerge != 2 || !settings.ResetApprovalsOnPush {
		t.Errorf("settings = %+v, %v", settings, err)
	}
}

func TestListGroupAccessTokens_AsksForActiveTokens(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Query().Get("state")
		_, _ = w.Write([]byte(`[{"id":42,"user_id":141,"scopes":["api"],"active":true,"revoked":false,"access_level":40,"created_at":"2026-01-20T22:11:48.151Z","last_used_at":null,"expires_at":"2027-01-31"}]`))
	}))
	t.Cleanup(srv.Close)
	tokens, err := NewClient(srv.Client(), srv.URL, "test-token").ListGroupAccessTokens(context.Background(), "my-group")
	if err != nil {
		t.Fatal(err)
	}
	if query != "active" {
		t.Errorf("state = %q, want active", query)
	}
	if len(tokens) != 1 || tokens[0].ExpiresAt == nil || tokens[0].ExpiresAt.Format("2006-01-02") != "2027-01-31" || tokens[0].LastUsedAt != nil {
		t.Errorf("tokens = %+v, want one token that expires on 2027-01-31 and was never used", tokens)
	}
}

// GitLab answers a role that cannot list access tokens with 401. The
// sign-in already worked, so the error is permission_denied.
func TestAccessTokenList401IsPermissionDenied(t *testing.T) {
	c := answer(t, http.StatusUnauthorized, `{"message":"401 Unauthorized"}`)
	_, err := c.ListProjectAccessTokens(context.Background(), 7)
	if got := componentsdk.Classify(err); got != componentsdk.CodePermissionDenied {
		t.Errorf("code = %s, want permission_denied", got)
	}
	_, err = c.ListProjectDeployKeys(context.Background(), 7)
	if got := componentsdk.Classify(err); got != componentsdk.CodeAuthFailed {
		t.Errorf("deploy keys code = %s, want auth_failed", got)
	}
}

func TestListBillableMembers(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_, _ = w.Write([]byte(`[{"id":1,"username":"raymond_smith","last_activity_on":"2021-01-27","membership_type":"group_member"},{"id":2,"username":"john_doe","last_activity_on":null}]`))
	}))
	t.Cleanup(srv.Close)
	members, err := NewClient(srv.Client(), srv.URL, "test-token").ListBillableMembers(context.Background(), "my-group")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/api/v4/groups/my-group/billable_members" {
		t.Errorf("path = %s, want the group's billable members", path)
	}
	if len(members) != 2 || members[0].LastActivityOn == nil || members[0].LastActivityOn.Format("2006-01-02") != "2021-01-27" || members[1].LastActivityOn != nil {
		t.Errorf("members = %+v, want one active on 2021-01-27 and one with no activity", members)
	}
}

// GitLab answers a role that cannot list billable members with 400. The
// collector does not call it for a subgroup, its other 400.
func TestBillableMembers400IsPermissionDenied(t *testing.T) {
	_, err := answer(t, http.StatusBadRequest, `{"message":"400 Bad request"}`).ListBillableMembers(context.Background(), "my-group")
	if got := componentsdk.Classify(err); got != componentsdk.CodePermissionDenied {
		t.Errorf("code = %s, want permission_denied", got)
	}
}

// A denial names a scope only when GitLab answers insufficient_scope, and a
// role only when it does not.
func TestNamesPermission(t *testing.T) {
	const scopeDenied = `{"error":"insufficient_scope","error_description":"The request requires higher privileges than provided by the access token."}`
	const roleDenied = `{"message":"403 Forbidden"}`
	cases := []struct {
		op, body string
		want     bool
	}{
		{opGroupMembers, scopeDenied, true},
		{opGroupMembers, roleDenied, false},
		{opGroupHooks, scopeDenied, false},
		{opGroupHooks, roleDenied, true},
		{"", roleDenied, false},
	}
	for _, tc := range cases {
		ctx := context.Background()
		if tc.op != "" {
			ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: tc.op, Permission: permissions[tc.op]})
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://gitlab.com/api/v4/groups/7", nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := NamesPermission(&http.Response{StatusCode: http.StatusForbidden, Request: req}, []byte(tc.body)); got != tc.want {
			t.Errorf("%q with %s: NamesPermission = %v, want %v", tc.op, tc.body, got, tc.want)
		}
	}
}

// Every operation the client names declares the scope or role it needs.
func TestEveryOperationDeclaresItsPermission(t *testing.T) {
	for _, op := range []string{
		opGroup, opProjects, opProtectedBranches, opApprovalSettings, opApprovalRules, opGroupMembers, opBillableMembers, opMemberRoles,
		opGroupHooks, opProjectHooks, opDeployKeys, opGroupRunners, opGroupAuditEvents, opGroupAccessTokens,
		opProjectAccessTokens, opSecurityScanners, opVulnerabilities,
	} {
		if p := permissions[op]; p == "" || strings.Contains(p, " ") {
			t.Errorf("%s declares %q, want a scope or a role identifier", op, p)
		}
	}
}

// graphqlServer answers each GraphQL request with the next of bodies, and
// records the requests' variables.
func graphqlServer(t *testing.T, bodies ...string) (*Client, *[]map[string]any) {
	t.Helper()
	var seen []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/graphql" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("request %s %s with Authorization %q, want a POST to /api/graphql with the token", r.Method, r.URL.Path, r.Header.Get("Authorization"))
		}
		var req struct {
			Variables map[string]any `json:"variables"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		seen = append(seen, req.Variables)
		if len(seen) > len(bodies) {
			t.Fatalf("request %d, want %d", len(seen), len(bodies))
		}
		_, _ = w.Write([]byte(bodies[len(seen)-1]))
	}))
	t.Cleanup(srv.Close)
	return NewClient(srv.Client(), srv.URL, "test-token"), &seen
}

func TestListGroupVulnerabilities_ReadsEveryPage(t *testing.T) {
	c, seen := graphqlServer(t,
		`{"data":{"group":{"vulnerabilitySeveritiesCount":{"critical":1},"vulnerabilities":{"nodes":[{"reportType":"SAST","severity":"CRITICAL","detectedAt":"2026-08-01T09:00:00Z","project":{"id":"gid://gitlab/Project/10"}}],"pageInfo":{"hasNextPage":true,"endCursor":"c1"}}}}}`,
		`{"data":{"group":{"vulnerabilitySeveritiesCount":{"critical":1},"vulnerabilities":{"nodes":[{"reportType":"DEPENDENCY_SCANNING","severity":"LOW","detectedAt":"2026-09-01T09:00:00Z","project":{"id":"gid://gitlab/Project/11"}}],"pageInfo":{"hasNextPage":false,"endCursor":"c2"}}}}}`,
	)
	vulns, err := c.ListGroupVulnerabilities(context.Background(), "acme/platform")
	if err != nil {
		t.Fatal(err)
	}
	if !vulns.Readable || len(vulns.Items) != 2 || vulns.Items[0].ProjectID != 10 || vulns.Items[1].Severity != "LOW" {
		t.Errorf("vulnerabilities = %+v", vulns)
	}
	if len(*seen) != 2 || (*seen)[0]["after"] != nil || (*seen)[1]["after"] != "c1" || (*seen)[0]["group"] != "acme/platform" {
		t.Errorf("variables = %v, want the group's full path and the first page's cursor on the second", *seen)
	}
}

// A token that cannot read the vulnerability report gets a null count, and
// sometimes an error on it. The empty list is then no answer.
func TestListGroupVulnerabilities_UnreadableReport(t *testing.T) {
	for _, body := range []string{
		`{"data":{"group":{"vulnerabilitySeveritiesCount":null,"vulnerabilities":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}`,
		`{"data":{"group":{"vulnerabilitySeveritiesCount":null,"vulnerabilities":{"nodes":[],"pageInfo":{"hasNextPage":false}}}},"errors":[{"message":"The resource that you are attempting to access does not exist or you don't have permission to perform this action","path":["group","vulnerabilitySeveritiesCount"]}]}`,
	} {
		c, _ := graphqlServer(t, body)
		vulns, err := c.ListGroupVulnerabilities(context.Background(), "acme")
		if err != nil || vulns.Readable || len(vulns.Items) != 0 {
			t.Errorf("body %s: vulnerabilities = %+v, %v; want an unreadable report", body, vulns, err)
		}
	}
}

func TestListGroupVulnerabilities_InvalidAnswers(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"data":{"group":null}}`,
		`{"data":{"group":{"vulnerabilitySeveritiesCount":{"critical":0}}}}`,
		`{"data":{"group":{"vulnerabilitySeveritiesCount":{"critical":0},"vulnerabilities":{"nodes":[{"reportType":"SAST","severity":"HIGH","project":{"id":"gid://gitlab/Project/1"}}],"pageInfo":{"hasNextPage":false}}}}}`,
		`{"data":{"group":{"vulnerabilitySeveritiesCount":{"critical":0},"vulnerabilities":{"nodes":[],"pageInfo":{"hasNextPage":true}}}}}`,
		`{"data":null,"errors":[{"message":"Query has complexity of 300, which exceeds max complexity of 250"}]}`,
	} {
		c, _ := graphqlServer(t, body)
		_, err := c.ListGroupVulnerabilities(context.Background(), "acme")
		if got := componentsdk.Classify(err); got != componentsdk.CodeInvalidResponse {
			t.Errorf("body %s: code = %s (%v), want invalid_response", body, got, err)
		}
	}
}

func TestListSecurityScanners(t *testing.T) {
	c, seen := graphqlServer(t, `{"data":{"projects":{"nodes":[
		{"id":"gid://gitlab/Project/10","securityScanners":{"available":["SAST"],"pipelineRun":["SAST"]}},
		{"id":"gid://gitlab/Project/11","securityScanners":null}
	],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}`)
	scanners, err := c.ListSecurityScanners(context.Background(), []int{10, 11, 12})
	if err != nil {
		t.Fatal(err)
	}
	if len(scanners) != 1 || len(scanners[10].PipelineRun) != 1 {
		t.Errorf("scanners = %+v, want only project 10's", scanners)
	}
	ids, _ := (*seen)[0]["ids"].([]any)
	if len(ids) != 3 || ids[0] != "gid://gitlab/Project/10" {
		t.Errorf("ids = %v, want the three projects' global IDs", ids)
	}

	c, _ = graphqlServer(t, `{"data":{"projects":{"nodes":[{"id":"gid://gitlab/Group/10","securityScanners":null}],"pageInfo":{"hasNextPage":false}}}}`)
	if _, err := c.ListSecurityScanners(context.Background(), []int{10}); componentsdk.Classify(err) != componentsdk.CodeInvalidResponse {
		t.Errorf("a node that is not a project: %v, want invalid_response", err)
	}
}
