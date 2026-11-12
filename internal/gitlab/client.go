package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

const (
	// DefaultBaseURL is the instance the collector reads when base_url is
	// not set.
	DefaultBaseURL = "https://gitlab.com"
	apiPrefix      = "/api/v4"
	graphqlPath    = "/api/graphql"
	maxPerPage     = 100
	maxErrorBody   = 64 << 10
)

// Client is a GitLab REST and GraphQL API client. Each method is one named
// operation in the collector result.
type Client struct {
	baseURL    string
	graphqlURL string
	token      string
	httpClient *http.Client
}

// The operations the collector names its calls with.
const (
	opGroup               = "gitlab.groups.get"
	opProjects            = "gitlab.projects.list"
	opProtectedBranches   = "gitlab.protected_branches.list"
	opApprovalSettings    = "gitlab.approval_settings.get"
	opApprovalRules       = "gitlab.approval_rules.list"
	opGroupMembers        = "gitlab.group_members.list"
	opBillableMembers     = "gitlab.billable_members.list"
	opMemberRoles         = "gitlab.member_roles.list"
	opGroupHooks          = "gitlab.group_hooks.list"
	opProjectHooks        = "gitlab.project_hooks.list"
	opDeployKeys          = "gitlab.deploy_keys.list"
	opGroupRunners        = "gitlab.group_runners.list"
	opGroupAuditEvents    = "gitlab.group_audit_events.list"
	opGroupAccessTokens   = "gitlab.group_access_tokens.list"
	opProjectAccessTokens = "gitlab.project_access_tokens.list"
)

// scopeReadAPI is the token scope every call needs. GitLab's docs give no
// role for a call whose permission is this scope.
const scopeReadAPI = "read_api"

// permissions names the token scope or the GitLab role each operation needs,
// as GitLab's API docs give it. The collector result lists it with the
// operation, and a gap from the call's denial names it.
var permissions = map[string]string{
	opGroup:               scopeReadAPI,
	opProjects:            scopeReadAPI,
	opProtectedBranches:   scopeReadAPI,
	opApprovalSettings:    scopeReadAPI,
	opApprovalRules:       scopeReadAPI,
	opGroupMembers:        scopeReadAPI,
	opBillableMembers:     "Owner",
	opMemberRoles:         "Owner",
	opGroupHooks:          "Owner",
	opProjectHooks:        "Maintainer",
	opDeployKeys:          "Maintainer",
	opGroupRunners:        "Owner",
	opGroupAuditEvents:    "Owner",
	opGroupAccessTokens:   "Owner",
	opProjectAccessTokens: "Maintainer",
	opSecurityScanners:    scopeReadAPI,
	opVulnerabilities:     "Developer",
}

// roleDeniedStatus gives the status an operation gets when the token lacks
// the role it needs, where that status is not 403. The access token lists
// answer 401, and the sign-in already showed that the token works. The
// billable members list answers 400, and the collector does not call it for
// a subgroup, its only other 400.
var roleDeniedStatus = map[string]int{
	opGroupAccessTokens:   http.StatusUnauthorized,
	opProjectAccessTokens: http.StatusUnauthorized,
	opBillableMembers:     http.StatusBadRequest,
}

// ClassifyResponse reads the status in roleDeniedStatus as
// permission_denied, for componentsdk.HTTPOptions.ClassifyResponse. The
// collector result then counts the call's error as permission_denied, and
// its gap names the operation's permission.
func ClassifyResponse(resp *http.Response, _ []byte) (componentsdk.Code, bool) {
	if op, ok := operationOf(resp); ok && roleDenied(op.Name, resp.StatusCode) {
		return componentsdk.CodePermissionDenied, true
	}
	return "", false
}

// NamesPermission reports whether a denial shows that the token lacks the
// call's permission, for componentsdk.HTTPOptions.NamesPermission. GitLab
// answers a token without a scope the call needs with insufficient_scope.
// So a scope is named only on that answer, and a role only on any other.
func NamesPermission(resp *http.Response, body []byte) bool {
	op, ok := operationOf(resp)
	if !ok {
		return false
	}
	var payload struct {
		Error any `json:"error"`
	}
	_ = json.Unmarshal(body, &payload)
	code, _ := payload.Error.(string)
	return (code == "insufficient_scope") == (op.Permission == scopeReadAPI)
}

func operationOf(resp *http.Response) (componentsdk.Operation, bool) {
	if resp == nil || resp.Request == nil {
		return componentsdk.Operation{}, false
	}
	return componentsdk.OperationOf(resp.Request.Context())
}

func roleDenied(op string, status int) bool {
	want, ok := roleDeniedStatus[op]
	return ok && status == want
}

// NewClient returns a client for the instance at baseURL, or GitLab.com when
// baseURL is empty. It sends token in the PRIVATE-TOKEN header through
// httpClient, which retries safe requests and keeps the token on the hosts it
// was built for and off plain http.
func NewClient(httpClient *http.Client, baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	root := strings.TrimRight(baseURL, "/")
	return &Client{
		baseURL:    root + apiPrefix,
		graphqlURL: root + graphqlPath,
		token:      token,
		httpClient: httpClient,
	}
}

// Host returns the host of the instance at baseURL, or of GitLab.com when
// baseURL is empty. It is the only host that may receive the token. The SDK's
// client never sends the token over plain http except to a loopback host, so
// any other http URL is refused here as configuration.
func Host(baseURL string) (string, error) {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	u, err := url.Parse(baseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" {
		return "", fmt.Errorf("%q is not an http or https URL, such as https://gitlab.example.com", baseURL)
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "http" && !loopback(host) {
		return "", fmt.Errorf("%q uses plain http, which would send the token in clear text; use https", baseURL)
	}
	return host, nil
}

func loopback(host string) bool {
	ip := net.ParseIP(host)
	return host == "localhost" || (ip != nil && ip.IsLoopback())
}

// GetGroup fetches group details. The collector signs in with this call.
func (c *Client) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	var group Group
	if _, err := c.get(ctx, opGroup, "/groups/"+url.PathEscape(groupID), nil, &group); err != nil {
		return nil, err
	}
	return &group, nil
}

// ListProjects lists all projects in a group, including subgroups.
func (c *Client) ListProjects(ctx context.Context, groupID string) ([]Project, error) {
	params := url.Values{
		"include_subgroups": {"true"},
		"with_shared":       {"false"},
	}
	return listAll[Project](ctx, c, opProjects, "/groups/"+url.PathEscape(groupID)+"/projects", params)
}

// ListProtectedBranches lists protected branches for a project.
func (c *Client) ListProtectedBranches(ctx context.Context, projectID int) ([]ProtectedBranch, error) {
	return listAll[ProtectedBranch](ctx, c, opProtectedBranches, fmt.Sprintf("/projects/%d/protected_branches", projectID), url.Values{})
}

// GetApprovalSettings fetches project-level approval configuration
// (Premium+). A response without the settings the collector reads is an
// invalid response.
func (c *Client) GetApprovalSettings(ctx context.Context, projectID int) (*ApprovalSettings, error) {
	const op = opApprovalSettings
	var wire struct {
		ApprovalsBeforeMerge                   *int  `json:"approvals_before_merge"`
		ResetApprovalsOnPush                   *bool `json:"reset_approvals_on_push"`
		DisableOverridingApproversPerMR        bool  `json:"disable_overriding_approvers_per_merge_request"`
		MergeRequestsAuthorApproval            bool  `json:"merge_requests_author_approval"`
		MergeRequestsDisableCommittersApproval *bool `json:"merge_requests_disable_committers_approval"`
	}
	resp, err := c.get(ctx, op, fmt.Sprintf("/projects/%d/approvals", projectID), nil, &wire)
	if err != nil {
		return nil, err
	}
	if wire.ApprovalsBeforeMerge == nil || wire.ResetApprovalsOnPush == nil || wire.MergeRequestsDisableCommittersApproval == nil {
		return nil, componentsdk.ResponseError(resp, invalidResponse(op, "lacks approvals_before_merge, reset_approvals_on_push, or merge_requests_disable_committers_approval"))
	}
	return &ApprovalSettings{
		ApprovalsBeforeMerge:                   *wire.ApprovalsBeforeMerge,
		ResetApprovalsOnPush:                   *wire.ResetApprovalsOnPush,
		DisableOverridingApproversPerMR:        wire.DisableOverridingApproversPerMR,
		MergeRequestsAuthorApproval:            wire.MergeRequestsAuthorApproval,
		MergeRequestsDisableCommittersApproval: *wire.MergeRequestsDisableCommittersApproval,
	}, nil
}

// ListApprovalRules lists project-level approval rules (Premium+).
func (c *Client) ListApprovalRules(ctx context.Context, projectID int) ([]ApprovalRule, error) {
	return listAll[ApprovalRule](ctx, c, opApprovalRules, fmt.Sprintf("/projects/%d/approval_rules", projectID), url.Values{})
}

// ListGroupMembers lists all members of a group (including inherited).
func (c *Client) ListGroupMembers(ctx context.Context, groupID string) ([]Member, error) {
	return listAll[Member](ctx, c, opGroupMembers, "/groups/"+url.PathEscape(groupID)+"/members/all", url.Values{})
}

// ListBillableMembers lists the billable members of a top-level group,
// with the date of each one's last activity. Only the group's Owners can
// list them. GitLab answers 400 for a subgroup or for another role.
func (c *Client) ListBillableMembers(ctx context.Context, groupID string) ([]BillableMember, error) {
	return listAll[BillableMember](ctx, c, opBillableMembers, "/groups/"+url.PathEscape(groupID)+"/billable_members", url.Values{})
}

// ListMemberRoles lists a top-level group's custom roles. Only the group's
// Owners can list them, on GitLab.com with Ultimate. A GitLab Self-Managed
// instance lists its custom roles only to an administrator, instance-wide.
func (c *Client) ListMemberRoles(ctx context.Context, groupID string) ([]MemberRole, error) {
	return listAll[MemberRole](ctx, c, opMemberRoles, "/groups/"+url.PathEscape(groupID)+"/member_roles", url.Values{})
}

// ListGroupWebhooks lists webhooks for a group (Premium+).
func (c *Client) ListGroupWebhooks(ctx context.Context, groupID string) ([]Webhook, error) {
	return listAll[Webhook](ctx, c, opGroupHooks, "/groups/"+url.PathEscape(groupID)+"/hooks", url.Values{})
}

// ListProjectWebhooks lists webhooks for a project.
func (c *Client) ListProjectWebhooks(ctx context.Context, projectID int) ([]Webhook, error) {
	return listAll[Webhook](ctx, c, opProjectHooks, fmt.Sprintf("/projects/%d/hooks", projectID), url.Values{})
}

// ListProjectDeployKeys lists deploy keys for a project.
func (c *Client) ListProjectDeployKeys(ctx context.Context, projectID int) ([]DeployKey, error) {
	return listAll[DeployKey](ctx, c, opDeployKeys, fmt.Sprintf("/projects/%d/deploy_keys", projectID), url.Values{})
}

// ListGroupAccessTokens lists the group's active access tokens. Only the
// group's Owners can list them. On versions without the state filter the
// list has inactive tokens too, and the collector leaves them out.
func (c *Client) ListGroupAccessTokens(ctx context.Context, groupID string) ([]AccessToken, error) {
	params := url.Values{"state": {"active"}}
	return listAll[AccessToken](ctx, c, opGroupAccessTokens, "/groups/"+url.PathEscape(groupID)+"/access_tokens", params)
}

// ListProjectAccessTokens lists a project's active access tokens. The
// project's Maintainers and Owners can list them.
func (c *Client) ListProjectAccessTokens(ctx context.Context, projectID int) ([]AccessToken, error) {
	params := url.Values{"state": {"active"}}
	return listAll[AccessToken](ctx, c, opProjectAccessTokens, fmt.Sprintf("/projects/%d/access_tokens", projectID), params)
}

// ListGroupRunners lists the group runners of a group and its ancestor
// groups. Without the type filter, the list also has instance runners.
func (c *Client) ListGroupRunners(ctx context.Context, groupID string) ([]Runner, error) {
	params := url.Values{"type": {"group_type"}}
	return listAll[Runner](ctx, c, opGroupRunners, "/groups/"+url.PathEscape(groupID)+"/runners", params)
}

// ListGroupAuditEvents lists audit events for a group (Premium+).
func (c *Client) ListGroupAuditEvents(ctx context.Context, groupID string, since time.Time) ([]AuditEvent, error) {
	params := url.Values{"created_after": {since.UTC().Format(time.RFC3339)}}
	return listAll[AuditEvent](ctx, c, opGroupAuditEvents, "/groups/"+url.PathEscape(groupID)+"/audit_events", params)
}

// get sends one named GET and decodes a 200 response into dest. Any other
// status returns an *APIError. The SDK's transport retries the call when
// that is safe. It returns the response for componentsdk.ResponseError and
// the paging headers. The response's body is closed.
func (c *Client) get(ctx context.Context, op, path string, params url.Values, dest any) (*http.Response, error) {
	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: op, Permission: permissions[op]})
	u := c.baseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if err := decode(op, req, resp, dest); err != nil {
		return nil, err
	}
	return resp, nil
}

// decode reads a 200 response into dest. Any other status returns an
// *APIError.
func decode(op string, req *http.Request, resp *http.Response, dest any) error {
	// ResponseError adds the call to each error about the response, so the
	// gap recorded from the error includes the call.
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		apiErr := newAPIError(req, resp, body)
		apiErr.roleDenied = roleDenied(op, resp.StatusCode)
		return componentsdk.ResponseError(resp, apiErr)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return componentsdk.ResponseError(resp, fmt.Errorf("reading the response to %s: %w", op, err))
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return componentsdk.ResponseError(resp, fmt.Errorf("decoding the response to %s: %w", op, err))
	}
	return nil
}

// listAll reads every page of a list endpoint. A page that is not a JSON
// array fails the read, so a missing list never reads as an empty one.
func listAll[T any](ctx context.Context, c *Client, op, path string, params url.Values) ([]T, error) {
	params.Set("per_page", strconv.Itoa(maxPerPage))
	items := []T{}
	page := 1
	for {
		params.Set("page", strconv.Itoa(page))
		var batch *[]T
		resp, err := c.get(ctx, op, path, params, &batch)
		if err != nil {
			return nil, err
		}
		if batch == nil {
			return nil, componentsdk.ResponseError(resp, invalidResponse(op, "has no list"))
		}
		items = append(items, *batch...)
		next, ok := nextPageFromHeaders(resp.Header, page)
		if !ok {
			return items, nil
		}
		page = next
	}
}

// invalidResponse reports a 200 response that lacks what the collector
// reads from it.
func invalidResponse(op, problem string) error {
	return componentsdk.CodeError(componentsdk.CodeInvalidResponse, fmt.Errorf("the response to %s %s", op, problem))
}

// nextPageFromHeaders extracts the next page number from response headers.
// It checks X-Next-Page first, then falls back to the Link header's rel="next".
func nextPageFromHeaders(h http.Header, currentPage int) (int, bool) {
	if xnp := h.Get("X-Next-Page"); xnp != "" {
		n, err := strconv.Atoi(xnp)
		if err == nil && n > currentPage {
			return n, true
		}
		return 0, false
	}

	for _, link := range h.Values("Link") {
		if n, ok := parseLinkNextPage(link); ok && n > currentPage {
			return n, true
		}
	}
	return 0, false
}

// parseLinkNextPage extracts the page number from a Link header value
// containing rel="next". Only the page query parameter is used; the full
// URL is not followed, preserving the client's origin restrictions.
func parseLinkNextPage(header string) (int, bool) {
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start < 0 || end <= start {
			continue
		}
		linkURL, err := url.Parse(part[start+1 : end])
		if err != nil {
			continue
		}
		pageStr := linkURL.Query().Get("page")
		if pageStr == "" {
			continue
		}
		n, err := strconv.Atoi(pageStr)
		if err != nil {
			continue
		}
		return n, true
	}
	return 0, false
}

// APIError is a GitLab response with a status other than 200. It carries the
// status, headers, and GitLab's own error text for componentsdk.Classify,
// and never the raw body.
type APIError struct {
	StatusCode int
	Method     string
	// Path is the request's path, without its query.
	Path   string
	Header http.Header
	// Message is GitLab's error text, such as "404 Group Not Found".
	Message string
	// Code is GitLab's OAuth error code, such as insufficient_scope.
	Code string

	routeMissing bool
	roleDenied   bool
}

var oauthCode = regexp.MustCompile(`^[a-z_]+$`)

const maxMessage = 200

func newAPIError(req *http.Request, resp *http.Response, body []byte) *APIError {
	e := &APIError{StatusCode: resp.StatusCode, Method: req.Method, Path: req.URL.Path, Header: resp.Header}
	var payload struct {
		Message          any    `json:"message"`
		Error            any    `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if json.Unmarshal(body, &payload) != nil {
		return e
	}
	message, _ := payload.Message.(string)
	errText, _ := payload.Error.(string)
	switch {
	case oauthCode.MatchString(errText):
		e.Code = errText
		message = payload.ErrorDescription
	case message == "":
		message = errText
	}
	// GitLab answers a route it does not have with {"error":"404 Not Found"},
	// and a missing resource with {"message":"404 ... Not Found"}.
	e.routeMissing = resp.StatusCode == http.StatusNotFound && errText == "404 Not Found"
	if len(message) > maxMessage {
		message = message[:maxMessage] + "..."
	}
	e.Message = message
	return e
}

func (e *APIError) Error() string {
	text := fmt.Sprintf("GitLab API %s %s returned %d", e.Method, e.Path, e.StatusCode)
	switch {
	case e.Code != "" && e.Message != "":
		text += ": " + e.Code + ": " + e.Message
	case e.Code != "":
		text += ": " + e.Code
	case e.Message != "":
		text += ": " + e.Message
	}
	return text
}

func (e *APIError) HTTPStatus() int         { return e.StatusCode }
func (e *APIError) HTTPHeader() http.Header { return e.Header }
func (e *APIError) VendorCode() string      { return e.Code }

// CollectionCode reads a 404 for a route the instance does not have as
// not_licensed: the edition or version lacks the feature, as GitLab Free
// lacks group webhooks, group audit events, and merge request approval
// settings. It reads the status in roleDeniedStatus as permission_denied.
func (e *APIError) CollectionCode() componentsdk.Code {
	switch {
	case e.routeMissing:
		return componentsdk.CodeNotLicensed
	case e.roleDenied:
		return componentsdk.CodePermissionDenied
	}
	return ""
}

// StatusOf returns the HTTP status of the GitLab response that caused err,
// or 0 when no response did.
func StatusOf(err error) int {
	var e *APIError
	if errors.As(err, &e) {
		return e.StatusCode
	}
	return 0
}

// GroupNotFound reports whether err is GitLab's answer for a group that does
// not exist or that the token cannot see.
func GroupNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.StatusCode == http.StatusNotFound && e.Message == "404 Group Not Found"
}
