package gitlab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultBaseURL = "https://gitlab.com"
	apiPrefix      = "/api/v4"
	requestTimeout = 30 * time.Second
	maxAttempts    = 5
	maxPerPage     = 100
)

var retryableStatuses = map[int]bool{
	http.StatusTooManyRequests:     true,
	http.StatusInternalServerError: true,
	http.StatusBadGateway:          true,
	http.StatusServiceUnavailable:  true,
	http.StatusGatewayTimeout:      true,
}

var (
	ErrUnauthorized       = fmt.Errorf("unauthorized")
	ErrPermissionDenied   = fmt.Errorf("permission denied")
	ErrNotFound           = fmt.Errorf("not found")
	ErrFeatureUnavailable = fmt.Errorf("feature unavailable")
)

type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("gitlab API error: status %d: %s", e.StatusCode, e.Body)
}

func (e *APIError) Unwrap() error {
	switch e.StatusCode {
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrPermissionDenied
	case http.StatusNotFound:
		return ErrNotFound
	}
	return nil
}

// Client is a GitLab REST API client.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient creates a new GitLab API client.
func NewClient(baseURL, token string) *Client {
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	origin, _ := url.Parse(baseURL)

	return &Client{
		baseURL: baseURL + apiPrefix,
		token:   token,
		httpClient: &http.Client{
			Timeout: requestTimeout,
			CheckRedirect: sameOriginRedirect(origin),
		},
	}
}

// sameOriginRedirect returns a CheckRedirect function that only follows
// redirects to the same scheme+host as the original request. This prevents
// the PRIVATE-TOKEN header from leaking to a different server.
func sameOriginRedirect(origin *url.URL) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("too many redirects")
		}
		if req.URL.Scheme == "http" && origin.Scheme == "https" {
			return fmt.Errorf("refusing HTTPS-to-HTTP downgrade redirect to %s", req.URL.Host)
		}
		if !strings.EqualFold(req.URL.Host, origin.Host) {
			return fmt.Errorf("refusing cross-origin redirect from %s to %s", origin.Host, req.URL.Host)
		}
		return nil
	}
}

// GetGroup fetches group details.
func (c *Client) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	path := fmt.Sprintf("/groups/%s", url.PathEscape(groupID))
	var group Group
	if err := c.get(ctx, path, nil, &group); err != nil {
		return nil, err
	}
	return &group, nil
}

// ListProjects lists all projects in a group, including subgroups.
func (c *Client) ListProjects(ctx context.Context, groupID string) ([]Project, error) {
	path := fmt.Sprintf("/groups/%s/projects", url.PathEscape(groupID))
	params := url.Values{
		"include_subgroups": {"true"},
		"with_shared":       {"false"},
		"per_page":          {strconv.Itoa(maxPerPage)},
	}

	var all []Project
	return all, c.paginate(ctx, path, params, &all)
}

// ListProtectedBranches lists protected branches for a project.
func (c *Client) ListProtectedBranches(ctx context.Context, projectID int) ([]ProtectedBranch, error) {
	path := fmt.Sprintf("/projects/%d/protected_branches", projectID)
	params := url.Values{"per_page": {strconv.Itoa(maxPerPage)}}

	var all []ProtectedBranch
	return all, c.paginate(ctx, path, params, &all)
}

// GetApprovalSettings fetches project-level approval configuration.
func (c *Client) GetApprovalSettings(ctx context.Context, projectID int) (*ApprovalSettings, error) {
	path := fmt.Sprintf("/projects/%d/approvals", projectID)
	var settings ApprovalSettings
	if err := c.get(ctx, path, nil, &settings); err != nil {
		return nil, err
	}
	return &settings, nil
}

// ListApprovalRules lists project-level approval rules (Premium+).
func (c *Client) ListApprovalRules(ctx context.Context, projectID int) ([]ApprovalRule, error) {
	path := fmt.Sprintf("/projects/%d/approval_rules", projectID)
	params := url.Values{"per_page": {strconv.Itoa(maxPerPage)}}

	var all []ApprovalRule
	return all, c.paginate(ctx, path, params, &all)
}

// ListGroupMembers lists all members of a group (including inherited).
func (c *Client) ListGroupMembers(ctx context.Context, groupID string) ([]Member, error) {
	path := fmt.Sprintf("/groups/%s/members/all", url.PathEscape(groupID))
	params := url.Values{"per_page": {strconv.Itoa(maxPerPage)}}

	var all []Member
	return all, c.paginate(ctx, path, params, &all)
}

// ListGroupWebhooks lists webhooks for a group (Premium+).
func (c *Client) ListGroupWebhooks(ctx context.Context, groupID string) ([]Webhook, error) {
	path := fmt.Sprintf("/groups/%s/hooks", url.PathEscape(groupID))
	params := url.Values{"per_page": {strconv.Itoa(maxPerPage)}}

	var all []Webhook
	return all, c.paginate(ctx, path, params, &all)
}

// ListProjectWebhooks lists webhooks for a project.
func (c *Client) ListProjectWebhooks(ctx context.Context, projectID int) ([]Webhook, error) {
	path := fmt.Sprintf("/projects/%d/hooks", projectID)
	params := url.Values{"per_page": {strconv.Itoa(maxPerPage)}}

	var all []Webhook
	return all, c.paginate(ctx, path, params, &all)
}

// ListProjectDeployKeys lists deploy keys for a project.
func (c *Client) ListProjectDeployKeys(ctx context.Context, projectID int) ([]DeployKey, error) {
	path := fmt.Sprintf("/projects/%d/deploy_keys", projectID)
	params := url.Values{"per_page": {strconv.Itoa(maxPerPage)}}

	var all []DeployKey
	return all, c.paginate(ctx, path, params, &all)
}

// ListGroupRunners lists runners for a group.
func (c *Client) ListGroupRunners(ctx context.Context, groupID string) ([]Runner, error) {
	path := fmt.Sprintf("/groups/%s/runners", url.PathEscape(groupID))
	params := url.Values{"per_page": {strconv.Itoa(maxPerPage)}}

	var all []Runner
	return all, c.paginate(ctx, path, params, &all)
}

// ListGroupAuditEvents lists audit events for a group (Premium+).
func (c *Client) ListGroupAuditEvents(ctx context.Context, groupID string, since time.Time) ([]AuditEvent, error) {
	path := fmt.Sprintf("/groups/%s/audit_events", url.PathEscape(groupID))
	params := url.Values{
		"per_page":      {strconv.Itoa(maxPerPage)},
		"created_after": {since.Format(time.RFC3339)},
	}

	var all []AuditEvent
	return all, c.paginate(ctx, path, params, &all)
}

// ListVulnerabilityFindings lists vulnerability findings for a project (Ultimate).
func (c *Client) ListVulnerabilityFindings(ctx context.Context, projectID int) ([]VulnerabilityFinding, error) {
	path := fmt.Sprintf("/projects/%d/vulnerability_findings", projectID)
	params := url.Values{
		"per_page": {strconv.Itoa(maxPerPage)},
		"scope":    {"all"},
	}

	var all []VulnerabilityFinding
	return all, c.paginate(ctx, path, params, &all)
}

// get performs a single GET request with retry.
func (c *Client) get(ctx context.Context, path string, params url.Values, target any) error {
	var lastErr error
	for attempt := range maxAttempts {
		resp, err := c.doRequest(ctx, path, params)
		if err != nil {
			return err
		}

		if resp.StatusCode == http.StatusOK {
			defer func() { _ = resp.Body.Close() }()
			return json.NewDecoder(resp.Body).Decode(target)
		}

		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		apiErr := &APIError{StatusCode: resp.StatusCode, Body: string(body)}
		if !retryableStatuses[resp.StatusCode] {
			return apiErr
		}

		lastErr = apiErr
		if err := sleep(ctx, retryDelay(resp, attempt)); err != nil {
			return err
		}
	}
	return fmt.Errorf("max retries exceeded: %w", lastErr)
}

// paginate walks through paginated results using offset pagination.
// It checks X-Next-Page first, then falls back to parsing Link rel="next".
func (c *Client) paginate(ctx context.Context, path string, params url.Values, target any) error {
	page := 1
	for {
		params.Set("page", strconv.Itoa(page))

		var pageData json.RawMessage
		resp, err := c.getWithResponse(ctx, path, params, &pageData)
		if err != nil {
			return err
		}

		if err := appendJSON(target, pageData); err != nil {
			return fmt.Errorf("decoding page %d: %w", page, err)
		}

		next, ok := nextPageFromHeaders(resp.Header, page)
		if !ok {
			break
		}
		page = next
	}
	return nil
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

// getWithResponse performs a GET with retry and returns the response for header inspection.
func (c *Client) getWithResponse(ctx context.Context, path string, params url.Values, target any) (*http.Response, error) {
	var lastErr error
	for attempt := range maxAttempts {
		resp, err := c.doRequest(ctx, path, params)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusOK {
			defer func() { _ = resp.Body.Close() }()
			if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
				return nil, fmt.Errorf("decoding response: %w", err)
			}
			return resp, nil
		}

		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		apiErr := &APIError{StatusCode: resp.StatusCode, Body: string(body)}
		if !retryableStatuses[resp.StatusCode] {
			return nil, apiErr
		}

		lastErr = apiErr
		if err := sleep(ctx, retryDelay(resp, attempt)); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

func (c *Client) doRequest(ctx context.Context, path string, params url.Values) (*http.Response, error) {
	u := c.baseURL + path
	if len(params) > 0 {
		u += "?" + params.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("PRIVATE-TOKEN", c.token)

	return c.httpClient.Do(req)
}

func retryDelay(resp *http.Response, attempt int) time.Duration {
	if resp != nil {
		if after := resp.Header.Get("Retry-After"); after != "" {
			if seconds, err := strconv.Atoi(after); err == nil && seconds > 0 {
				return time.Duration(seconds) * time.Second
			}
		}
	}
	return backoff(attempt)
}

func backoff(attempt int) time.Duration {
	base := math.Pow(2, float64(attempt))
	jitter := rand.Float64() * base * 0.5
	return time.Duration(base+jitter) * time.Second
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// appendJSON unmarshals pageData (a JSON array) and appends to target (a pointer to a slice).
func appendJSON(target any, pageData json.RawMessage) error {
	switch t := target.(type) {
	case *[]Project:
		var page []Project
		if err := json.Unmarshal(pageData, &page); err != nil {
			return err
		}
		*t = append(*t, page...)
	case *[]ProtectedBranch:
		var page []ProtectedBranch
		if err := json.Unmarshal(pageData, &page); err != nil {
			return err
		}
		*t = append(*t, page...)
	case *[]ApprovalRule:
		var page []ApprovalRule
		if err := json.Unmarshal(pageData, &page); err != nil {
			return err
		}
		*t = append(*t, page...)
	case *[]Member:
		var page []Member
		if err := json.Unmarshal(pageData, &page); err != nil {
			return err
		}
		*t = append(*t, page...)
	case *[]Webhook:
		var page []Webhook
		if err := json.Unmarshal(pageData, &page); err != nil {
			return err
		}
		*t = append(*t, page...)
	case *[]DeployKey:
		var page []DeployKey
		if err := json.Unmarshal(pageData, &page); err != nil {
			return err
		}
		*t = append(*t, page...)
	case *[]Runner:
		var page []Runner
		if err := json.Unmarshal(pageData, &page); err != nil {
			return err
		}
		*t = append(*t, page...)
	case *[]AuditEvent:
		var page []AuditEvent
		if err := json.Unmarshal(pageData, &page); err != nil {
			return err
		}
		*t = append(*t, page...)
	case *[]VulnerabilityFinding:
		var page []VulnerabilityFinding
		if err := json.Unmarshal(pageData, &page); err != nil {
			return err
		}
		*t = append(*t, page...)
	default:
		return fmt.Errorf("unsupported target type for pagination: %T", target)
	}
	return nil
}
