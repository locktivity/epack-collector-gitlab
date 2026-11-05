package gitlab

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/locktivity/epack/componentsdk"
)

const (
	opSecurityScanners = "gitlab.graphql.security_scanners"
	opVulnerabilities  = "gitlab.graphql.vulnerabilities"

	// ScannerBatch is the largest number of projects in one security
	// scanner query. Each project's scanners are read from its repository,
	// so a small batch keeps the query within GraphQL's 30 second limit.
	ScannerBatch = 50
)

// securityScannersQuery reads the scanners of the projects with the given
// IDs. available lists the scanners the plan includes. pipelineRun lists
// those whose jobs succeeded in the latest pipeline on the default branch.
const securityScannersQuery = `query GitLabSecurityScanners($ids: [ID!], $after: String) {
  projects(ids: $ids, first: 50, after: $after) {
    nodes { id securityScanners { available pipelineRun } }
    pageInfo { hasNextPage endCursor }
  }
}`

// vulnerabilitiesQuery reads the group's open vulnerabilities from the three
// scanners the collector reports, page by page. vulnerabilitySeveritiesCount
// is null when the token cannot read the group's vulnerabilities, which
// takes GitLab Ultimate and the Developer role. The vulnerability list is
// empty in that case, so only the null count shows that the report could
// not be read.
const vulnerabilitiesQuery = `query GitLabVulnerabilities($group: ID!, $after: String) {
  group(fullPath: $group) {
    vulnerabilitySeveritiesCount(state: [DETECTED, CONFIRMED]) { critical }
    vulnerabilities(state: [DETECTED, CONFIRMED], reportType: [DEPENDENCY_SCANNING, SAST, SECRET_DETECTION], severity: [CRITICAL, HIGH, MEDIUM, LOW], first: 100, after: $after) {
      nodes { reportType severity detectedAt project { id } }
      pageInfo { hasNextPage endCursor }
    }
  }
}`

// SecurityScanners holds the lists in one project's securityScanners field
// in GitLab's GraphQL API. Each list holds scanner types such as SAST or
// DEPENDENCY_SCANNING.
type SecurityScanners struct {
	Available   []string
	PipelineRun []string
}

// Vulnerabilities is a group's open vulnerabilities from dependency
// scanning, SAST, and secret detection. Readable is false when the token
// cannot read the group's vulnerability report, and Items is then empty.
type Vulnerabilities struct {
	Readable bool
	Items    []Vulnerability
}

// Vulnerability is one open vulnerability.
type Vulnerability struct {
	ProjectID int
	// ReportType is DEPENDENCY_SCANNING, SAST, or SECRET_DETECTION.
	ReportType string
	// Severity is CRITICAL, HIGH, MEDIUM, or LOW.
	Severity   string
	DetectedAt time.Time
}

// pageInfo is a GraphQL connection's paging state.
type pageInfo struct {
	HasNextPage *bool  `json:"hasNextPage"`
	EndCursor   string `json:"endCursor"`
}

// next returns the cursor of the next page, or "" after the last page.
func (p *pageInfo) next(op string) (string, error) {
	switch {
	case p == nil || p.HasNextPage == nil:
		return "", invalidResponse(op, "has no pageInfo")
	case !*p.HasNextPage:
		return "", nil
	case p.EndCursor == "":
		return "", invalidResponse(op, "has a next page and no endCursor")
	}
	return p.EndCursor, nil
}

// ListSecurityScanners reads the security scanners of the projects with the
// given IDs, at most ScannerBatch of them. A project missing from the
// answer, or whose securityScanners is null, has no entry.
func (c *Client) ListSecurityScanners(ctx context.Context, projectIDs []int) (map[int]SecurityScanners, error) {
	ids := make([]string, len(projectIDs))
	for i, id := range projectIDs {
		ids[i] = projectGID(id)
	}
	out := make(map[int]SecurityScanners, len(projectIDs))
	var after *string
	for {
		var data struct {
			Projects *struct {
				Nodes []struct {
					ID               string `json:"id"`
					SecurityScanners *struct {
						Available   []string `json:"available"`
						PipelineRun []string `json:"pipelineRun"`
					} `json:"securityScanners"`
				} `json:"nodes"`
				PageInfo *pageInfo `json:"pageInfo"`
			} `json:"projects"`
		}
		resp, err := c.graphql(ctx, opSecurityScanners, "GitLabSecurityScanners", securityScannersQuery,
			map[string]any{"ids": ids, "after": after}, &data, nil)
		if err != nil {
			return nil, err
		}
		if data.Projects == nil || data.Projects.Nodes == nil {
			return nil, componentsdk.ResponseError(resp, invalidResponse(opSecurityScanners, "has no projects"))
		}
		for _, node := range data.Projects.Nodes {
			id, ok := gidNumber(node.ID, "Project")
			if !ok {
				return nil, componentsdk.ResponseError(resp, invalidResponse(opSecurityScanners, "has a project without a project ID"))
			}
			if s := node.SecurityScanners; s != nil {
				out[id] = SecurityScanners{Available: s.Available, PipelineRun: s.PipelineRun}
			}
		}
		cursor, err := data.Projects.PageInfo.next(opSecurityScanners)
		if err != nil {
			return nil, componentsdk.ResponseError(resp, err)
		}
		if cursor == "" {
			return out, nil
		}
		after = &cursor
	}
}

// ListGroupVulnerabilities reads the open vulnerabilities of the group at
// fullPath and its subgroups, every page of them.
func (c *Client) ListGroupVulnerabilities(ctx context.Context, fullPath string) (*Vulnerabilities, error) {
	out := &Vulnerabilities{Items: []Vulnerability{}}
	var after *string
	for {
		var data struct {
			Group *struct {
				SeveritiesCount json.RawMessage `json:"vulnerabilitySeveritiesCount"`
				Vulnerabilities *struct {
					Nodes []struct {
						ReportType string     `json:"reportType"`
						Severity   string     `json:"severity"`
						DetectedAt *time.Time `json:"detectedAt"`
						Project    *struct {
							ID string `json:"id"`
						} `json:"project"`
					} `json:"nodes"`
					PageInfo *pageInfo `json:"pageInfo"`
				} `json:"vulnerabilities"`
			} `json:"group"`
		}
		// A token that cannot read the report gets an error on the count
		// along with the null.
		countDenied := func(e graphqlError) bool {
			return slices.Equal(e.Path, []any{"group", "vulnerabilitySeveritiesCount"})
		}
		resp, err := c.graphql(ctx, opVulnerabilities, "GitLabVulnerabilities", vulnerabilitiesQuery,
			map[string]any{"group": fullPath, "after": after}, &data, countDenied)
		if err != nil {
			return nil, err
		}
		if data.Group == nil {
			return nil, componentsdk.ResponseError(resp, invalidResponse(opVulnerabilities, "has no group"))
		}
		if len(data.Group.SeveritiesCount) == 0 || string(data.Group.SeveritiesCount) == "null" {
			return &Vulnerabilities{Items: []Vulnerability{}}, nil
		}
		list := data.Group.Vulnerabilities
		if list == nil || list.Nodes == nil {
			return nil, componentsdk.ResponseError(resp, invalidResponse(opVulnerabilities, "has no vulnerabilities"))
		}
		out.Readable = true
		for _, node := range list.Nodes {
			var projectID int
			ok := node.Project != nil
			if ok {
				projectID, ok = gidNumber(node.Project.ID, "Project")
			}
			if !ok || node.DetectedAt == nil || node.ReportType == "" || node.Severity == "" {
				return nil, componentsdk.ResponseError(resp, invalidResponse(opVulnerabilities, "has a vulnerability without its project, detectedAt, reportType, or severity"))
			}
			out.Items = append(out.Items, Vulnerability{
				ProjectID:  projectID,
				ReportType: node.ReportType,
				Severity:   node.Severity,
				DetectedAt: *node.DetectedAt,
			})
		}
		cursor, err := list.PageInfo.next(opVulnerabilities)
		if err != nil {
			return nil, componentsdk.ResponseError(resp, err)
		}
		if cursor == "" {
			return out, nil
		}
		after = &cursor
	}
}

// graphqlError is one entry of a GraphQL response's errors.
type graphqlError struct {
	Message string `json:"message"`
	Path    []any  `json:"path"`
}

// graphql sends one named query and decodes its data into dest. An error in
// the response fails the call unless tolerate accepts it. The query is a
// read, so the SDK's client retries it as it retries a GET.
func (c *Client) graphql(ctx context.Context, op, name, query string, variables map[string]any, dest any, tolerate func(graphqlError) bool) (*http.Response, error) {
	ctx = componentsdk.WithOperation(ctx, componentsdk.Operation{Name: op, Safe: true, Permission: permissions[op]})
	body, err := json.Marshal(map[string]any{"operationName": name, "query": query, "variables": variables})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.graphqlURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var envelope struct {
		Data   json.RawMessage `json:"data"`
		Errors []graphqlError  `json:"errors"`
	}
	if err := decode(op, req, resp, &envelope); err != nil {
		return nil, err
	}
	for _, e := range envelope.Errors {
		if tolerate == nil || !tolerate(e) {
			return nil, componentsdk.ResponseError(resp, invalidResponse(op, "has an error: "+truncate(e.Message)))
		}
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil, componentsdk.ResponseError(resp, invalidResponse(op, "has no data"))
	}
	if err := json.Unmarshal(envelope.Data, dest); err != nil {
		return nil, componentsdk.ResponseError(resp, fmt.Errorf("decoding the response to %s: %w", op, err))
	}
	return resp, nil
}

func truncate(message string) string {
	if len(message) > maxMessage {
		return message[:maxMessage] + "..."
	}
	return message
}

// projectGID is the GraphQL global ID of the project with the REST ID id.
func projectGID(id int) string {
	return "gid://gitlab/Project/" + strconv.Itoa(id)
}

// gidNumber returns the number at the end of a GraphQL global ID of the
// given type, such as 12 from gid://gitlab/Project/12.
func gidNumber(gid, kind string) (int, bool) {
	rest, ok := strings.CutPrefix(gid, "gid://gitlab/"+kind+"/")
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	return n, err == nil && n > 0
}
