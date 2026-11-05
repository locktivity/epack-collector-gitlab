package collector

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
	"github.com/locktivity/epack/componentsdk"
)

const auditLogWindowDays = 7

var errNoCreatedAt = componentsdk.CodeError(componentsdk.CodeInvalidResponse, errors.New("an audit event in the response has no created_at"))

// collectProjects builds the audit-level project inventory. A row whose
// branch protection or approval settings could not be read leaves them out,
// with a gap.
func (c *Collector) collectProjects(posture *GroupPosture, projects []gitlab.Project, metrics *projectMetrics) {
	pub, priv, internal, archived := 0, 0, 0, 0
	rows := make([]ProjectRow, 0, len(projects))

	for _, p := range projects {
		switch p.Visibility {
		case "public":
			pub++
		case "private":
			priv++
		case "internal":
			internal++
		}
		if p.Archived {
			archived++
		}

		row := ProjectRow{
			Name:              p.Name,
			PathWithNamespace: p.PathWithNamespace,
			Visibility:        p.Visibility,
			Archived:          p.Archived,
			DefaultBranch:     p.DefaultBranch,
			MergeMethod:       p.MergeMethod,
		}
		if p.CreatedAt != nil {
			row.CreatedAt = p.CreatedAt.Format(time.RFC3339)
		}
		if p.LastActivityAt != nil {
			row.LastActivityAt = p.LastActivityAt.Format(time.RFC3339)
		}
		if r := metrics.results[p.ID]; r != nil {
			row.BranchProtection = r.protection
			row.ApprovalSettings = r.approval
			row.protectionErr = r.protectionErr
			row.approvalErr = r.approvalErr
		}
		rows = append(rows, row)
	}

	t := truncateProjects(rows)
	for i, row := range t.items {
		if row.protectionErr != nil {
			c.gaps.leaveOut(row.protectionErr, rowPointer("/projects/per_project", i, "branch_protection"))
		}
		if row.approvalErr != nil {
			c.gaps.leaveOut(row.approvalErr, rowPointer("/projects/per_project", i, "approval_settings"))
		}
	}
	posture.Projects = &Projects{
		TotalCount:       len(projects),
		PublicCount:      pub,
		PrivateCount:     priv,
		InternalCount:    internal,
		ArchivedCount:    archived,
		PerProject:       t.items,
		Truncated:        t.truncated,
		TruncatedDropped: t.truncatedDropped,
	}
}

// readMembers reads the group's members once, for the detailed artifact and
// the access-posture artifact.
func (c *Collector) readMembers(ctx context.Context) {
	c.status("Fetching members...")
	c.reads.members, c.reads.membersErr = c.client.ListGroupMembers(ctx, c.config.Group)
}

// collectMembers builds the audit-level member inventory from the members
// readMembers read.
func (c *Collector) collectMembers(posture *GroupPosture) {
	members, err := c.reads.members, c.reads.membersErr
	if err != nil {
		if gitlab.StatusOf(err) == http.StatusForbidden {
			c.diag.surfacePermissionDenied("members", "permission denied (requires read_api scope)")
		} else {
			c.diag.surfaceUnavailable("members", "fetch failed: "+safeDiagError(err))
		}
		c.gaps.leaveOut(err, "/members")
		return
	}

	owners, maintainers, developers := 0, 0, 0
	rows := make([]MemberRow, 0, len(members))

	for _, m := range members {
		switch {
		case m.AccessLevel >= 50:
			owners++
		case m.AccessLevel >= 40:
			maintainers++
		case m.AccessLevel >= 30:
			developers++
		}

		rows = append(rows, MemberRow{
			Username:         m.Username,
			Name:             m.Name,
			Role:             accessLevelName(m.AccessLevel),
			AccessLevel:      m.AccessLevel,
			TwoFactorEnabled: m.TwoFactorEnabled,
			State:            m.State,
		})
	}

	t := truncateMembers(rows)
	posture.Members = &Members{
		TotalCount:       len(members),
		OwnerCount:       owners,
		MaintainerCount:  maintainers,
		DeveloperCount:   developers,
		PerMember:        t.items,
		Truncated:        t.truncated,
		TruncatedDropped: t.truncatedDropped,
	}
}

// collectWebhooks counts group and project webhooks, with rows at internal.
// When any project's hooks could not be read, the project count and rows
// are left out, since the rest no longer describe the group.
func (c *Collector) collectWebhooks(ctx context.Context, posture *GroupPosture, projects []gitlab.Project, projectsErr error, level componentsdk.Level) {
	c.status("Fetching webhooks...")
	internal := level.AtLeast(componentsdk.LevelInternal)
	hooks := &Webhooks{}

	groupHooks, err := c.client.ListGroupWebhooks(ctx, c.config.Group)
	if err != nil {
		if gitlab.StatusOf(err) == http.StatusForbidden {
			c.diag.tierRequired("group_webhooks", "Premium")
		} else {
			c.diag.surfaceUnavailable("group_webhooks", "fetch failed: "+safeDiagError(err))
		}
		c.gaps.leaveOut(err, "/webhooks/group_count")
		if internal {
			c.gaps.leaveOut(err, "/webhooks/group")
		}
	} else {
		count := len(groupHooks)
		hooks.GroupCount = &count
		if internal {
			hooks.Group = make([]WebhookRow, 0, len(groupHooks))
			for _, h := range groupHooks {
				hooks.Group = append(hooks.Group, webhookRow("", h))
			}
			c.leaveOutHosts("/webhooks/group", hooks.Group)
		}
	}

	// A failed project list already left the project count and rows out.
	if projectsErr == nil {
		count, failed := 0, 0
		var firstErr error
		rows := []WebhookRow{}
		for _, p := range projects {
			projectHooks, err := c.client.ListProjectWebhooks(ctx, p.ID)
			if err != nil {
				if ctx.Err() == nil {
					c.diag.surfaceUnavailable("project_webhooks", fmt.Sprintf("project %s: fetch failed", p.Name))
				}
				failed++
				firstErr = firstError(firstErr, err)
				continue
			}
			count += len(projectHooks)
			if internal {
				for _, h := range projectHooks {
					rows = append(rows, webhookRow(p.Name, h))
				}
			}
		}
		if failed > 0 {
			c.gaps.partial(failed, firstErr, "/webhooks/project_count")
			if internal {
				c.gaps.leaveOut(firstErr, "/webhooks/project")
			}
		} else {
			hooks.ProjectCount = &count
			if internal {
				hooks.Project = rows
				c.leaveOutHosts("/webhooks/project", rows)
			}
		}
	}

	posture.Webhooks = hooks
}

func webhookRow(project string, h gitlab.Webhook) WebhookRow {
	host, hostErr := webhookHost(h.URL)
	return WebhookRow{
		Project:   project,
		ID:        h.ID,
		Active:    h.AlertStatus != "disabled",
		URLHost:   host,
		SSLVerify: h.EnableSSLVerification,
		hostErr:   hostErr,
	}
}

// leaveOutHosts records a gap for each row in list whose url_host is not
// known.
func (c *Collector) leaveOutHosts(list string, rows []WebhookRow) {
	for i, row := range rows {
		if row.hostErr != nil {
			c.gaps.leaveOut(row.hostErr, rowPointer(list, i, "url_host"))
		}
	}
}

// readDeployKeys reads each assessed project's deploy keys once, for the
// detailed artifact and the access-posture artifact.
func (c *Collector) readDeployKeys(ctx context.Context, projects []gitlab.Project) {
	c.status("Fetching deploy keys...")
	c.reads.deployKeys = readEachProject(ctx, projects, c.client.ListProjectDeployKeys)
}

// readEachProject calls list for each project, and counts the projects whose
// call failed. It names each project whose call failed before the run ran
// out of time.
func readEachProject[T any](ctx context.Context, projects []gitlab.Project, list func(context.Context, int) ([]T, error)) projectLists[T] {
	var out projectLists[T]
	for _, p := range projects {
		items, err := list(ctx, p.ID)
		if err != nil {
			out.failed++
			out.err = firstError(out.err, err)
			if ctx.Err() == nil {
				out.failedNames = append(out.failedNames, p.Name)
			}
			continue
		}
		out.lists = append(out.lists, projectList[T]{project: p, items: items})
	}
	return out
}

// collectDeployKeys counts the deploy keys readDeployKeys read across
// projects, with rows at internal. When any project's keys could not be
// read, the counts and rows are left out.
func (c *Collector) collectDeployKeys(posture *GroupPosture, projectsErr error, level componentsdk.Level) {
	// A failed project list already left deploy_keys out.
	if projectsErr != nil {
		return
	}
	internal := level.AtLeast(componentsdk.LevelInternal)
	keys := c.reads.deployKeys
	for _, name := range keys.failedNames {
		c.diag.surfaceUnavailable("deploy_keys", fmt.Sprintf("project %s: fetch failed", name))
	}

	totalCount, readWriteCount := 0, 0
	rows := []DeployKeyRow{}
	for _, list := range keys.lists {
		for _, k := range list.items {
			totalCount++
			if k.CanPush {
				readWriteCount++
			}
			if internal {
				row := DeployKeyRow{
					Project:     list.project.Name,
					ID:          k.ID,
					Title:       k.Title,
					ReadOnly:    !k.CanPush,
					Fingerprint: k.Fingerprint,
				}
				if k.CreatedAt != nil {
					row.CreatedAt = k.CreatedAt.Format(time.RFC3339)
				}
				rows = append(rows, row)
			}
		}
	}

	deployKeys := &DeployKeys{}
	if keys.failed > 0 {
		c.gaps.partial(keys.failed, keys.err, "/deploy_keys/total_count", "/deploy_keys/read_write_count")
		if internal {
			c.gaps.leaveOut(keys.err, "/deploy_keys/per_key")
		}
	} else {
		deployKeys.TotalCount = &totalCount
		deployKeys.ReadWriteCount = &readWriteCount
		if internal {
			deployKeys.PerKey = rows
		}
	}
	posture.DeployKeys = deployKeys
}

// collectRunners counts the group runners available to the group. A runner
// of another type in the list, such as an instance runner, is not counted.
func (c *Collector) collectRunners(ctx context.Context, posture *GroupPosture) {
	c.status("Fetching runners...")

	runners, err := c.client.ListGroupRunners(ctx, c.config.Group)
	if err != nil {
		if gitlab.StatusOf(err) == http.StatusForbidden {
			c.diag.surfacePermissionDenied("runners", "permission denied (requires Maintainer role or above)")
		} else {
			c.diag.surfaceUnavailable("runners", "fetch failed: "+safeDiagError(err))
		}
		c.gaps.leaveOut(err, "/runners")
		return
	}

	rows := make([]RunnerRow, 0, len(runners))
	for _, r := range runners {
		if r.RunnerType != "group_type" {
			continue
		}
		rows = append(rows, RunnerRow{
			ID:     r.ID,
			Name:   r.Description, // LINT-ALLOW: runner description is a display name, not customer content
			Status: r.Status,
			Type:   r.RunnerType,
			Online: r.Online,
			Paused: r.Paused,
			Tags:   r.TagList,
		})
	}

	posture.Runners = &Runners{
		GroupRunnerCount: len(rows),
		PerRunner:        rows,
	}
}

func (c *Collector) collectAuditLog(ctx context.Context, posture *GroupPosture) {
	c.status("Fetching audit events...")

	since := c.now().UTC().AddDate(0, 0, -auditLogWindowDays)
	events, err := c.client.ListGroupAuditEvents(ctx, c.config.Group, since)
	if err == nil && slices.ContainsFunc(events, func(e gitlab.AuditEvent) bool { return e.CreatedAt == nil }) {
		err = errNoCreatedAt
	}
	if err != nil {
		if gitlab.StatusOf(err) == http.StatusForbidden {
			c.diag.tierRequired("audit_events", "Premium")
		} else {
			c.diag.surfaceUnavailable("audit_events", "fetch failed: "+safeDiagError(err))
		}
		c.gaps.leaveOut(err, "/audit_log")
		return
	}

	countByAction := make(map[string]int)
	rows := make([]AuditLogRow, 0, len(events))

	for _, e := range events {
		action := e.Details.CustomMessage
		if action == "" {
			action = "unknown"
		}
		countByAction[action]++

		rows = append(rows, AuditLogRow{
			Action:    action,
			Actor:     e.Details.AuthorName,
			Timestamp: e.CreatedAt.Unix(),
		})
	}

	truncated := false
	truncatedDropped := 0
	if len(rows) > MaxAuditEvents {
		truncatedDropped = len(rows) - MaxAuditEvents
		rows = rows[:MaxAuditEvents]
		truncated = true
	}

	posture.AuditLog = &AuditLog{
		WindowDays:       auditLogWindowDays,
		CountByAction:    countByAction,
		Events:           rows,
		Truncated:        truncated,
		TruncatedDropped: truncatedDropped,
	}
}

func accessLevelName(level int) string {
	switch {
	case level >= 50:
		return "owner"
	case level >= 40:
		return "maintainer"
	case level >= 30:
		return "developer"
	case level >= 25:
		return "security_manager"
	case level >= 20:
		return "reporter"
	case level >= 15:
		return "planner"
	case level >= 10:
		return "guest"
	default:
		return "minimal"
	}
}
