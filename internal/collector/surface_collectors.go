package collector

import (
	"context"
	"fmt"
	"time"

	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
	"github.com/locktivity/epack/componentsdk"
)

const auditLogWindowDays = 7

func (c *Collector) collectSurfaces(ctx context.Context, posture *GroupPosture, group *gitlab.Group, projects []gitlab.Project, metrics *projectMetrics, level componentsdk.Level, diag *diagnosticsTracker) {
	if !level.AtLeast(componentsdk.LevelAudit) {
		return
	}

	posture.AccessControl.ProjectCreationLevel = group.ProjectCreationLevel
	shareWithGroupLock := group.ShareWithGroupLock
	posture.AccessControl.ShareWithGroupLock = &shareWithGroupLock

	c.collectProjects(posture, projects, metrics)
	c.collectMembers(ctx, posture, diag)
	c.collectWebhooks(ctx, posture, projects, level, diag)
	c.collectDeployKeys(ctx, posture, projects, level, diag)
	c.collectRunners(ctx, posture, diag)

	if level.AtLeast(componentsdk.LevelInternal) {
		c.collectAuditLog(ctx, posture, diag)
	}
}

func (c *Collector) collectProjects(posture *GroupPosture, projects []gitlab.Project, metrics *projectMetrics) {
	pub, priv, internal, archived := 0, 0, 0, 0
	var rows []ProjectRow

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
		if bp, ok := metrics.branchProtections[p.ID]; ok {
			row.BranchProtection = bp
		}
		if ad, ok := metrics.approvalDetails[p.ID]; ok {
			row.ApprovalSettings = ad
		}
		rows = append(rows, row)
	}

	t := truncateProjects(rows)
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

func (c *Collector) collectMembers(ctx context.Context, posture *GroupPosture, diag *diagnosticsTracker) {
	c.status("Fetching members...")

	members, err := c.client.ListGroupMembers(ctx, c.config.Group)
	if err != nil {
		if isDenied(err) {
			diag.surfacePermissionDenied("members", "permission denied (requires read_api scope)")
		} else {
			diag.surfaceUnavailable("members", "fetch failed: "+safeDiagError(err))
		}
		return
	}

	owners, maintainers, developers := 0, 0, 0
	var rows []MemberRow

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

func (c *Collector) collectWebhooks(ctx context.Context, posture *GroupPosture, projects []gitlab.Project, level componentsdk.Level, diag *diagnosticsTracker) {
	c.status("Fetching webhooks...")

	groupCount := 0
	var groupRows []WebhookRow
	groupHooks, err := c.client.ListGroupWebhooks(ctx, c.config.Group)
	if err != nil {
		if isDenied(err) {
			diag.tierRequired("group_webhooks", "Premium")
		} else {
			diag.surfaceUnavailable("group_webhooks", "fetch failed: "+safeDiagError(err))
		}
	} else {
		groupCount = len(groupHooks)
		if level.AtLeast(componentsdk.LevelInternal) {
			for _, h := range groupHooks {
				groupRows = append(groupRows, WebhookRow{
					ID:        h.ID,
					Active:    h.AlertStatus != "disabled",
					URLHost:   webhookHost(h.URL),
					SSLVerify: h.EnableSSLVerification,
				})
			}
		}
	}

	projectCount := 0
	var projectRows []WebhookRow
	for _, p := range projects {
		hooks, err := c.client.ListProjectWebhooks(ctx, p.ID)
		if err != nil {
			diag.surfaceUnavailable("project_webhooks", fmt.Sprintf("project %s: fetch failed", p.Name))
			continue
		}
		projectCount += len(hooks)
		if level.AtLeast(componentsdk.LevelInternal) {
			for _, h := range hooks {
				projectRows = append(projectRows, WebhookRow{
					Project:   p.Name,
					ID:        h.ID,
					Active:    h.AlertStatus != "disabled",
					URLHost:   webhookHost(h.URL),
					SSLVerify: h.EnableSSLVerification,
				})
			}
		}
	}

	posture.Webhooks = &Webhooks{
		GroupCount:   groupCount,
		ProjectCount: projectCount,
		Group:        groupRows,
		Project:      projectRows,
	}
}

func (c *Collector) collectDeployKeys(ctx context.Context, posture *GroupPosture, projects []gitlab.Project, level componentsdk.Level, diag *diagnosticsTracker) {
	c.status("Fetching deploy keys...")

	totalCount, readWriteCount := 0, 0
	var rows []DeployKeyRow

	for _, p := range projects {
		keys, err := c.client.ListProjectDeployKeys(ctx, p.ID)
		if err != nil {
			diag.surfaceUnavailable("deploy_keys", fmt.Sprintf("project %s: fetch failed", p.Name))
			continue
		}
		for _, k := range keys {
			totalCount++
			if k.CanPush {
				readWriteCount++
			}
			if level.AtLeast(componentsdk.LevelInternal) {
				row := DeployKeyRow{
					Project:     p.Name,
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

	posture.DeployKeys = &DeployKeys{
		TotalCount:     totalCount,
		ReadWriteCount: readWriteCount,
		PerKey:         rows,
	}
}

func (c *Collector) collectRunners(ctx context.Context, posture *GroupPosture, diag *diagnosticsTracker) {
	c.status("Fetching runners...")

	runners, err := c.client.ListGroupRunners(ctx, c.config.Group)
	if err != nil {
		if isDenied(err) {
			diag.surfacePermissionDenied("runners", "permission denied (requires Maintainer role or above)")
		} else {
			diag.surfaceUnavailable("runners", "fetch failed: "+safeDiagError(err))
		}
		return
	}

	var rows []RunnerRow
	for _, r := range runners {
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
		GroupRunnerCount: len(runners),
		PerRunner:        rows,
	}
}

func (c *Collector) collectAuditLog(ctx context.Context, posture *GroupPosture, diag *diagnosticsTracker) {
	c.status("Fetching audit events...")

	since := time.Now().UTC().AddDate(0, 0, -auditLogWindowDays)
	events, err := c.client.ListGroupAuditEvents(ctx, c.config.Group, since)
	if err != nil {
		if isDenied(err) {
			diag.tierRequired("audit_events", "Premium")
		} else {
			diag.surfaceUnavailable("audit_events", "fetch failed: "+safeDiagError(err))
		}
		return
	}

	countByAction := make(map[string]int)
	var rows []AuditLogRow

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
	case level >= 20:
		return "reporter"
	case level >= 10:
		return "guest"
	default:
		return "minimal"
	}
}
