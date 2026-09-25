package collector

import "sort"

const (
	MaxProjects    = 5000
	MaxMembers     = 10000
	MaxAuditEvents = 5000
	MaxFindings    = 5000
)

type truncatable[T any] struct {
	items           []T
	truncated       bool
	truncatedDropped int
}

func truncateProjects(rows []ProjectRow) truncatable[ProjectRow] {
	if len(rows) <= MaxProjects {
		return truncatable[ProjectRow]{items: rows}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Visibility != rows[j].Visibility {
			return visibilityRank(rows[i].Visibility) < visibilityRank(rows[j].Visibility)
		}
		return rows[i].Name < rows[j].Name
	})
	return truncatable[ProjectRow]{
		items:            rows[:MaxProjects],
		truncated:        true,
		truncatedDropped: len(rows) - MaxProjects,
	}
}

func truncateMembers(rows []MemberRow) truncatable[MemberRow] {
	if len(rows) <= MaxMembers {
		return truncatable[MemberRow]{items: rows}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].AccessLevel != rows[j].AccessLevel {
			return rows[i].AccessLevel > rows[j].AccessLevel
		}
		return rows[i].Username < rows[j].Username
	})
	return truncatable[MemberRow]{
		items:            rows[:MaxMembers],
		truncated:        true,
		truncatedDropped: len(rows) - MaxMembers,
	}
}

func visibilityRank(v string) int {
	switch v {
	case "private":
		return 0
	case "internal":
		return 1
	case "public":
		return 2
	default:
		return 3
	}
}
