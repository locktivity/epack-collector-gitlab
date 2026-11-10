package collector

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/locktivity/epack/componentsdk"
	"github.com/locktivity/epack/componentsdk/collectortest"
)

// kitGroupTarget is the group target of a run with the kit's config. count
// is nil at trust, which writes no count.
func kitGroupTarget(count *int) componentsdk.ResultTarget {
	return componentsdk.ResultTarget{
		Kind:      componentsdk.TargetGroup,
		ChosenBy:  componentsdk.ChosenByConfig,
		ConfigKey: "group",
		At:        &componentsdk.Location{Path: DetailedPath, Pointer: "/group"},
		Count:     count,
		Complete:  ptr(true),
	}
}

// kitProjectTarget is the project target of an audit run with the kit's
// config, which excludes sandbox-*.
func kitProjectTarget(complete bool) componentsdk.ResultTarget {
	at := func(pointer string) *componentsdk.Location {
		return &componentsdk.Location{Path: DetailedPath, Pointer: pointer}
	}
	return componentsdk.ResultTarget{
		Kind:      componentsdk.TargetProject,
		ChosenBy:  componentsdk.ChosenByFilter,
		ConfigKey: "exclude_patterns",
		At:        at("/projects/per_project"),
		Name:      []string{"/path_with_namespace"},
		Found:     at("/scope/project_count"),
		Assessed:  at("/scope/included_project_count"),
		Coverage:  at("/scope/projects_coverage"),
		Include:   at("/scope/include_patterns"),
		Exclude:   at("/scope/exclude_patterns"),
		Count:     ptr(4),
		Complete:  ptr(complete),
	}
}

// targetsOf runs the collector at level and returns its group and project
// targets. It fails the test unless the result declares those two alone and
// the artifacts bear them out.
func targetsOf(t *testing.T, config map[string]any, level string, responses []collectortest.Response) (group, projects componentsdk.ResultTarget) {
	t.Helper()
	config["level"] = level
	res := runInProcess(config, kitSecrets(), newReplay(t, responses))
	if res.Result == nil {
		t.Fatalf("no collector result; exit %d: %s", res.ExitCode, res.Stderr)
	}
	for _, f := range res.Result.Checks {
		if f.Check == componentsdk.CheckTargets {
			t.Errorf("targets check: %s %s %s", f.Path, f.Pointer, f.Message)
		}
	}
	got := res.Result.Targets
	if len(got) != 2 || got[0].Kind != componentsdk.TargetGroup || got[1].Kind != componentsdk.TargetProject {
		t.Fatalf("targets = %+v, want the group and its projects", got)
	}
	return got[0], got[1]
}

func checkTarget(t *testing.T, got, want componentsdk.ResultTarget) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		g, _ := json.Marshal(got)
		w, _ := json.Marshal(want)
		t.Errorf("%s target:\n got  %s\n want %s", want.Kind, g, w)
	}
}

func TestAnAuditRunDeclaresTheGroupAndTheProjectsItAssessed(t *testing.T) {
	group, projects := targetsOf(t, kitConfig(), "audit", kitResponses(kitCleanTenant(), kitBase))
	checkTarget(t, group, kitGroupTarget(ptr(1)))
	checkTarget(t, projects, kitProjectTarget(true))
}

// The projects are audit-level, so a trust run keeps the group and the
// scope's counts, coverage, and patterns, and leaves out the projects and
// whether they were complete.
func TestATrustRunKeepsTheGroupAndTheProjectScope(t *testing.T) {
	group, projects := targetsOf(t, kitConfig(), "trust", kitResponses(kitCleanTenant(), kitBase))
	checkTarget(t, group, kitGroupTarget(nil))
	want := kitProjectTarget(true)
	want.At, want.Name, want.Count, want.Complete = nil, nil, nil, nil
	checkTarget(t, projects, want)
}

func TestAProjectWhoseProtectionReadFailsLeavesTheProjectsIncomplete(t *testing.T) {
	responses := append([]collectortest.Response{{
		URL:    kitBase + "/projects/10/protected_branches",
		Status: http.StatusInternalServerError,
		Body:   `{"message":"500 Internal Server Error"}`,
	}}, kitResponses(kitCleanTenant(), kitBase)...)
	group, projects := targetsOf(t, kitConfig(), "audit", responses)
	checkTarget(t, group, kitGroupTarget(ptr(1)))
	checkTarget(t, projects, kitProjectTarget(false))
}

func TestProjectsAreChosenByFilterWhenThePatternsNarrowThem(t *testing.T) {
	tests := []struct {
		name   string
		config map[string]any
		how    componentsdk.TargetChoice
		key    string
		count  int
	}{
		{name: "the default patterns", config: map[string]any{}, how: componentsdk.ChosenByDiscovery, count: 5},
		{name: "the default include pattern written out", config: map[string]any{"include_patterns": []any{"*"}, "exclude_patterns": []any{}}, how: componentsdk.ChosenByDiscovery, count: 5},
		{name: "include patterns", config: map[string]any{"include_patterns": []any{"web*", "docs"}}, how: componentsdk.ChosenByFilter, key: "include_patterns", count: 2},
		{name: "include and exclude patterns", config: map[string]any{"include_patterns": []any{"web*", "docs"}, "exclude_patterns": []any{"docs"}}, how: componentsdk.ChosenByFilter, key: "exclude_patterns", count: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config["group"] = kitGroup
			_, projects := targetsOf(t, tt.config, "audit", kitResponses(kitCleanTenant(), kitBase))
			if projects.ChosenBy != tt.how || projects.ConfigKey != tt.key {
				t.Errorf("chosen_by = %q config_key = %q, want %q and %q", projects.ChosenBy, projects.ConfigKey, tt.how, tt.key)
			}
			if projects.Count == nil || *projects.Count != tt.count {
				t.Errorf("count = %v, want %d", projects.Count, tt.count)
			}
		})
	}
}
