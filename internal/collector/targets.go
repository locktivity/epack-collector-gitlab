package collector

import (
	"slices"

	"github.com/locktivity/epack/componentsdk"
)

// declareTargets declares what the run was pointed at: the group the config
// names, and the projects in it the run assessed.
func (g *GroupPosture) declareTargets(rec *componentsdk.Recorder) {
	rec.Targets(componentsdk.TargetGroup, detailed("/group")).
		ChosenBy(componentsdk.ChosenByConfig, "group")
	how, key := g.Scope.projectChoice()
	rec.Targets(componentsdk.TargetProject, detailed("/projects/per_project"), "/path_with_namespace").
		ChosenBy(how, key).
		Found(detailed("/scope/project_count")).
		Assessed(detailed("/scope/included_project_count")).
		Coverage(detailed("/scope/projects_coverage")).
		Patterns(detailed("/scope/include_patterns"), detailed("/scope/exclude_patterns"))
}

// projectChoice says how the run chose its projects, and the config key that
// narrowed them. Patterns other than the default narrow them.
func (s Scope) projectChoice() (componentsdk.TargetChoice, string) {
	switch {
	case len(s.ExcludePatterns) > 0:
		return componentsdk.ChosenByFilter, "exclude_patterns"
	case !slices.Equal(s.IncludePatterns, []string{DefaultIncludePattern}):
		return componentsdk.ChosenByFilter, "include_patterns"
	}
	return componentsdk.ChosenByDiscovery, ""
}
