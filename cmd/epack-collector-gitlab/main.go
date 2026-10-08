package main

import (
	"github.com/locktivity/epack-collector-gitlab/internal/collector"
	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
	"github.com/locktivity/epack/componentsdk"
)

var (
	Version = "dev"
	Commit  = "unknown"
)

func main() {
	componentsdk.RunCollector(componentsdk.CollectorSpec{
		Name:        "gitlab",
		Version:     Version,
		Commit:      Commit,
		Description: "Collects GitLab group security posture metrics",
	}, run)
}

func run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()

	includePatterns, err := getStringSlice(cfg, "include_patterns")
	if err != nil {
		return err
	}
	excludePatterns, err := getStringSlice(cfg, "exclude_patterns")
	if err != nil {
		return err
	}

	config := collector.Config{
		Group:           getString(cfg, "group"),
		BaseURL:         getString(cfg, "base_url"),
		IncludePatterns: includePatterns,
		ExcludePatterns: excludePatterns,
		OnStatus:        ctx.Status,
		OnProgress:      ctx.Progress,
	}

	if config.Group == "" {
		return componentsdk.NewConfigError("group is required")
	}

	token := ctx.Secret("GITLAB_TOKEN")
	if token == "" {
		return componentsdk.NewConfigError("GITLAB_TOKEN is required")
	}

	client := gitlab.NewClient(config.BaseURL, token)
	c := collector.New(config, client)

	posture, err := c.Collect(ctx.Context(), ctx.Level())
	if err != nil {
		return componentsdk.NewNetworkError("collecting posture: %v", err)
	}

	normalized := posture.ToVCSPosture()

	return ctx.Emit([]componentsdk.CollectedArtifact{
		{
			Data: posture,
			Path: "artifacts/gitlab.json",
		},
		{
			Data:   normalized,
			Schema: "evidencepack/vcs-posture@v1",
			Path:   "artifacts/gitlab.vcs-posture.json",
		},
	})
}

func getString(cfg map[string]any, key string) string {
	if cfg == nil {
		return ""
	}
	if v, ok := cfg[key].(string); ok {
		return v
	}
	return ""
}

func getStringSlice(cfg map[string]any, key string) ([]string, error) {
	if cfg == nil {
		return nil, nil
	}
	raw, exists := cfg[key]
	if !exists || raw == nil {
		return nil, nil
	}
	v, ok := raw.([]any)
	if !ok {
		return nil, componentsdk.NewConfigError("%s must be a list", key)
	}
	result := make([]string, 0, len(v))
	for i, item := range v {
		s, ok := item.(string)
		if !ok {
			return nil, componentsdk.NewConfigError("%s[%d] must be a string", key, i)
		}
		result = append(result, s)
	}
	return result, nil
}
