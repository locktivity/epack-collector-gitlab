package collector

import (
	"time"

	"github.com/locktivity/epack-collector-gitlab/docs/schema"
	"github.com/locktivity/epack-collector-gitlab/internal/gitlab"
	"github.com/locktivity/epack/componentsdk"
)

// Spec describes the collector to componentsdk.RunCollector.
func Spec(version, commit string) componentsdk.CollectorSpec {
	return componentsdk.CollectorSpec{
		Name:        collectorName,
		Version:     version,
		Commit:      commit,
		Description: "Collects GitLab group security posture metrics",
		// Large groups take minutes. A runner's EPACK_DEADLINE shortens this.
		Timeout:  30 * time.Minute,
		Schemas:  schema.Schemas(),
		Methods:  schema.Methods(),
		TraceMap: schema.TraceMap,
		Writes:   []string{NormalizedSchema, AccessSchema, VulnSchema},
	}
}

// Run is the collector's handler. It fails only for invalid configuration or
// a failed sign-in, and otherwise emits what it collected with a gap recorded
// for each value it could not read.
func Run(ctx componentsdk.CollectorContext) error {
	cfg := ctx.Config()

	includePatterns, err := getStringSlice(cfg, "include_patterns")
	if err != nil {
		return err
	}
	excludePatterns, err := getStringSlice(cfg, "exclude_patterns")
	if err != nil {
		return err
	}

	config := Config{
		Group:           getString(cfg, "group"),
		BaseURL:         getString(cfg, "base_url"),
		IncludePatterns: includePatterns,
		ExcludePatterns: excludePatterns,
		OnStatus:        ctx.Status,
		OnProgress:      ctx.Progress,
		Recorder:        componentsdk.Records(ctx),
		Now:             func() time.Time { return componentsdk.Now(ctx) },
	}
	if config.Group == "" {
		return componentsdk.NewConfigError("group is required")
	}
	host, err := gitlab.Host(config.BaseURL)
	if err != nil {
		return componentsdk.NewConfigError("base_url: %v", err)
	}

	token := ctx.Secret("GITLAB_TOKEN") // LINT-ALLOW: sent only to the configured host, never written to an artifact
	if token == "" {
		return componentsdk.NewConfigError("GITLAB_TOKEN is required")
	}
	config.AccessPosture = componentsdk.Selected(ctx, componentsdk.Location{Schema: AccessSchema, Path: AccessPath})
	config.VulnScanning = componentsdk.Selected(ctx, componentsdk.Location{Schema: VulnSchema, Path: VulnPath})

	httpClient := componentsdk.NewHTTPClient(ctx, componentsdk.HTTPOptions{
		CredentialHosts:  []string{host},
		ClassifyResponse: gitlab.ClassifyResponse,
		NamesPermission:  gitlab.NamesPermission,
	})
	c := New(config, gitlab.NewClient(httpClient, config.BaseURL, token))

	posture, err := c.Collect(ctx.Context(), ctx.Level())
	if err != nil {
		return err
	}
	return ctx.Emit(c.Artifacts(posture))
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
