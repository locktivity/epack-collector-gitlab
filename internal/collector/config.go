package collector

// StatusFunc is called to report indeterminate status updates.
type StatusFunc func(message string)

// ProgressFunc is called to report determinate progress (current/total).
type ProgressFunc func(current, total int64, message string)

// Config holds the collector configuration.
type Config struct {
	Group           string   `json:"group"`
	BaseURL         string   `json:"base_url"`
	IncludePatterns []string `json:"include_patterns"`
	ExcludePatterns []string `json:"exclude_patterns"`

	OnStatus   StatusFunc   `json:"-"`
	OnProgress ProgressFunc `json:"-"`
}
