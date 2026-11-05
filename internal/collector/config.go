package collector

import (
	"time"

	"github.com/locktivity/epack/componentsdk"
)

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

	// AccessPosture and VulnScanning say whether the run collects the
	// access-posture and vuln-scanning artifacts. Run sets them from
	// componentsdk.Selected.
	AccessPosture bool `json:"-"`
	VulnScanning  bool `json:"-"`

	OnStatus   StatusFunc   `json:"-"`
	OnProgress ProgressFunc `json:"-"`

	// Recorder takes the gaps and the signed-in identity. Nil discards them.
	Recorder *componentsdk.Recorder `json:"-"`
	// Now reads the run's clock. Nil means time.Now.
	Now func() time.Time `json:"-"`
}
