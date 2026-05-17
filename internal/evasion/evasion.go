package evasion

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/pridhvi/nyx/internal/models"
)

type Policy struct {
	Profile           string `json:"profile"`
	JitterMS          int    `json:"jitter_ms"`
	ProxyURL          string `json:"proxy_url,omitempty"`
	UserAgentProfile  string `json:"user_agent_profile,omitempty"`
	HeaderProfile     string `json:"header_profile,omitempty"`
	AdaptiveBackoff   bool   `json:"adaptive_backoff"`
	MaxBackoffSeconds int    `json:"max_backoff_seconds"`
}

func Normalize(options models.ScanRunnerOptions) (models.ScanRunnerOptions, Policy, error) {
	profile := strings.TrimSpace(options.EvasionProfile)
	if profile == "" {
		profile = "normal"
	}
	switch profile {
	case "safe":
		if options.Concurrency == 0 || options.Concurrency > 2 {
			options.Concurrency = 2
		}
		if options.PerToolConcurrency == 0 || options.PerToolConcurrency > 1 {
			options.PerToolConcurrency = 1
		}
	case "normal":
	case "stealth":
		options.Concurrency = 1
		options.PerToolConcurrency = 1
		if options.ToolDelayMS < 1000 {
			options.ToolDelayMS = 1000
		}
		if options.JitterMS < 250 {
			options.JitterMS = 250
		}
		if options.UserAgentProfile == "" {
			options.UserAgentProfile = "browser"
		}
		options.AdaptiveBackoff = true
		if options.MaxBackoffSeconds == 0 {
			options.MaxBackoffSeconds = 30
		}
	case "custom":
	default:
		return models.ScanRunnerOptions{}, Policy{}, fmt.Errorf("unsupported evasion profile %q", profile)
	}
	if strings.TrimSpace(options.ProxyURL) != "" {
		parsed, err := url.Parse(options.ProxyURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https" && parsed.Scheme != "socks5") || parsed.Host == "" {
			return models.ScanRunnerOptions{}, Policy{}, fmt.Errorf("invalid proxy URL")
		}
	}
	options.EvasionProfile = profile
	policy := Policy{
		Profile:           profile,
		JitterMS:          options.JitterMS,
		ProxyURL:          RedactProxy(options.ProxyURL),
		UserAgentProfile:  options.UserAgentProfile,
		HeaderProfile:     options.HeaderProfile,
		AdaptiveBackoff:   options.AdaptiveBackoff,
		MaxBackoffSeconds: options.MaxBackoffSeconds,
	}
	return options, policy, nil
}

func RedactProxy(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.User == nil {
		return raw
	}
	parsed.User = url.User("********")
	return parsed.String()
}

func DetectBlock(statusCode int, body string) (string, bool) {
	lower := strings.ToLower(body)
	switch {
	case statusCode == 403:
		return "http_403", true
	case statusCode == 429:
		return "rate_limited", true
	case strings.Contains(lower, "access denied") || strings.Contains(lower, "captcha") || strings.Contains(lower, "blocked"):
		return "block_marker", true
	default:
		return "", false
	}
}
