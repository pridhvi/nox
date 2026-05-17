package engine

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/pridhvi/nyx/internal/models"
)

func NewInitialTarget(sessionID, targetInput string) models.Target {
	host, port, protocol := ParseTargetInput(targetInput)
	return models.Target{
		ID:           models.NewID(),
		SessionID:    sessionID,
		Host:         host,
		Port:         port,
		Protocol:     protocol,
		IsAlive:      false,
		DiscoveredBy: "user",
		CreatedAt:    time.Now().UTC(),
	}
}

func SplitTargetList(value string) []string {
	fields := strings.FieldsFunc(value, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t'
	})
	out := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" || seen[field] {
			continue
		}
		seen[field] = true
		out = append(out, field)
	}
	return out
}

func ValidateTargetInput(targetInput string) error {
	raw := strings.TrimSpace(targetInput)
	if raw == "" {
		return fmt.Errorf("target is required")
	}
	if strings.ContainsAny(raw, "\x00 ") {
		return fmt.Errorf("target %q contains unsupported whitespace", raw)
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Hostname() == "" {
			return fmt.Errorf("target %q is not a valid URL", raw)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("target %q must use http or https", raw)
		}
		return nil
	}
	host, _, protocol := ParseTargetInput(raw)
	if host == "" || protocol == "" {
		return fmt.Errorf("target %q is not valid", raw)
	}
	return nil
}

func ParseTargetInput(targetInput string) (host string, port int, protocol string) {
	protocol = "https"
	raw := strings.TrimSpace(targetInput)
	if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
		raw = parsed.Host
		if parsed.Scheme != "" {
			protocol = parsed.Scheme
		}
	}
	if splitHost, splitPort, err := net.SplitHostPort(raw); err == nil {
		raw = splitHost
		if p, err := strconv.Atoi(splitPort); err == nil {
			port = p
		}
	}
	if port == 0 {
		switch protocol {
		case "http":
			port = 80
		case "https":
			port = 443
		}
	}
	return strings.Trim(strings.ToLower(raw), "[]"), port, protocol
}
