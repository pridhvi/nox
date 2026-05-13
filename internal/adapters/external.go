package adapters

import (
	"encoding/json"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kanini/nox/internal/models"
)

func activeOnly(input AdapterInput) bool {
	return input.Session.Mode == models.ScanModeActive
}

func targetBaseURL(target models.Target) string {
	return targetURL(target)
}

func sessionTargetURL(input AdapterInput) string {
	raw := strings.TrimSpace(input.Session.TargetInput)
	parsed, err := url.Parse(raw)
	if err == nil && parsed.Scheme != "" && parsed.Host != "" {
		return raw
	}
	return targetBaseURL(input.Target)
}

func sessionTargetHasQuery(input AdapterInput) bool {
	parsed, err := url.Parse(sessionTargetURL(input))
	return err == nil && parsed.RawQuery != ""
}

func newToolRun(input AdapterInput, toolID string, args []string) models.ToolRun {
	return models.ToolRun{
		ID:        models.NewID(),
		SessionID: input.Session.ID,
		TargetID:  input.Target.ID,
		ToolID:    toolID,
		Args:      args,
		StartedAt: time.Now().UTC(),
	}
}

func finishToolRun(run models.ToolRun, result CommandResult, findingCount int) models.ToolRun {
	run.StdoutRaw = result.Stdout
	run.StderrRaw = result.Stderr
	run.ExitCode = result.ExitCode
	run.DurationMS = result.DurationMS
	run.FindingCount = findingCount
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return run
}

func failedToolRun(input AdapterInput, toolID string, args []string, message string, exitCode int) models.ToolRun {
	run := newToolRun(input, toolID, args)
	run.StderrRaw = message
	run.ExitCode = exitCode
	run.DurationMS = time.Since(run.StartedAt).Milliseconds()
	now := time.Now().UTC()
	run.NormalizedAt = &now
	return run
}

func externalFinding(input AdapterInput, toolID string, findingType models.FindingType, severity models.Severity, title, description, remediation, rawEvidence string, normalized any, tags []string) models.Finding {
	normalizedBody, _ := json.Marshal(normalized)
	return models.Finding{
		ID:                 models.NewID(),
		SessionID:          input.Session.ID,
		TargetID:           input.Target.ID,
		ToolID:             toolID,
		Type:               findingType,
		Severity:           severity,
		Confidence:         0.8,
		Title:              title,
		Description:        description,
		Remediation:        remediation,
		URL:                sessionTargetURL(input),
		EvidenceRaw:        rawEvidence,
		EvidenceNormalized: string(normalizedBody),
		Tags:               tags,
		CreatedAt:          time.Now().UTC(),
	}
}

func commonWordlistPath() string {
	for _, path := range []string{
		"/usr/share/seclists/Discovery/Web-Content/common.txt",
		"/usr/share/wordlists/dirb/common.txt",
		"/usr/share/dirb/wordlists/common.txt",
		"/usr/local/share/seclists/Discovery/Web-Content/common.txt",
	} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}
