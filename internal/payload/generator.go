package payload

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
)

type GenerateOptions struct {
	Force bool
}

func Generate(ctx context.Context, store *db.Store, sessionID, findingID string, options GenerateOptions) ([]models.Payload, error) {
	finding, err := store.GetFinding(ctx, sessionID, findingID)
	if err != nil {
		return nil, err
	}
	if !options.Force {
		existing, err := store.ListPayloadsByFinding(ctx, sessionID, findingID)
		if err != nil {
			return nil, err
		}
		if len(existing) > 0 {
			return existing, nil
		}
	}
	if options.Force {
		if err := store.DeletePayloadsByFinding(ctx, sessionID, findingID); err != nil {
			return nil, err
		}
	}
	generated := deterministicPayloads(finding)
	if len(generated) == 0 {
		return nil, fmt.Errorf("finding %q is not a supported payload generation target", finding.ID)
	}
	now := time.Now().UTC()
	for i := range generated {
		generated[i].ID = models.NewID()
		generated[i].SessionID = sessionID
		generated[i].FindingID = findingID
		generated[i].Rank = i + 1
		generated[i].CreatedAt = now
		if err := store.InsertPayload(ctx, generated[i]); err != nil {
			return nil, err
		}
	}
	return store.ListPayloadsByFinding(ctx, sessionID, findingID)
}

func deterministicPayloads(finding models.Finding) []models.Payload {
	text := strings.ToLower(strings.Join([]string{finding.Title, finding.Description, string(finding.Type), finding.ToolID, finding.Parameter, finding.URL}, " "))
	switch {
	case strings.Contains(text, "xss") || strings.Contains(text, "script") || strings.Contains(text, "reflected"):
		return []models.Payload{
			{PayloadType: "xss", Payload: `"><script>confirm("nox")</script>`, Context: "Reflected marker payload; generation is advisory and not sent automatically.", BypassTechnique: "quote-breakout", Confidence: 0.62},
			{PayloadType: "xss", Payload: `<img src=x onerror=confirm("nox")>`, Context: "Event-handler marker payload for manual validation.", BypassTechnique: "event-handler", Confidence: 0.56},
		}
	case strings.Contains(text, "sql") || strings.Contains(text, "sqli"):
		return []models.Payload{
			{PayloadType: "sqli", Payload: `' OR '1'='1' --`, Context: "Boolean SQL injection probe; use only with explicit authorization.", BypassTechnique: "boolean-tautology", Confidence: 0.58},
			{PayloadType: "sqli", Payload: `' AND 1=2 UNION SELECT NULL --`, Context: "Union-shape probe for manual testing.", BypassTechnique: "union-probe", Confidence: 0.42},
		}
	case strings.Contains(text, "ssrf"):
		return []models.Payload{{PayloadType: "ssrf", Payload: `http://127.0.0.1:9/nox-canary`, Context: "Local-only canary URL placeholder; external callback support is separate.", BypassTechnique: "loopback-canary", Confidence: 0.35}}
	case strings.Contains(text, "ssti") || strings.Contains(text, "template"):
		return []models.Payload{{PayloadType: "ssti", Payload: `{{7*7}}`, Context: "Harmless arithmetic marker for manual SSTI validation.", BypassTechnique: "arithmetic-marker", Confidence: 0.54}}
	case strings.Contains(text, "xxe"):
		return []models.Payload{{PayloadType: "xxe", Payload: `<!DOCTYPE x [<!ENTITY nox "nox">]>`, Context: "Non-exfiltrating entity marker.", BypassTechnique: "entity-marker", Confidence: 0.31}}
	case strings.Contains(text, "redirect"):
		return []models.Payload{{PayloadType: "open_redirect", Payload: `https://example.com/nox-redirect-marker`, Context: "Benign external redirect marker.", BypassTechnique: "absolute-url", Confidence: 0.5}}
	case strings.Contains(text, "command") || strings.Contains(text, "rce"):
		return []models.Payload{{PayloadType: "cmd_injection", Payload: `; echo nox-marker`, Context: "Harmless echo marker; not automatically verifiable.", BypassTechnique: "shell-separator", Confidence: 0.28}}
	default:
		return nil
	}
}
