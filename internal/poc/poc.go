package poc

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
)

type RunRequest struct {
	PoCType   string `json:"poc_type"`
	PayloadID string `json:"payload_id"`
	Confirm   bool   `json:"confirm"`
}

func Run(ctx context.Context, store *db.Store, sessionID, findingID string, req RunRequest) (models.PoCResult, error) {
	if !req.Confirm {
		return models.PoCResult{}, fmt.Errorf("poc run requires confirm=true")
	}
	finding, err := store.GetFinding(ctx, sessionID, findingID)
	if err != nil {
		return models.PoCResult{}, err
	}
	now := time.Now().UTC()
	completed := now
	pocType := strings.TrimSpace(req.PoCType)
	if pocType == "" {
		pocType = inferType(finding)
	}
	result := models.PoCResult{
		ID:              models.NewID(),
		SessionID:       sessionID,
		FindingID:       findingID,
		TargetID:        finding.TargetID,
		PoCType:         pocType,
		Status:          models.PoCStatusInconclusive,
		PayloadID:       strings.TrimSpace(req.PayloadID),
		Evidence:        "Safe PoC request recorded. Automatic active exploitation is disabled for this finding type in the current slice.",
		ImpactNarrative: "Manual validation is required before treating this finding as proven impact.",
		CreatedAt:       now,
		CompletedAt:     &completed,
	}
	text := strings.ToLower(finding.Title + " " + finding.Description)
	if strings.Contains(text, "reflected") || strings.Contains(text, "open redirect") {
		result.Evidence = "Finding is eligible for safe manual validation; no request was sent by the default PoC recorder."
	}
	if err := store.InsertPoCResult(ctx, result); err != nil {
		return models.PoCResult{}, err
	}
	return result, nil
}

func inferType(finding models.Finding) string {
	text := strings.ToLower(finding.Title + " " + finding.Description)
	for _, candidate := range []string{"xss", "sqli", "ssrf", "ssti", "xxe", "redirect"} {
		if strings.Contains(text, candidate) {
			return candidate
		}
	}
	return "manual"
}
