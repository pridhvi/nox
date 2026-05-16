package burp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/models"
)

type issuesXML struct {
	Issues []issueXML `xml:"issue"`
}

type issueXML struct {
	Host       string `xml:"host"`
	Path       string `xml:"path"`
	Location   string `xml:"location"`
	Name       string `xml:"name"`
	Severity   string `xml:"severity"`
	Confidence string `xml:"confidence"`
	IssueType  string `xml:"type"`
	Request    string `xml:"requestresponse>request"`
	Response   string `xml:"requestresponse>response"`
}

func ImportXML(ctx context.Context, store *db.Store, session models.Session, raw []byte) (models.BurpImportResult, error) {
	var parsed issuesXML
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		return models.BurpImportResult{}, err
	}
	now := time.Now().UTC()
	var result models.BurpImportResult
	for _, issue := range parsed.Issues {
		host := strings.TrimSpace(issue.Host)
		if host == "" {
			continue
		}
		target := models.Target{
			ID:           models.NewID(),
			SessionID:    session.ID,
			Host:         strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://"),
			Port:         443,
			Protocol:     "https",
			IsAlive:      true,
			DiscoveredBy: "burp-import",
			CreatedAt:    now,
		}
		if strings.HasPrefix(host, "http://") {
			target.Protocol = "http"
			target.Port = 80
		}
		if err := store.InsertTarget(ctx, target); err != nil {
			return result, err
		}
		result.TargetsImported++
		finding := models.Finding{
			ID:          models.NewID(),
			SessionID:   session.ID,
			TargetID:    target.ID,
			ToolID:      "burp",
			Type:        models.FindingTypeVulnerability,
			Severity:    mapSeverity(issue.Severity),
			Confidence:  mapConfidence(issue.Confidence),
			Title:       firstNonEmpty(issue.Name, issue.IssueType, "Burp issue"),
			Description: "Imported from Burp XML.",
			URL:         firstNonEmpty(issue.Location, host+issue.Path),
			EvidenceRaw: truncate(decodeMaybe(issue.Request)+"\n\n"+decodeMaybe(issue.Response), 4000),
			Tags:        []string{"burp"},
			CreatedAt:   now,
		}
		if request, response := decodeMaybe(issue.Request), decodeMaybe(issue.Response); request != "" || response != "" {
			finding.HTTPEvidence = &models.HTTPEvidence{RequestRaw: truncate(request, 8000), ResponseRaw: truncate(response, 8000)}
			result.EvidenceImported++
		}
		if err := store.InsertFinding(ctx, finding); err != nil {
			return result, err
		}
		result.FindingsImported++
	}
	_ = store.UpdateSessionCounts(ctx, session.ID)
	return result, nil
}

func ExportScope(ctx context.Context, store *db.Store, sessionID string) ([]byte, error) {
	targets, err := store.ListTargets(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?><scope>`)
	for _, target := range targets {
		fmt.Fprintf(&buf, `<url>%s://%s:%d</url>`, html.EscapeString(target.Protocol), html.EscapeString(target.Host), target.Port)
	}
	buf.WriteString(`</scope>`)
	return buf.Bytes(), nil
}

func ExportFindings(ctx context.Context, store *db.Store, sessionID string) ([]byte, error) {
	findings, err := store.ListFindings(ctx, sessionID, db.FindingFilter{})
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?><issues>`)
	for _, finding := range findings {
		fmt.Fprintf(&buf, `<issue><name>%s</name><severity>%s</severity><confidence>Firm</confidence><host>%s</host><path>%s</path><location>%s</location></issue>`,
			html.EscapeString(finding.Title), html.EscapeString(string(finding.Severity)), html.EscapeString(finding.URL), "", html.EscapeString(finding.URL))
	}
	buf.WriteString(`</issues>`)
	return buf.Bytes(), nil
}

func ReadAll(reader io.Reader) ([]byte, error) {
	return io.ReadAll(reader)
}

func mapSeverity(value string) models.Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	case "information", "info":
		return models.SeverityInfo
	default:
		return models.SeverityMedium
	}
}

func mapConfidence(value string) float64 {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "certain":
		return 1
	case "firm":
		return 0.8
	case "tentative":
		return 0.45
	default:
		return 0.6
	}
}

func decodeMaybe(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return string(decoded)
	}
	return value
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "\n...[truncated]"
}
