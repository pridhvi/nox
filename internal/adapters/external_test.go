package adapters

import (
	"testing"
	"time"

	"github.com/kanini/nox/internal/models"
)

func testExternalInput() AdapterInput {
	session := models.Session{
		ID:          "session-1",
		Mode:        models.ScanModeActive,
		TargetInput: "https://example.com/search?q=test",
		CreatedAt:   time.Now().UTC(),
	}
	return AdapterInput{
		SessionID: session.ID,
		Session:   session,
		Target: models.Target{
			ID:        "target-1",
			SessionID: session.ID,
			Host:      "example.com",
			Port:      443,
			Protocol:  "https",
			IsAlive:   true,
		},
	}
}

func TestParseNmapFindings(t *testing.T) {
	raw := `<nmaprun><host><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.25"/></port></ports></host></nmaprun>`
	findings := parseNmapFindings(testExternalInput(), raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "nmap" || findings[0].Type != models.FindingTypeExposure || findings[0].Severity != models.SeverityInfo {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
	if findings[0].EvidenceRaw == "" || findings[0].EvidenceNormalized == "" {
		t.Fatal("expected raw and normalized evidence")
	}
}

func TestParseFFUFFindings(t *testing.T) {
	raw := `{"results":[{"url":"https://example.com/admin","status":200,"length":42,"words":4,"lines":1}]}`
	findings := parseFFUFFindings(testExternalInput(), raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "ffuf" || findings[0].Severity != models.SeverityLow {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseSQLMapFindings(t *testing.T) {
	raw := `Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
q parameter is vulnerable.`
	findings := parseSQLMapFindings(testExternalInput(), raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "sqlmap" || findings[0].Parameter != "q" || findings[0].Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}

func TestParseDalfoxFindings(t *testing.T) {
	raw := `[{"type":"reflected","param":"q","payload":"<script>alert(1)</script>","poc":"https://example.com/search?q=%3Cscript%3E"}]`
	findings := parseDalfoxFindings(testExternalInput(), raw)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ToolID != "dalfox" || findings[0].Parameter != "q" || findings[0].Severity != models.SeverityHigh {
		t.Fatalf("unexpected finding: %#v", findings[0])
	}
}
