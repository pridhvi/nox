package adapters

import (
	"strings"
	"testing"

	"github.com/pridhvi/nyx/internal/models"
)

func TestParseStaticOutputToolSpecificFindings(t *testing.T) {
	input := StaticAdapterInput{SessionID: "session-1"}
	cases := []struct {
		tool string
		raw  string
		want string
	}{
		{"semgrep", `{"results":[{"path":"app.py","check_id":"python.sql","start":{"line":7},"extra":{"message":"SQL injection","severity":"ERROR"}}]}`, "app.py"},
		{"bandit", `{"results":[{"filename":"app.py","line_number":3,"issue_text":"hardcoded password","issue_severity":"HIGH"}]}`, "app.py"},
		{"gosec", `{"Issues":[{"file":"main.go","line":"9","details":"G401 weak crypto","severity":"MEDIUM"}]}`, "main.go"},
		{"brakeman", `{"warnings":[{"file":"app/controllers/users_controller.rb","line":12,"message":"SQL Injection","confidence":1}]}`, "users_controller.rb"},
		{"psalm", `[{"file_path":"src/App.php","line_from":4,"message":"Tainted input","severity":"error"}]`, "src/App.php"},
		{"trufflehog", `{"DetectorName":"AWS","SourceMetadata":{"Data":{"Filesystem":{"file":"secrets.txt"}}},"StartLine":2}`, "secrets.txt"},
		{"gitleaks", `[{"RuleID":"generic-api-key","File":"config.js","StartLine":2}]`, "config.js"},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			findings, _ := parseStaticOutput(input, tc.tool, tc.raw)
			if len(findings) == 0 {
				t.Fatalf("expected finding for %s", tc.tool)
			}
			if !strings.Contains(findings[0].URL, tc.want) || !strings.HasPrefix(findings[0].ToolID, "audit/") {
				t.Fatalf("unexpected finding: %#v", findings[0])
			}
		})
	}
}

func TestParseStaticOutputDependencyCVEs(t *testing.T) {
	input := StaticAdapterInput{SessionID: "session-1"}
	cases := []struct {
		tool    string
		raw     string
		pkg     string
		version string
	}{
		{"npm-audit", `{"vulnerabilities":{"lodash":{"range":"<4.17.21","via":[{"source":"CVE-2021-23337","title":"Command Injection"}]}}}`, "lodash", "<4.17.21"},
		{"grype", `{"matches":[{"vulnerability":{"id":"CVE-2024-0001","description":"demo","cvss":[{"baseScore":9.8}],"fix":{"versions":["1.2.3"]}},"artifact":{"name":"openssl","version":"1.0.0"}}]}`, "openssl", "1.0.0"},
		{"safety", `[{"vulnerability_id":"CVE-2023-1234","package":"django","installed_version":"3.0","advisory":"demo"}]`, "django", "3.0"},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			_, cves := parseStaticOutput(input, tc.tool, tc.raw)
			if len(cves) == 0 {
				t.Fatalf("expected cve for %s", tc.tool)
			}
			if cves[0].SessionID != input.SessionID || cves[0].PackageName != tc.pkg || cves[0].PackageVersion != tc.version || cves[0].Source != "audit/"+tc.tool {
				t.Fatalf("unexpected cve: %#v", cves[0])
			}
		})
	}
}

func TestSourceFindingToAuditFindingUsesAuditToolID(t *testing.T) {
	finding := sourceFindingToAuditFinding("s1", "authmiddleware", models.SeverityMedium, models.SourceFinding{
		Kind:       models.SourceKindUnprotectedRoute,
		FilePath:   "app.py",
		LineNumber: 10,
		Value:      "/admin",
	})
	if finding.ToolID != "audit/authmiddleware" || !strings.Contains(finding.URL, "app.py") {
		t.Fatalf("unexpected audit finding: %#v", finding)
	}
}
