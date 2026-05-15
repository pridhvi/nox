package db

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pridhvi/nox/internal/models"
	_ "modernc.org/sqlite"
)

func TestMigrationCreatesExpectedTables(t *testing.T) {
	ctx := context.Background()
	store, err := Open(ctx, filepath.Join(t.TempDir(), "session.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, table := range []string{
		"sessions",
		"targets",
		"findings",
		"http_evidence",
		"tool_runs",
		"technologies",
		"cve_matches",
		"attack_vectors",
		"llm_analyses",
		"plugins",
		"schema_migrations",
	} {
		var name string
		err := store.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("expected table %s: %v", table, err)
		}
	}
	for _, version := range []string{"001_initial", "002_phase2_persistence", "003_operator_console"} {
		var got string
		if err := store.db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = ?`, version).Scan(&got); err != nil {
			t.Fatalf("expected migration %s: %v", version, err)
		}
	}
}

func TestDefaultSessionsDirIsAbsoluteStatePath(t *testing.T) {
	dir := DefaultSessionsDir()
	if !filepath.IsAbs(dir) {
		t.Fatalf("expected absolute default sessions dir, got %q", dir)
	}
	if filepath.Base(dir) != "sessions" || filepath.Base(filepath.Dir(dir)) != ".nox" {
		t.Fatalf("expected $HOME/.nox/sessions style path, got %q", dir)
	}
}

func TestCreateListShowDeleteSessionLifecycle(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	session := models.Session{
		ID:           models.NewID(),
		Name:         "Example",
		Status:       models.SessionStatusPending,
		Mode:         models.ScanModeActive,
		TargetInput:  "https://example.com",
		InScope:      []string{"https://example.com"},
		EnabledTools: []string{"http-probe", "ffuf"},
		ToolParameters: map[string]map[string]any{
			"ffuf": {"wordlist": "/tmp/words.txt"},
		},
		RunnerOptions: models.ScanRunnerOptions{Concurrency: 2, PerToolConcurrency: 1, ToolTimeoutSeconds: 30, ToolDelayMS: 50, RateLimit: "gentle"},
		CreatedAt:     time.Now().UTC(),
	}
	target := testTarget(session.ID, "example.com", 443, "https")
	record, err := CreateSessionDB(ctx, dir, session, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record.DBPath); err != nil {
		t.Fatal(err)
	}

	records, err := ListSessions(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 session, got %d", len(records))
	}
	if records[0].Session.TargetCount != 1 {
		t.Fatalf("expected target count 1, got %d", records[0].Session.TargetCount)
	}

	store, err := OpenSession(ctx, dir, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, err := store.GetSession(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != session.ID || got.TargetInput != session.TargetInput {
		t.Fatalf("unexpected session: %#v", got)
	}
	if len(got.EnabledTools) != 2 || got.EnabledTools[1] != "ffuf" {
		t.Fatalf("expected enabled tools to round-trip, got %#v", got.EnabledTools)
	}
	if got.ToolParameters["ffuf"]["wordlist"] != "/tmp/words.txt" {
		t.Fatalf("expected tool parameters to round-trip, got %#v", got.ToolParameters)
	}
	if got.RunnerOptions.Concurrency != 2 || got.RunnerOptions.RateLimit != "gentle" {
		t.Fatalf("expected runner options to round-trip, got %#v", got.RunnerOptions)
	}
	targets, err := store.ListTargets(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Host != "example.com" || targets[0].Port != 443 {
		t.Fatalf("unexpected targets: %#v", targets)
	}
	store.Close()

	if err := DeleteSession(ctx, dir, session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(record.DBPath); !os.IsNotExist(err) {
		t.Fatalf("expected deleted db, got err %v", err)
	}
}

func TestListSessionsSkipsNonSessionFiles(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.db"), []byte("not sqlite"), 0o644); err != nil {
		t.Fatal(err)
	}
	session := models.Session{
		ID:          models.NewID(),
		Status:      models.SessionStatusPending,
		Mode:        models.ScanModeActive,
		TargetInput: "example.org",
		InScope:     []string{"example.org"},
		CreatedAt:   time.Now().UTC(),
	}
	target := testTarget(session.ID, "example.org", 443, "https")
	if _, err := CreateSessionDB(ctx, dir, session, target); err != nil {
		t.Fatal(err)
	}
	records, err := ListSessions(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Session.ID != session.ID {
		t.Fatalf("unexpected records: %#v", records)
	}
}

func TestPhase2PersistenceRoundTrips(t *testing.T) {
	ctx := context.Background()
	session, target, store := createTestStore(t, ctx)

	technology := models.Technology{
		ID:         models.NewID(),
		TargetID:   target.ID,
		Name:       "nginx",
		Version:    "1.25.0",
		Category:   "server",
		Confidence: 0.86,
		SourceTool: "whatweb",
	}
	if err := store.InsertTechnology(ctx, technology); err != nil {
		t.Fatal(err)
	}

	finding := models.Finding{
		ID:                 models.NewID(),
		SessionID:          session.ID,
		TargetID:           target.ID,
		ToolID:             "sqlmap",
		Type:               models.FindingTypeVulnerability,
		Severity:           models.SeverityHigh,
		Confidence:         0.9,
		CVSSScore:          8.1,
		Title:              "SQL injection",
		Description:        "Injected parameter accepted a boolean payload.",
		Remediation:        "Use parameterized queries.",
		URL:                "https://example.com/search?q=1",
		Parameter:          "q",
		Method:             "GET",
		EvidenceRaw:        "sqlmap evidence",
		EvidenceNormalized: `{"parameter":"q"}`,
		Tags:               []string{"owasp:A03", "cwe:89"},
		HTTPEvidence: &models.HTTPEvidence{
			RequestRaw:   "GET /search?q=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
			ResponseRaw:  "HTTP/1.1 200 OK\r\n\r\nok",
			StatusCode:   200,
			ResponseTime: 123,
		},
		CVEMatches: []models.CVEMatch{{
			ID:               models.NewID(),
			CVEID:            "CVE-2024-0001",
			CVSSv3Score:      7.5,
			CVSSv3Vector:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			Description:      "Example CVE",
			AffectedVersion:  "1.25.0",
			FixedVersion:     "1.25.1",
			PatchAvailable:   true,
			ExploitAvailable: false,
			References:       []string{"https://example.com/cve"},
			Source:           "nvd",
			ConfidenceScore:  0.77,
		}},
		CreatedAt: time.Now().UTC(),
	}
	if err := store.InsertFinding(ctx, finding); err != nil {
		t.Fatal(err)
	}

	techCVE := models.CVEMatch{
		ID:               models.NewID(),
		TechnologyID:     technology.ID,
		CVEID:            "CVE-2024-0002",
		CVSSv3Score:      9.8,
		Description:      "Technology CVE",
		AffectedVersion:  "1.25.0",
		FixedVersion:     "1.25.2",
		PatchAvailable:   true,
		ExploitAvailable: true,
		References:       []string{"https://example.com/tech-cve"},
		Source:           "nvd",
		ConfidenceScore:  0.88,
	}
	if err := store.InsertCVEMatch(ctx, techCVE); err != nil {
		t.Fatal(err)
	}

	targets, err := store.ListTargets(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || len(targets[0].Technologies) != 1 || targets[0].Technologies[0].Name != "nginx" {
		t.Fatalf("unexpected targets with technologies: %#v", targets)
	}

	findings, err := store.ListFindings(ctx, session.ID, FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].HTTPEvidence == nil || findings[0].HTTPEvidence.StatusCode != 200 {
		t.Fatalf("expected finding with HTTP evidence, got %#v", findings)
	}
	if len(findings[0].CVEMatches) != 1 || findings[0].CVEMatches[0].FixedVersion != "1.25.1" {
		t.Fatalf("expected finding CVE match, got %#v", findings[0].CVEMatches)
	}

	sessionCVEs, err := store.ListCVEMatchesBySession(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessionCVEs) != 2 {
		t.Fatalf("expected 2 session CVEs, got %#v", sessionCVEs)
	}
}

func TestAttackVectorLLMAndPluginPersistenceRoundTrips(t *testing.T) {
	ctx := context.Background()
	session, _, store := createTestStore(t, ctx)

	vector := models.AttackVector{
		ID:               models.NewID(),
		SessionID:        session.ID,
		Title:            "Exploit injection",
		Description:      "SQL injection can expose data.",
		Narrative:        "An attacker abuses the injectable parameter.",
		OWASPCategory:    "A03:2021 - Injection",
		Severity:         models.SeverityCritical,
		Confidence:       0.82,
		PrereqFindingIDs: []string{"finding-1"},
		LLMReviewed:      true,
		LLMNotes:         "Narrative only.",
		CreatedAt:        time.Now().UTC(),
		Steps: []models.AttackStep{{
			Order:         1,
			Description:   "Exploit injectable search parameter.",
			FindingID:     "finding-1",
			ToolSuggested: "sqlmap --level 5",
		}},
	}
	if err := store.InsertAttackVector(ctx, vector); err != nil {
		t.Fatal(err)
	}
	vectors, err := store.ListAttackVectors(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 1 || len(vectors[0].Steps) != 1 || vectors[0].Steps[0].ToolSuggested == "" {
		t.Fatalf("unexpected vectors: %#v", vectors)
	}

	analysis := models.LLMAnalysis{
		ID:            models.NewID(),
		SessionID:     session.ID,
		ModelID:       "llama3:8b",
		PromptSummary: "Summarize injection risk.",
		Messages: []models.LLMMessage{{
			Role:    "assistant",
			Content: "Use parameterized queries.",
			ToolCalls: []models.LLMToolCall{{
				ID:        "call-1",
				Name:      "lookup_cve",
				Arguments: `{"technology":"nginx"}`,
				Result:    "[]",
			}},
		}},
		TotalTokens: 42,
		CreatedAt:   time.Now().UTC(),
	}
	if err := store.InsertLLMAnalysis(ctx, analysis); err != nil {
		t.Fatal(err)
	}
	analyses, err := store.ListLLMAnalyses(ctx, session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(analyses) != 1 || analyses[0].Messages[0].ToolCalls[0].Name != "lookup_cve" {
		t.Fatalf("unexpected analyses: %#v", analyses)
	}

	plugin := models.PluginRecord{
		ID:        models.NewID(),
		Name:      "custom-scanner",
		Binary:    "/opt/nox/custom-scanner",
		Enabled:   true,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.UpsertPlugin(ctx, plugin); err != nil {
		t.Fatal(err)
	}
	plugin.Binary = "/opt/nox/custom-scanner-v2"
	plugin.UpdatedAt = plugin.UpdatedAt.Add(time.Minute)
	if err := store.UpsertPlugin(ctx, plugin); err != nil {
		t.Fatal(err)
	}
	plugins, err := store.ListPlugins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plugins) != 1 || plugins[0].Binary != "/opt/nox/custom-scanner-v2" {
		t.Fatalf("unexpected plugins: %#v", plugins)
	}
	if err := store.DeletePlugin(ctx, plugin.Name); err != nil {
		t.Fatal(err)
	}
	plugins, err = store.ListPlugins(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plugins) != 0 {
		t.Fatalf("expected plugin delete, got %#v", plugins)
	}
}

func TestExistingInitialDatabaseMigratesToPhase2(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "session.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `CREATE TABLE schema_migrations (version TEXT PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	body, err := migrationFS.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, string(body)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO schema_migrations (version, applied_at) VALUES ('001_initial', ?)`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, column := range []string{"affected_version", "fixed_version"} {
		var name string
		if err := store.db.QueryRowContext(ctx, `SELECT name FROM pragma_table_info('cve_matches') WHERE name = ?`, column).Scan(&name); err != nil {
			t.Fatalf("expected cve_matches.%s after migration: %v", column, err)
		}
	}
	var pluginTable string
	if err := store.db.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'plugins'`).Scan(&pluginTable); err != nil {
		t.Fatalf("expected plugins table after migration: %v", err)
	}
	for _, expected := range []string{"002_phase2_persistence", "003_operator_console"} {
		var version string
		if err := store.db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = ?`, expected).Scan(&version); err != nil {
			t.Fatalf("expected %s migration record: %v", expected, err)
		}
	}
}

func testTarget(sessionID, host string, port int, protocol string) models.Target {
	return models.Target{
		ID:           models.NewID(),
		SessionID:    sessionID,
		Host:         host,
		Port:         port,
		Protocol:     protocol,
		DiscoveredBy: "user",
		CreatedAt:    time.Now().UTC(),
	}
}

func createTestStore(t *testing.T, ctx context.Context) (models.Session, models.Target, *Store) {
	t.Helper()
	session := models.Session{
		ID:          models.NewID(),
		Name:        "Example",
		Status:      models.SessionStatusPending,
		Mode:        models.ScanModeActive,
		TargetInput: "https://example.com",
		InScope:     []string{"https://example.com"},
		CreatedAt:   time.Now().UTC(),
	}
	target := testTarget(session.ID, "example.com", 443, "https")
	record, err := CreateSessionDB(ctx, t.TempDir(), session, target)
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenSession(ctx, filepath.Dir(record.DBPath), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		store.Close()
	})
	return session, target, store
}
