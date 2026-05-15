package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kanini/nox/internal/db"
	"github.com/kanini/nox/internal/engine"
	"github.com/kanini/nox/internal/models"
)

func TestSessionAPI(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>Nox Test</title>"))
	}))
	defer targetServer.Close()

	server := NewServer(Config{SessionDir: t.TempDir(), HTTPClient: targetServer.Client()})
	handler := server.Handler()

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("health status = %d", health.Code)
	}

	body := bytes.NewBufferString(`{"target":"` + targetServer.URL + `","name":"Example","mode":"active","out_of_scope":["admin.example.com"]}`)
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, httptest.NewRequest(http.MethodPost, "/api/scan/start", body))
	if start.Code != http.StatusAccepted {
		t.Fatalf("start status = %d body=%s", start.Code, start.Body.String())
	}
	var created db.SessionRecord
	if err := json.NewDecoder(start.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Session.ID == "" || created.Session.TargetInput != targetServer.URL || created.Session.Status != "pending" {
		t.Fatalf("unexpected created session: %#v", created.Session)
	}
	waitForCompletedScan(t, handler, created.Session.ID)

	list := httptest.NewRecorder()
	handler.ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/api/sessions", nil))
	if list.Code != http.StatusOK {
		t.Fatalf("list status = %d", list.Code)
	}
	var sessions []db.SessionRecord
	if err := json.NewDecoder(list.Body).Decode(&sessions); err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].Session.ID != created.Session.ID {
		t.Fatalf("unexpected sessions: %#v", sessions)
	}

	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID, nil))
	if get.Code != http.StatusOK {
		t.Fatalf("get status = %d", get.Code)
	}

	targets := httptest.NewRecorder()
	handler.ServeHTTP(targets, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/targets", nil))
	if targets.Code != http.StatusOK {
		t.Fatalf("targets status = %d", targets.Code)
	}

	status := httptest.NewRecorder()
	handler.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/scan/"+created.Session.ID+"/status", nil))
	if status.Code != http.StatusOK {
		t.Fatalf("scan status = %d", status.Code)
	}

	findings := httptest.NewRecorder()
	handler.ServeHTTP(findings, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/findings", nil))
	if findings.Code != http.StatusOK {
		t.Fatalf("findings status = %d", findings.Code)
	}
	var decodedFindings []models.Finding
	if err := json.NewDecoder(findings.Body).Decode(&decodedFindings); err != nil {
		t.Fatal(err)
	}
	if len(decodedFindings) == 0 {
		t.Fatal("expected security header findings")
	}

	runs := httptest.NewRecorder()
	handler.ServeHTTP(runs, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/tool-runs", nil))
	if runs.Code != http.StatusOK {
		t.Fatalf("tool runs status = %d", runs.Code)
	}
	var decodedRuns []models.ToolRun
	if err := json.NewDecoder(runs.Body).Decode(&decodedRuns); err != nil {
		t.Fatal(err)
	}
	runIDs := map[string]bool{}
	for _, run := range decodedRuns {
		runIDs[run.ToolID] = true
	}
	for _, toolID := range []string{"http-probe", "security-headers", "nmap", "ffuf"} {
		if !runIDs[toolID] {
			t.Fatalf("expected tool run %s in %#v", toolID, runIDs)
		}
	}

	stats := httptest.NewRecorder()
	handler.ServeHTTP(stats, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/stats", nil))
	if stats.Code != http.StatusOK {
		t.Fatalf("stats status = %d", stats.Code)
	}

	vectors := httptest.NewRecorder()
	handler.ServeHTTP(vectors, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/vectors", nil))
	if vectors.Code != http.StatusOK {
		t.Fatalf("vectors status = %d", vectors.Code)
	}

	cves := httptest.NewRecorder()
	handler.ServeHTTP(cves, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/cves", nil))
	if cves.Code != http.StatusOK {
		t.Fatalf("cves status = %d", cves.Code)
	}

	report := httptest.NewRecorder()
	handler.ServeHTTP(report, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/report?format=md&mode=technical", nil))
	if report.Code != http.StatusOK || !strings.Contains(report.Body.String(), "Executive Summary") {
		t.Fatalf("report status = %d body=%s", report.Code, report.Body.String())
	}

	history := httptest.NewRecorder()
	handler.ServeHTTP(history, httptest.NewRequest(http.MethodGet, "/api/sessions/"+created.Session.ID+"/llm/history", nil))
	if history.Code != http.StatusOK {
		t.Fatalf("llm history status = %d", history.Code)
	}

	analyse := httptest.NewRecorder()
	handler.ServeHTTP(analyse, httptest.NewRequest(http.MethodPost, "/api/sessions/"+created.Session.ID+"/llm/analyse", nil))
	if analyse.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected unavailable llm status, got %d", analyse.Code)
	}

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/api/sessions/not-found", nil))
	if missing.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", missing.Code)
	}

	deleted := httptest.NewRecorder()
	handler.ServeHTTP(deleted, httptest.NewRequest(http.MethodDelete, "/api/sessions/"+created.Session.ID, nil))
	if deleted.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", deleted.Code, deleted.Body.String())
	}
}

func TestAPIKeyAuth(t *testing.T) {
	handler := NewServer(Config{SessionDir: t.TempDir(), APIKey: "secret"}).Handler()
	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, "/api/health", nil))
	if blocked.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", blocked.Code)
	}
	allowed := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	req.Header.Set("X-Nox-API-Key", "secret")
	handler.ServeHTTP(allowed, req)
	if allowed.Code != http.StatusOK {
		t.Fatalf("expected authorized health, got %d", allowed.Code)
	}
}

func TestOperatorConsoleAPI(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":[{"id":"llama3:8b"},{"id":"codellama"}]}`))
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer targetServer.Close()
	handler := NewServer(Config{SessionDir: t.TempDir(), HTTPClient: targetServer.Client()}).Handler()

	tools := httptest.NewRecorder()
	handler.ServeHTTP(tools, httptest.NewRequest(http.MethodGet, "/api/tools", nil))
	if tools.Code != http.StatusOK {
		t.Fatalf("tools status = %d body=%s", tools.Code, tools.Body.String())
	}
	var records []toolRecord
	if err := json.NewDecoder(tools.Body).Decode(&records); err != nil {
		t.Fatal(err)
	}
	foundFFUF := false
	for _, record := range records {
		if record.ID == "ffuf" {
			foundFFUF = len(record.Parameters) > 0 && record.Kind == "subprocess"
		}
	}
	if !foundFFUF {
		t.Fatalf("expected ffuf tool metadata, got %#v", records)
	}

	body := bytes.NewBufferString(`{"target":"` + targetServer.URL + `","mode":"active","tools":["http-probe"],"tool_parameters":{"ffuf":{"wordlist":"/tmp/words.txt"}},"concurrency":2,"per_tool_concurrency":1,"tool_timeout_seconds":15,"tool_delay_ms":25,"rate_limit":"gentle"}`)
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, httptest.NewRequest(http.MethodPost, "/api/scan/start", body))
	if start.Code != http.StatusAccepted {
		t.Fatalf("start status = %d body=%s", start.Code, start.Body.String())
	}
	var created db.SessionRecord
	if err := json.NewDecoder(start.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if len(created.Session.EnabledTools) != 1 || created.Session.EnabledTools[0] != "http-probe" {
		t.Fatalf("expected enabled tools in response, got %#v", created.Session.EnabledTools)
	}
	if created.Session.ToolParameters["ffuf"]["wordlist"] != "/tmp/words.txt" {
		t.Fatalf("expected tool parameters in response, got %#v", created.Session.ToolParameters)
	}
	if created.Session.RunnerOptions.ToolTimeoutSeconds != 15 || created.Session.RunnerOptions.RateLimit != "gentle" {
		t.Fatalf("expected runner options in response, got %#v", created.Session.RunnerOptions)
	}
	waitForCompletedScan(t, handler, created.Session.ID)

	bad := httptest.NewRecorder()
	handler.ServeHTTP(bad, httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"target":"`+targetServer.URL+`","mode":"active","tools":["missing-tool"]}`)))
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for unknown tool, got %d", bad.Code)
	}

	unsafeArgs := httptest.NewRecorder()
	handler.ServeHTTP(unsafeArgs, httptest.NewRequest(http.MethodPost, "/api/scan/start", bytes.NewBufferString(`{"target":"`+targetServer.URL+`","mode":"active","tools":["ffuf"],"tool_parameters":{"ffuf":{"extra_args":["--output","/tmp/leak"]}}}`)))
	if unsafeArgs.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for unsafe extra args, got %d", unsafeArgs.Code)
	}

	profileBody := bytes.NewBufferString(`{"name":"Web active","description":"Saved","request":{"target":"","mode":"active","tools":["http-probe"],"enabled_phases":["fingerprint"]}}`)
	profileCreate := httptest.NewRecorder()
	handler.ServeHTTP(profileCreate, httptest.NewRequest(http.MethodPost, "/api/scan-profiles", profileBody))
	if profileCreate.Code != http.StatusCreated {
		t.Fatalf("profile create status = %d body=%s", profileCreate.Code, profileCreate.Body.String())
	}
	var profile scanProfileRecord
	if err := json.NewDecoder(profileCreate.Body).Decode(&profile); err != nil {
		t.Fatal(err)
	}
	profileList := httptest.NewRecorder()
	handler.ServeHTTP(profileList, httptest.NewRequest(http.MethodGet, "/api/scan-profiles", nil))
	if profileList.Code != http.StatusOK || !strings.Contains(profileList.Body.String(), profile.ID) {
		t.Fatalf("profile list status = %d body=%s", profileList.Code, profileList.Body.String())
	}
	profileDelete := httptest.NewRecorder()
	handler.ServeHTTP(profileDelete, httptest.NewRequest(http.MethodDelete, "/api/scan-profiles/"+profile.ID, nil))
	if profileDelete.Code != http.StatusOK {
		t.Fatalf("profile delete status = %d body=%s", profileDelete.Code, profileDelete.Body.String())
	}

	badPlugin := httptest.NewRecorder()
	handler.ServeHTTP(badPlugin, httptest.NewRequest(http.MethodPost, "/api/sessions/"+created.Session.ID+"/plugins", bytes.NewBufferString(`{"binary":"definitely-not-a-real-plugin-binary"}`)))
	if badPlugin.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for missing plugin binary, got %d", badPlugin.Code)
	}

	models := httptest.NewRecorder()
	handler.ServeHTTP(models, httptest.NewRequest(http.MethodPost, "/api/llm/models", bytes.NewBufferString(`{"base_url":"`+targetServer.URL+`"}`)))
	if models.Code != http.StatusOK || !strings.Contains(models.Body.String(), "llama3:8b") {
		t.Fatalf("models status = %d body=%s", models.Code, models.Body.String())
	}
}

func waitForCompletedScan(t *testing.T, handler http.Handler, sessionID string) {
	t.Helper()
	waitForScanStatus(t, handler, sessionID, models.SessionStatusCompleted)
}

func waitForScanStatus(t *testing.T, handler http.Handler, sessionID string, want models.SessionStatus) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		status := httptest.NewRecorder()
		handler.ServeHTTP(status, httptest.NewRequest(http.MethodGet, "/api/scan/"+sessionID+"/status", nil))
		if status.Code != http.StatusOK {
			t.Fatalf("scan status = %d", status.Code)
		}
		var payload struct {
			Status models.SessionStatus `json:"status"`
		}
		if err := json.NewDecoder(status.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.Status == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("scan did not reach status %s", want)
}

func TestScanEventsWebSocketReplaysLifecycle(t *testing.T) {
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<title>Nox Test</title>"))
	}))
	defer targetServer.Close()

	handler := NewServer(Config{SessionDir: t.TempDir(), HTTPClient: targetServer.Client()}).Handler()
	apiServer := httptest.NewServer(handler)
	defer apiServer.Close()

	body := bytes.NewBufferString(`{"target":"` + targetServer.URL + `","name":"Events","mode":"active"}`)
	resp, err := http.Post(apiServer.URL+"/api/scan/start", "application/json", body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start status = %d", resp.StatusCode)
	}
	var created db.SessionRecord
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	waitForScanStatus(t, handler, created.Session.ID, models.SessionStatusCompleted)

	wsURL := "ws" + strings.TrimPrefix(apiServer.URL, "http") + "/ws/scan/" + created.Session.ID
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	seen := map[engine.ScanEventType]bool{}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		var event engine.ScanEvent
		if err := conn.ReadJSON(&event); err != nil {
			t.Fatalf("read scan event: %v", err)
		}
		seen[event.Type] = true
		if event.Type == engine.ScanEventCompleted || event.Type == engine.ScanEventFailed {
			break
		}
	}
	for _, eventType := range []engine.ScanEventType{
		engine.ScanEventQueued,
		engine.ScanEventRunning,
		engine.ScanEventToolStarted,
		engine.ScanEventToolCompleted,
		engine.ScanEventFindingFound,
		engine.ScanEventCompleted,
	} {
		if !seen[eventType] {
			t.Fatalf("missing event %s; saw %#v", eventType, seen)
		}
	}
}

func TestStopScanCancelsRunningScan(t *testing.T) {
	requestStarted := make(chan struct{})
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
	}))
	defer targetServer.Close()

	server := NewServer(Config{SessionDir: t.TempDir(), HTTPClient: targetServer.Client()})
	handler := server.Handler()

	body := bytes.NewBufferString(`{"target":"` + targetServer.URL + `","name":"Cancel","mode":"active"}`)
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, httptest.NewRequest(http.MethodPost, "/api/scan/start", body))
	if start.Code != http.StatusAccepted {
		t.Fatalf("start status = %d body=%s", start.Code, start.Body.String())
	}
	var created db.SessionRecord
	if err := json.NewDecoder(start.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}

	select {
	case <-requestStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("scan did not start target request")
	}

	stop := httptest.NewRecorder()
	handler.ServeHTTP(stop, httptest.NewRequest(http.MethodPost, "/api/scan/"+created.Session.ID+"/stop", nil))
	if stop.Code != http.StatusAccepted {
		t.Fatalf("stop status = %d body=%s", stop.Code, stop.Body.String())
	}
	waitForScanStatus(t, handler, created.Session.ID, models.SessionStatusCancelled)
}
