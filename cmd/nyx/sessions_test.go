package nyx

import (
	"archive/zip"
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/pridhvi/nyx/internal/db"
	"github.com/pridhvi/nyx/internal/models"
)

func TestExportSessionArchivesSessionDirectory(t *testing.T) {
	sessionDir := t.TempDir()
	t.Setenv("NYX_SESSION_DIR", sessionDir)
	session := models.Session{
		ID:          models.NewID(),
		Status:      models.SessionStatusPending,
		Mode:        models.ScanModeActive,
		TargetInput: "https://example.com",
		InScope:     []string{"example.com"},
		CreatedAt:   time.Now().UTC(),
	}
	target := models.Target{
		ID:        models.NewID(),
		SessionID: session.ID,
		Host:      "example.com",
		Port:      443,
		Protocol:  "https",
		CreatedAt: time.Now().UTC(),
	}
	if _, err := db.CreateSessionDB(context.Background(), sessionDir, session, target); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "session.zip")
	if err := exportSession([]string{session.ID, "--output", out}); err != nil {
		t.Fatal(err)
	}
	archive, err := zip.OpenReader(out)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	for _, file := range archive.File {
		if file.Name == "session.db" {
			return
		}
	}
	t.Fatalf("expected session.db in export, got %#v", archive.File)
}
