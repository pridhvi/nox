package source

import "github.com/pridhvi/nyx/internal/models"

type Extractor interface {
	Detect(repoPath string) bool
	Language() string
	Framework() string
	Extract(repoPath, sessionID string) ([]models.SourceFinding, error)
}
