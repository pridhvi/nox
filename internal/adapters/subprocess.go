package adapters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"

	"github.com/kanini/nox/internal/models"
)

type PluginRequest struct {
	Version           string              `json:"version"`
	SessionID         string              `json:"session_id"`
	Target            models.Target       `json:"target"`
	PriorFindings     []models.Finding    `json:"prior_findings"`
	PriorTechnologies []models.Technology `json:"prior_technologies"`
	Config            map[string]string   `json:"config"`
}

type PluginResponse struct {
	Version      string              `json:"version"`
	Findings     []models.Finding    `json:"findings"`
	NewTargets   []models.Target     `json:"new_targets"`
	Technologies []models.Technology `json:"technologies"`
	Error        *string             `json:"error"`
}

func RunPlugin(ctx context.Context, binary string, req PluginRequest) (PluginResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return PluginResponse{}, err
	}
	cmd := exec.CommandContext(ctx, binary)
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return PluginResponse{}, fmt.Errorf("%s failed: %w: %s", binary, err, stderr.String())
	}
	var resp PluginResponse
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		return PluginResponse{}, err
	}
	if resp.Error != nil && *resp.Error != "" {
		return resp, fmt.Errorf("plugin returned error: %s", *resp.Error)
	}
	return resp, nil
}
