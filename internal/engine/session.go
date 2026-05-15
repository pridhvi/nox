package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/pridhvi/nox/internal/models"
)

type NewSessionInput struct {
	Target         string
	Name           string
	Mode           models.ScanMode
	OutOfScope     []string
	EnabledPhases  []string
	EnabledTools   []string
	ToolParameters map[string]map[string]any
	RunnerOptions  models.ScanRunnerOptions
	LLMModel       string
	LLMBaseURL     string
}

func NewPendingSession(input NewSessionInput) (models.Session, models.Target, error) {
	session, targets, err := NewPendingSessionWithTargets(input)
	if err != nil {
		return models.Session{}, models.Target{}, err
	}
	return session, targets[0], nil
}

func NewPendingSessionWithTargets(input NewSessionInput) (models.Session, []models.Target, error) {
	targetsInput := SplitTargetList(input.Target)
	if len(targetsInput) == 0 {
		return models.Session{}, nil, fmt.Errorf("at least one target is required")
	}
	mode := input.Mode
	if mode == "" {
		mode = models.ScanModeActive
	}
	switch mode {
	case models.ScanModePassive, models.ScanModeActive, models.ScanModeStealth:
	default:
		return models.Session{}, nil, fmt.Errorf("unsupported scan mode %q", mode)
	}
	targetInput := strings.Join(targetsInput, ", ")
	session := models.Session{
		ID:             models.NewID(),
		Name:           input.Name,
		Status:         models.SessionStatusPending,
		Mode:           mode,
		TargetInput:    targetInput,
		InScope:        targetsInput,
		OutOfScope:     input.OutOfScope,
		EnabledPhases:  input.EnabledPhases,
		EnabledTools:   input.EnabledTools,
		ToolParameters: input.ToolParameters,
		RunnerOptions:  input.RunnerOptions,
		LLMModel:       input.LLMModel,
		LLMBaseURL:     input.LLMBaseURL,
		CreatedAt:      time.Now().UTC(),
	}
	checker, err := NewScopeChecker(session.InScope, session.OutOfScope)
	if err != nil {
		return models.Session{}, nil, err
	}
	var targets []models.Target
	for _, targetInput := range targetsInput {
		if err := ValidateTargetInput(targetInput); err != nil {
			return models.Session{}, nil, err
		}
		ok, reason := checker.IsInScope(targetInput)
		if !ok {
			return models.Session{}, nil, fmt.Errorf("target %q is out of scope: %s", targetInput, reason)
		}
		targets = append(targets, NewInitialTarget(session.ID, targetInput))
	}
	return session, targets, nil
}
