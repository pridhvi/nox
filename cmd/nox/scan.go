package nox

import (
	"flag"
	"fmt"
	"strings"
	"time"

	"github.com/kanini/nox/internal/engine"
	"github.com/kanini/nox/internal/models"
)

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	target := fs.String("target", "", "target host, URL, or CIDR")
	name := fs.String("name", "", "engagement name")
	mode := fs.String("mode", string(models.ScanModeActive), "scan mode: passive, active, stealth")
	outOfScope := fs.String("out-of-scope", "", "comma-separated hosts or CIDRs to exclude")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *target == "" {
		return fmt.Errorf("--target is required")
	}

	session := models.Session{
		ID:          models.NewID(),
		Name:        *name,
		Status:      models.SessionStatusPending,
		Mode:        models.ScanMode(*mode),
		TargetInput: *target,
		InScope:     []string{*target},
		OutOfScope:  splitCSV(*outOfScope),
		CreatedAt:   time.Now().UTC(),
	}
	checker, err := engine.NewScopeChecker(session.InScope, session.OutOfScope)
	if err != nil {
		return err
	}
	ok, reason := checker.IsInScope(*target)
	if !ok {
		return fmt.Errorf("target is out of scope: %s", reason)
	}

	fmt.Printf("created session %s for %s (%s mode)\n", session.ID, session.TargetInput, session.Mode)
	fmt.Println("scanner orchestration is scaffolded; adapters are registered next")
	return nil
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
