package nox

import "fmt"

func runReport(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("report requires a session id")
	}
	fmt.Printf("report generation for session %s is scaffolded\n", args[0])
	return nil
}
