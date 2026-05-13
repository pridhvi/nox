package nox

import "fmt"

func runSessions(args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return fmt.Errorf("supported sessions command: list")
	}
	fmt.Println("no sessions yet; persistent storage is scaffolded in internal/db")
	return nil
}
