package nox

import (
	"fmt"

	"github.com/kanini/nox/internal/adapters"
)

func runPlugins(args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return fmt.Errorf("supported plugins command: list")
	}
	for _, adapter := range adapters.All() {
		fmt.Printf("%s\t%s\t%s\n", adapter.ID(), adapter.Phase(), adapter.Name())
	}
	return nil
}
