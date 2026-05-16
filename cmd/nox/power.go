package nox

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pridhvi/nox/internal/activedirectory"
	"github.com/pridhvi/nox/internal/burp"
	"github.com/pridhvi/nox/internal/creds"
	"github.com/pridhvi/nox/internal/db"
	"github.com/pridhvi/nox/internal/osint"
	"github.com/pridhvi/nox/internal/payload"
	"github.com/pridhvi/nox/internal/poc"
)

func runPayloads(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nox payloads generate|list <session-id>")
	}
	sessionID := args[1]
	store, err := openSessionStore("", sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	switch args[0] {
	case "generate":
		fs := flag.NewFlagSet("payloads generate", flag.ContinueOnError)
		findingID := fs.String("finding", "", "finding id")
		force := fs.Bool("force", false, "force regeneration")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *findingID == "" {
			return fmt.Errorf("--finding is required")
		}
		payloads, err := payload.Generate(context.Background(), store, sessionID, *findingID, payload.GenerateOptions{Force: *force})
		if err != nil {
			return err
		}
		return printJSON(payloads)
	case "list":
		payloads, err := store.ListPayloadsBySession(context.Background(), sessionID, db.PayloadFilter{})
		if err != nil {
			return err
		}
		return printJSON(payloads)
	default:
		return fmt.Errorf("usage: nox payloads generate|list <session-id>")
	}
}

func runCreds(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nox creds test|list|redact <session-id>")
	}
	sessionID := args[1]
	store, err := openSessionStore("", sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	switch args[0] {
	case "test":
		fs := flag.NewFlagSet("creds test", flag.ContinueOnError)
		mode := fs.String("mode", "correlate", "defaults, spray, or correlate")
		username := fs.String("username", "", "username")
		password := fs.String("password", "", "password")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		results, err := creds.Run(context.Background(), store, sessionID, creds.TestRequest{Mode: *mode, Username: *username, Password: *password})
		if err != nil {
			return err
		}
		return printJSON(creds.RedactAll(results, false))
	case "list":
		results, err := store.ListCredentialFindings(context.Background(), sessionID, db.CredentialFilter{})
		if err != nil {
			return err
		}
		return printJSON(creds.RedactAll(results, false))
	default:
		return fmt.Errorf("usage: nox creds test|list <session-id>")
	}
}

func runOSINT(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nox osint run|list <session-id>")
	}
	sessionID := args[1]
	store, err := openSessionStore("", sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	session, err := store.GetSession(context.Background())
	if err != nil {
		return err
	}
	switch args[0] {
	case "run":
		results, err := osint.Run(context.Background(), store, session, osint.RunRequest{})
		if err != nil {
			return err
		}
		return printJSON(results)
	case "list":
		results, err := store.ListOSINTFindings(context.Background(), sessionID, db.OSINTFilter{})
		if err != nil {
			return err
		}
		return printJSON(results)
	default:
		return fmt.Errorf("usage: nox osint run|list <session-id>")
	}
}

func runAD(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nox ad enum|bloodhound <session-id>")
	}
	if args[0] == "bloodhound" && len(args) >= 3 && args[1] == "export" {
		sessionID := args[2]
		store, err := openSessionStore("", sessionID)
		if err != nil {
			return err
		}
		defer store.Close()
		entities, _ := store.ListADEntities(context.Background(), sessionID, "")
		relationships, _ := store.ListADRelationships(context.Background(), sessionID)
		return printJSON(map[string]any{"entities": entities, "relationships": relationships})
	}
	sessionID := args[1]
	store, err := openSessionStore("", sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	session, err := store.GetSession(context.Background())
	if err != nil {
		return err
	}
	switch args[0] {
	case "enum":
		fs := flag.NewFlagSet("ad enum", flag.ContinueOnError)
		domain := fs.String("domain", "", "AD domain")
		allowPublic := fs.Bool("allow-public", false, "allow non-private scope")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		entities, err := activedirectory.RecordEnumRequest(context.Background(), store, session, *domain, *allowPublic)
		if err != nil {
			return err
		}
		return printJSON(entities)
	default:
		return fmt.Errorf("usage: nox ad enum <session-id> or nox ad bloodhound export <session-id>")
	}
}

func runPoC(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: nox poc run|list <session-id>")
	}
	sessionID := args[1]
	store, err := openSessionStore("", sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	switch args[0] {
	case "run":
		fs := flag.NewFlagSet("poc run", flag.ContinueOnError)
		findingID := fs.String("finding", "", "finding id")
		confirm := fs.Bool("confirm", false, "confirm active PoC recording")
		if err := fs.Parse(args[2:]); err != nil {
			return err
		}
		if *findingID == "" {
			return fmt.Errorf("--finding is required")
		}
		result, err := poc.Run(context.Background(), store, sessionID, *findingID, poc.RunRequest{Confirm: *confirm})
		if err != nil {
			return err
		}
		return printJSON(result)
	case "list":
		results, err := store.ListPoCResults(context.Background(), sessionID, "")
		if err != nil {
			return err
		}
		return printJSON(results)
	default:
		return fmt.Errorf("usage: nox poc run|list <session-id>")
	}
}

func runBurp(args []string) error {
	if len(args) < 3 || args[0] != "export" {
		return fmt.Errorf("usage: nox burp export scope|findings <session-id> --output file.xml")
	}
	kind := args[1]
	sessionID := args[2]
	fs := flag.NewFlagSet("burp export", flag.ContinueOnError)
	output := fs.String("output", "", "output file")
	if err := fs.Parse(args[3:]); err != nil {
		return err
	}
	store, err := openSessionStore("", sessionID)
	if err != nil {
		return err
	}
	defer store.Close()
	var raw []byte
	switch kind {
	case "scope":
		raw, err = burp.ExportScope(context.Background(), store, sessionID)
	case "findings":
		raw, err = burp.ExportFindings(context.Background(), store, sessionID)
	default:
		return fmt.Errorf("usage: nox burp export scope|findings <session-id>")
	}
	if err != nil {
		return err
	}
	if *output == "" {
		fmt.Println(string(raw))
		return nil
	}
	return os.WriteFile(*output, raw, 0o600)
}

func openSessionStore(configPath, sessionID string) (*db.Store, error) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		return nil, err
	}
	return db.OpenSession(context.Background(), firstNonEmpty(cfg.Database.SessionDir, db.DefaultSessionsDir()), sessionID)
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
