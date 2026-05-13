package vectors

import "github.com/kanini/nox/internal/models"

type Rule struct {
	ID             string
	Title          string
	OWASPCategory  string
	Severity       models.Severity
	BaseConfidence float64
	Conditions     []Condition
	ChainTemplate  []string
}

type Condition struct {
	ToolID       string
	FindingType  models.FindingType
	SeverityMin  models.Severity
	URLContains  string
	TagContains  string
	ParameterSet bool
}

var DefaultRules = []Rule{
	{
		ID:             "sqli-unauth",
		Title:          "SQL injection in unauthenticated endpoint",
		OWASPCategory:  "A03:2021 - Injection",
		Severity:       models.SeverityCritical,
		BaseConfidence: 0.92,
		Conditions: []Condition{
			{ToolID: "sqlmap", FindingType: models.FindingTypeVulnerability},
		},
		ChainTemplate: []string{
			"Confirm injectable parameter with sqlmap.",
			"Enumerate databases and tables.",
			"Dump target data within authorized scope.",
			"Assess whether stacked queries enable command execution.",
		},
	},
	{
		ID:             "xss-no-csp",
		Title:          "Reflected XSS with no Content-Security-Policy",
		OWASPCategory:  "A03:2021 - Injection",
		Severity:       models.SeverityHigh,
		BaseConfidence: 0.85,
		Conditions: []Condition{
			{ToolID: "dalfox", FindingType: models.FindingTypeVulnerability},
			{ToolID: "header-check", TagContains: "missing-csp"},
		},
		ChainTemplate: []string{
			"Use the reflected XSS parameter found by dalfox.",
			"Craft a proof of concept payload that demonstrates impact.",
			"Document the missing CSP as an exploitability amplifier.",
		},
	},
}
