package adapters

import (
	"context"
	"encoding/xml"
	"fmt"
	"strconv"
	"time"

	"github.com/pridhvi/nox/internal/models"
)

type Nmap struct{}

func NewNmap() Nmap {
	return Nmap{}
}

func (Nmap) ID() string { return "nmap" }

func (Nmap) Name() string { return "Nmap" }

func (Nmap) Phase() Phase { return PhaseRecon }

func (Nmap) DependsOn() []string { return nil }

func (Nmap) ShouldRun(input AdapterInput) bool {
	return activeOnly(input) && input.Target.Host != ""
}

func (a Nmap) Run(ctx context.Context, input AdapterInput) (AdapterOutput, error) {
	args := []string{"-oX", "-", "-Pn", "-T2", input.Target.Host}
	if input.Target.Port > 0 {
		args = append(args, "-p", strconv.Itoa(input.Target.Port))
	}
	if ok, reason := input.Scope.IsInScope(input.Target.Host); !ok {
		return AdapterOutput{ToolRun: failedToolRun(input, a.ID(), args, reason, 1)}, nil
	}
	run := newToolRun(input, a.ID(), args)
	result := RunCommand(ctx, commandTimeout(input, 45*time.Second), "nmap", args...)
	findings := parseNmapFindings(input, result.Stdout)
	return AdapterOutput{Findings: findings, ToolRun: finishToolRun(run, result, len(findings))}, nil
}

type nmapRun struct {
	Hosts []struct {
		Addresses []struct {
			Addr string `xml:"addr,attr"`
		} `xml:"address"`
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr"`
				Version string `xml:"version,attr"`
			} `xml:"service"`
		} `xml:"ports>port"`
	} `xml:"host"`
}

func parseNmapFindings(input AdapterInput, raw string) []models.Finding {
	var parsed nmapRun
	if err := xml.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil
	}
	var findings []models.Finding
	for _, host := range parsed.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}
			service := port.Service.Name
			if service == "" {
				service = "unknown"
			}
			version := port.Service.Product
			if port.Service.Version != "" {
				version = version + " " + port.Service.Version
			}
			description := fmt.Sprintf("Nmap reported %s/%d open", port.Protocol, port.PortID)
			if service != "" {
				description += " for service " + service
			}
			if version != "" {
				description += " (" + version + ")"
			}
			findings = append(findings, externalFinding(
				input,
				"nmap",
				models.FindingTypeExposure,
				models.SeverityInfo,
				fmt.Sprintf("Open %s port %d", port.Protocol, port.PortID),
				description+".",
				"Confirm the service is intended to be exposed and restrict access where possible.",
				raw,
				map[string]any{
					"protocol": port.Protocol,
					"port":     port.PortID,
					"state":    port.State.State,
					"service":  service,
					"version":  version,
				},
				[]string{"nmap", "open-port", service},
			))
		}
	}
	return findings
}
