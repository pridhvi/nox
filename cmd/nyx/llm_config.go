package nyx

import "strings"

func selectLLMSettings(noLLM, configEnabled bool, explicitURL, explicitModel, configURL, configModel string) (string, string, bool) {
	explicit := strings.TrimSpace(explicitURL) != "" || strings.TrimSpace(explicitModel) != ""
	if noLLM || (!configEnabled && !explicit) {
		return "", "", true
	}
	return firstNonEmpty(explicitURL, configURL), firstNonEmpty(explicitModel, configModel), false
}
