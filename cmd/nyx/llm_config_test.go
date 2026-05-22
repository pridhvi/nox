package nyx

import "testing"

func TestSelectLLMSettingsUsesExplicitFlagsWhenConfigDisabled(t *testing.T) {
	baseURL, model, disabled := selectLLMSettings(false, false, "http://127.0.0.1:1234/v1", "local-model", "", "configured-model")
	if disabled {
		t.Fatal("expected explicit LLM flags to enable LLM for the run")
	}
	if baseURL != "http://127.0.0.1:1234/v1" || model != "local-model" {
		t.Fatalf("unexpected LLM settings: baseURL=%q model=%q", baseURL, model)
	}
}

func TestSelectLLMSettingsHonorsNoLLM(t *testing.T) {
	baseURL, model, disabled := selectLLMSettings(true, true, "http://127.0.0.1:1234/v1", "local-model", "http://configured", "configured-model")
	if !disabled {
		t.Fatal("expected --no-llm to disable LLM")
	}
	if baseURL != "" || model != "" {
		t.Fatalf("expected empty LLM settings when disabled, got baseURL=%q model=%q", baseURL, model)
	}
}

func TestSelectLLMSettingsRequiresConfigEnabledWithoutExplicitFlags(t *testing.T) {
	baseURL, model, disabled := selectLLMSettings(false, false, "", "", "http://configured", "configured-model")
	if !disabled {
		t.Fatal("expected disabled config without explicit flags to keep LLM disabled")
	}
	if baseURL != "" || model != "" {
		t.Fatalf("expected empty LLM settings when disabled, got baseURL=%q model=%q", baseURL, model)
	}
}
