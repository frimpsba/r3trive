package prompt

import (
	"strings"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestPromptBuilders(t *testing.T) {
	inc := event.Incident{
		ID:        "INC-101",
		Title:     "Ransomware Activity",
		Severity:  event.SeverityCritical,
		RiskScore: 95,
	}

	expPrompt := BuildIncidentExplanationPrompt(inc)
	if !strings.Contains(expPrompt, "INC-101") || !strings.Contains(expPrompt, "Ransomware Activity") {
		t.Errorf("BuildIncidentExplanationPrompt failed to embed incident info")
	}

	rulePrompt := BuildRuleGenerationPrompt("Detect cmd.exe calling powershell with encoded command")
	if !strings.Contains(rulePrompt, "powershell") {
		t.Errorf("BuildRuleGenerationPrompt failed")
	}

	chainPrompt := BuildAttackChainPrompt(inc)
	if !strings.Contains(chainPrompt, "Initial Access -> Execution") {
		t.Errorf("BuildAttackChainPrompt failed")
	}

	events := []event.Event{
		{
			ID:        "E1",
			Timestamp: time.Now(),
			Type:      event.ProcessCreate,
			Sensor:    "proc_sensor",
			Host:      event.HostInfo{Hostname: "HOST-1"},
		},
	}
	sumPrompt := BuildActivitySummaryPrompt(events)
	if !strings.Contains(sumPrompt, "HOST-1") {
		t.Errorf("BuildActivitySummaryPrompt failed")
	}

	freePrompt := BuildFreeformQueryPrompt("How to contain IP 10.0.0.5?", "Context line")
	if !strings.Contains(freePrompt, "10.0.0.5") {
		t.Errorf("BuildFreeformQueryPrompt failed")
	}
}
