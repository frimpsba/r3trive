package context

import (
	"strings"
	"testing"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/event"
)

func TestContextBuilder(t *testing.T) {
	builder := NewBuilder(500)

	evt := event.Event{
		ID:        "evt-001",
		Timestamp: time.Now(),
		Type:      event.ProcessCreate,
		Severity:  event.SeverityHigh,
		Sensor:    "WindowsProcessSensor",
		Host: event.HostInfo{
			Hostname: "WORKSTATION-01",
			OS:       "windows",
		},
		Data: event.EventData{
			Process: &event.ProcessData{
				PID:     1234,
				Name:    "powershell.exe",
				CmdLine: "powershell.exe -enc AAAA",
				User:    "SYSTEM",
			},
		},
	}

	ctxStr := builder.BuildEventContext(evt)
	if !strings.Contains(ctxStr, "WORKSTATION-01") {
		t.Errorf("expected hostname in context string")
	}
	if !strings.Contains(ctxStr, "powershell.exe") {
		t.Errorf("expected process name in context string")
	}

	inc := event.Incident{
		ID:        "inc-001",
		Title:     "Credential Dumping Attempt",
		Severity:  event.SeverityCritical,
		RiskScore: 90,
		Status:    event.IncidentStatusOpen,
		CreatedAt: time.Now().Add(-10 * time.Minute),
		UpdatedAt: time.Now(),
		Alerts: []event.Alert{
			{
				ID:              "alt-001",
				RuleName:        "LSASS Memory Access",
				Severity:        event.SeverityCritical,
				Message:         "Mimikatz detected",
				ATTACKTechnique: "T1003.001",
				Confidence:      0.95,
				RiskScore:       90,
			},
		},
	}

	incCtx := builder.BuildIncidentContext(inc, "ATT&CK context details", nil)
	if !strings.Contains(incCtx, "Credential Dumping Attempt") {
		t.Errorf("expected incident title in incident context")
	}
	if !strings.Contains(incCtx, "ATT&CK context details") {
		t.Errorf("expected attack context in incident context")
	}
}
