package sigma

import (
	"testing"
)

func TestSigmaTranspiler(t *testing.T) {
	sigmaContent := `
title: PowerShell Encoded Command Execution
id: 5a4325a7-9e6e-4731-bbdc-e87f54c12658
description: Detects base64 encoded command execution in PowerShell
level: high
tags:
  - attack.execution
  - attack.t1059.001
detection:
  selection:
    Image|endswith: powershell.exe
    CommandLine|contains: -enc
  condition: selection
`

	sr, err := ParseRule([]byte(sigmaContent))
	if err != nil {
		t.Fatalf("ParseRule failed: %v", err)
	}
	if sr.Title != "PowerShell Encoded Command Execution" {
		t.Errorf("unexpected title: %s", sr.Title)
	}

	transpiler := NewTranspiler()
	r3Rule, err := transpiler.Transpile(sr)
	if err != nil {
		t.Fatalf("Transpile failed: %v", err)
	}
	if r3Rule.Severity != "high" {
		t.Errorf("expected high severity, got %s", r3Rule.Severity)
	}
	if len(r3Rule.Conditions) == 0 {
		t.Errorf("expected conditions in transpiled rule")
	}
}
