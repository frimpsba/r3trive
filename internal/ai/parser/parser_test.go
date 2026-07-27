package parser

import (
	"testing"
)

func TestExtractJSON(t *testing.T) {
	input := `Here is the analysis:
{
	"executive_summary": "Suspicious execution of powershell",
	"confidence_score": 0.85
}
Hope this helps!`

	var target struct {
		Summary    string  `json:"executive_summary"`
		Confidence float64 `json:"confidence_score"`
	}

	err := ExtractJSON(input, &target)
	if err != nil {
		t.Fatalf("ExtractJSON failed: %v", err)
	}
	if target.Summary != "Suspicious execution of powershell" {
		t.Errorf("unexpected summary: %s", target.Summary)
	}
	if target.Confidence != 0.85 {
		t.Errorf("unexpected confidence: %f", target.Confidence)
	}
}

func TestExtractYAMLBlock(t *testing.T) {
	input := "```yaml\nid: R3-001\nname: Test Rule\ntype: atomic\nseverity: high\nconfidence: 0.9\nconditions:\n  - field: process.name\n    operator: eq\n    value: cmd.exe\n```"
	extracted := ExtractYAMLBlock(input)
	if extracted == "" || extracted == input {
		t.Errorf("failed to extract YAML block")
	}

	parsed, err := ParseRuleResponse(input)
	if err != nil {
		t.Fatalf("ParseRuleResponse failed: %v", err)
	}
	if parsed.ID != "R3-001" {
		t.Errorf("expected ID R3-001, got %s", parsed.ID)
	}
}

func TestExtractConfidenceScore(t *testing.T) {
	score1 := ExtractConfidenceScore("Overall confidence: 88%")
	if score1 != 0.88 {
		t.Errorf("expected 0.88, got %f", score1)
	}

	score2 := ExtractConfidenceScore("This has High Confidence")
	if score2 != 0.90 {
		t.Errorf("expected 0.90, got %f", score2)
	}
}
