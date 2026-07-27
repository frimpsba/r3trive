package yara

import (
	"context"
	"testing"
	"time"
)

func TestIntelligenceYARAEngine(t *testing.T) {
	engine := NewEngine()
	if err := engine.LoadRuleDir("/tmp/rules"); err != nil {
		t.Fatalf("LoadRuleDir failed: %v", err)
	}

	ctx := context.Background()
	matches, err := engine.ScanBytes(ctx, []byte("Execution via powershell -enc test payload"))
	if err != nil {
		t.Fatalf("ScanBytes failed: %v", err)
	}
	if len(matches) == 0 {
		t.Errorf("expected builtin YARA rule match for powershell -enc")
	}

	res, err := engine.ScanDirectory(ctx, t.TempDir(), 5*time.Second)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}
	if res == nil {
		t.Errorf("expected non-nil map result from ScanDirectory")
	}
}
