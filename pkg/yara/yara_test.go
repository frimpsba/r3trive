package yara

import (
	"os"
	"path/filepath"
	"testing"
)

func TestYARAScanner(t *testing.T) {
	ruleContent := `
rule DetectMimikatz {
	meta:
		author = "R3TRIVE"
	strings:
		$s1 = "mimikatz"
		$s2 = "sekurlsa::logonpasswords"
	condition:
		any of them
}
`

	compiler := NewCompiler()
	if err := compiler.AddString(ruleContent, "test"); err != nil {
		t.Fatalf("AddString failed: %v", err)
	}

	scanner := NewScanner(compiler)

	sampleData := []byte("Executing command sekurlsa::logonpasswords on host")
	matches, err := scanner.ScanBytes(sampleData)
	if err != nil {
		t.Fatalf("ScanBytes failed: %v", err)
	}
	if len(matches) == 0 {
		t.Fatalf("expected YARA rule match")
	}
	if matches[0].Rule != "DetectMimikatz" {
		t.Errorf("expected rule DetectMimikatz, got %s", matches[0].Rule)
	}

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.exe")
	if err := os.WriteFile(filePath, sampleData, 0644); err != nil {
		t.Fatalf("writing temp file failed: %v", err)
	}

	dirMatches, err := scanner.ScanDir(tmpDir)
	if err != nil {
		t.Fatalf("ScanDir failed: %v", err)
	}
	if len(dirMatches) != 1 {
		t.Errorf("expected 1 file match in dir scan, got %d", len(dirMatches))
	}
}
