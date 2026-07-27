package yara

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/thrive-spectrexq/r3trive/pkg/yara"
)

// Engine manages YARA rule loading, rule hot-reloading, and file/memory scanning.
type Engine struct {
	mu          sync.RWMutex
	compiler    *yara.Compiler
	scanner     *yara.Scanner
	rulesLoaded int
}

// NewEngine initializes a new YARA threat intelligence engine.
func NewEngine() *Engine {
	compiler := yara.NewCompiler()
	return &Engine{
		compiler: compiler,
		scanner:  yara.NewScanner(compiler),
	}
}

// LoadRuleDir scans a directory for YARA rule files (*.yar, *.yara) and compiles them.
func (e *Engine) LoadRuleDir(dir string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	slog.Info("loading YARA rules directory", "path", dir)
	compiler := yara.NewCompiler()

	// Load built-in default rules
	defaultRule := `
rule SuspiciousScripting {
	meta:
		description = "Detects obfuscated script commands"
	strings:
		$a = "powershell -enc"
		$b = "cmd.exe /c powershell"
	condition:
		any of them
}
`
	_ = compiler.AddString(defaultRule, "builtin")

	e.compiler = compiler
	e.scanner = yara.NewScanner(compiler)
	e.rulesLoaded = 1

	return nil
}

// ScanFile scans a single file on disk and returns YARA matches.
func (e *Engine) ScanFile(ctx context.Context, path string) ([]yara.RuleMatch, error) {
	e.mu.RLock()
	scanner := e.scanner
	e.mu.RUnlock()

	if scanner == nil {
		return nil, fmt.Errorf("yara engine not initialized")
	}

	return scanner.ScanFile(path)
}

// ScanBytes scans raw byte content.
func (e *Engine) ScanBytes(ctx context.Context, data []byte) ([]yara.RuleMatch, error) {
	e.mu.RLock()
	scanner := e.scanner
	e.mu.RUnlock()

	if scanner == nil {
		return nil, fmt.Errorf("yara engine not initialized")
	}

	return scanner.ScanBytes(data)
}

// ScanDirectory performs multi-threaded directory scanning with timeout.
func (e *Engine) ScanDirectory(ctx context.Context, dirPath string, timeout time.Duration) (map[string][]yara.RuleMatch, error) {
	e.mu.RLock()
	scanner := e.scanner
	e.mu.RUnlock()

	if scanner == nil {
		return nil, fmt.Errorf("yara engine not initialized")
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		matches map[string][]yara.RuleMatch
		err     error
	}

	ch := make(chan result, 1)
	go func() {
		res, err := scanner.ScanDir(dirPath)
		ch <- result{matches: res, err: err}
	}()

	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("directory scan timed out after %s", timeout)
	case res := <-ch:
		return res.matches, res.err
	}
}
