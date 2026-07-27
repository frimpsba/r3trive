package yara

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// StringMatch represents a matched string inside scanned data.
type StringMatch struct {
	Name   string `json:"name"`
	Offset uint64 `json:"offset"`
	Data   string `json:"data"`
}

// RuleMatch represents a triggered YARA rule.
type RuleMatch struct {
	Rule      string            `json:"rule"`
	Namespace string            `json:"namespace"`
	Tags      []string          `json:"tags"`
	Meta      map[string]string `json:"meta"`
	Strings   []StringMatch     `json:"strings"`
}

// SimpleRule is a lightweight fallback structure for YARA rules when CGO/libyara is unavailable.
type SimpleRule struct {
	Name      string
	Namespace string
	Tags      []string
	Meta      map[string]string
	Strings   []*regexp.Regexp
}

// Compiler manages YARA rule compilation and caching.
type Compiler struct {
	mu    sync.RWMutex
	rules []*SimpleRule
}

// NewCompiler creates a new YARA rule compiler.
func NewCompiler() *Compiler {
	return &Compiler{
		rules: make([]*SimpleRule, 0),
	}
}

// AddString parses and compiles a YARA rule string.
func (c *Compiler) AddString(ruleStr string, namespace string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	parsed, err := parseSimpleYARA(ruleStr, namespace)
	if err != nil {
		return err
	}
	c.rules = append(c.rules, parsed)
	return nil
}

// AddFile reads and compiles a YARA rule file.
func (c *Compiler) AddFile(path string, namespace string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading yara file: %w", err)
	}
	return c.AddString(string(data), namespace)
}

// Scanner scans files and bytes against compiled YARA rules.
type Scanner struct {
	compiler *Compiler
}

// NewScanner creates a scanner from a compiled rule set.
func NewScanner(compiler *Compiler) *Scanner {
	return &Scanner{compiler: compiler}
}

// ScanBytes scans a byte slice for rule matches.
func (s *Scanner) ScanBytes(data []byte) ([]RuleMatch, error) {
	s.compiler.mu.RLock()
	defer s.compiler.mu.RUnlock()

	var matches []RuleMatch
	for _, rule := range s.compiler.rules {
		matchedStrings := make([]StringMatch, 0)
		for idx, re := range rule.Strings {
			locs := re.FindAllIndex(data, 10)
			for _, loc := range locs {
				strData := string(data[loc[0]:loc[1]])
				if len(strData) > 64 {
					strData = strData[:64] + "..."
				}
				matchedStrings = append(matchedStrings, StringMatch{
					Name:   fmt.Sprintf("$s%d", idx+1),
					Offset: uint64(loc[0]),
					Data:   strData,
				})
			}
		}

		if len(matchedStrings) > 0 {
			matches = append(matches, RuleMatch{
				Rule:      rule.Name,
				Namespace: rule.Namespace,
				Tags:      rule.Tags,
				Meta:      rule.Meta,
				Strings:   matchedStrings,
			})
		}
	}
	return matches, nil
}

// ScanFile scans a file on disk for rule matches.
func (s *Scanner) ScanFile(path string) ([]RuleMatch, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading target file: %w", err)
	}
	return s.ScanBytes(data)
}

// ScanDir recursively scans a directory for YARA matches.
func (s *Scanner) ScanDir(dir string) (map[string][]RuleMatch, error) {
	results := make(map[string][]RuleMatch)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil || info.IsDir() {
			return nil // ignore unreadable paths and directories during traversal
		}
		if info.Size() > 50*1024*1024 {
			return nil
		}

		matches, scanErr := s.ScanFile(path)
		if scanErr == nil && len(matches) > 0 {
			results[path] = matches
		}
		return nil
	})

	return results, err
}

func parseSimpleYARA(ruleStr, namespace string) (*SimpleRule, error) {
	rule := &SimpleRule{
		Namespace: namespace,
		Meta:      make(map[string]string),
	}

	scanner := bufio.NewScanner(strings.NewReader(ruleStr))
	inStrings := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "rule "):
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				rule.Name = strings.TrimSuffix(parts[1], "{")
			}
		case strings.HasPrefix(line, "strings:"):
			inStrings = true
		case strings.HasPrefix(line, "condition:"):
			inStrings = false
		case inStrings && strings.Contains(line, "="):
			eqIdx := strings.Index(line, "=")
			valStr := strings.TrimSpace(line[eqIdx+1:])
			valStr = strings.Trim(valStr, "\"")
			if valStr != "" {
				re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(valStr))
				if err == nil {
					rule.Strings = append(rule.Strings, re)
				}
			}
		}
	}

	if rule.Name == "" {
		rule.Name = "custom_rule"
	}
	return rule, nil
}
