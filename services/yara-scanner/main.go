package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/hillu/go-yara/v4"
)

var (
	compiledRules *yara.Rules
	rulesDir      string
	rulesMutex    sync.RWMutex
)

type HealthResponse struct {
	Status      string `json:"status"`
	RulesLoaded bool   `json:"rules_loaded"`
	RulesDir    string `json:"rules_dir"`
}

type ScanRequest struct {
	Path string `json:"path"`
}

type Match struct {
	Rule    string   `json:"rule"`
	Tags    []string `json:"tags"`
	Strings []string `json:"strings,omitempty"`
}

type ScanResponse struct {
	Matches    []Match `json:"matches"`
	MatchCount int     `json:"match_count"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// matchCollector implements yara.ScanCallback to collect matches
type matchCollector struct {
	matches []yara.MatchRule
}

func (mc *matchCollector) RuleMatching(ctx *yara.ScanContext, rule *yara.Rule) (bool, error) {
	// Get rule strings (these are the pattern strings, not the matched values)
	ruleStrings := rule.Strings()
	matchStrings := make([]yara.MatchString, 0, len(ruleStrings))

	// For now, we'll just record the rule identifier and tags
	// MatchString details would require more complex extraction from ScanContext
	mc.matches = append(mc.matches, yara.MatchRule{
		Rule:      rule.Identifier(),
		Namespace: rule.Namespace(),
		Tags:      rule.Tags(),
		Strings:   matchStrings,
	})
	return true, nil
}

func loadRules() error {
	rulesDir = os.Getenv("YARA_RULES_DIR")
	if rulesDir == "" {
		rulesDir = "/rules"
	}

	// Check if directory exists
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		log.Printf("Warning: Rules directory %s does not exist", rulesDir)
		return fmt.Errorf("rules directory does not exist")
	}

	// Find all .yar and .yara files
	var ruleFiles []string
	err := filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			ext := strings.ToLower(filepath.Ext(path))
			if ext == ".yar" || ext == ".yara" {
				ruleFiles = append(ruleFiles, path)
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking rules directory: %w", err)
	}

	if len(ruleFiles) == 0 {
		log.Printf("Warning: No YARA rule files found in %s", rulesDir)
		return fmt.Errorf("no YARA rule files found")
	}

	// Compile all rules
	compiler, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("failed to create YARA compiler: %w", err)
	}

	for _, ruleFile := range ruleFiles {
		f, err := os.Open(ruleFile)
		if err != nil {
			log.Printf("Warning: Failed to open rule file %s: %v", ruleFile, err)
			continue
		}

		namespace := filepath.Base(ruleFile)
		namespace = strings.TrimSuffix(namespace, filepath.Ext(namespace))
		err = compiler.AddFile(f, namespace)
		f.Close() // Close immediately after use, not deferred
		if err != nil {
			log.Printf("Warning: Failed to compile rule file %s: %v", ruleFile, err)
			continue
		}
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return fmt.Errorf("failed to get compiled rules: %w", err)
	}

	rulesMutex.Lock()
	compiledRules = rules
	rulesMutex.Unlock()
	log.Printf("Loaded %d YARA rule files from %s", len(ruleFiles), rulesDir)
	return nil
}

type ReloadResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	RuleCount int    `json:"rule_count,omitempty"`
}

func healthHandler(c *gin.Context) {
	rulesMutex.RLock()
	loaded := compiledRules != nil
	rulesMutex.RUnlock()

	c.JSON(http.StatusOK, HealthResponse{
		Status:      "healthy",
		RulesLoaded: loaded,
		RulesDir:    rulesDir,
	})
}

func reloadRulesHandler(c *gin.Context) {
	if err := loadRules(); err != nil {
		c.JSON(http.StatusInternalServerError, ReloadResponse{
			Success: false,
			Message: fmt.Sprintf("Failed to reload rules: %v", err),
		})
		return
	}

	rulesMutex.RLock()
	ruleCount := 0
	if compiledRules != nil {
		// Count rules by checking if ruleset is valid
		ruleCount = 1 // Indicate rules are loaded
	}
	rulesMutex.RUnlock()

	c.JSON(http.StatusOK, ReloadResponse{
		Success:   true,
		Message:   "Rules reloaded successfully",
		RuleCount: ruleCount,
	})
}

func scanHandler(c *gin.Context) {
	rulesMutex.RLock()
	rules := compiledRules
	rulesMutex.RUnlock()

	if rules == nil {
		c.JSON(http.StatusServiceUnavailable, ErrorResponse{
			Error: "No YARA rules loaded",
		})
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "No file provided",
		})
		return
	}

	if file.Filename == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "Empty filename",
		})
		return
	}

	// Save uploaded file temporarily
	tmpFile, err := os.CreateTemp("", "yara-scan-*")
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("Failed to create temp file: %v", err),
		})
		return
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("Failed to open uploaded file: %v", err),
		})
		return
	}
	defer src.Close()

	_, err = io.Copy(tmpFile, src)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("Failed to save uploaded file: %v", err),
		})
		return
	}
	tmpFile.Close()

	// Scan with YARA (rules already checked above)
	collector := &matchCollector{matches: make([]yara.MatchRule, 0)}
	err = rules.ScanFile(tmpFile.Name(), 0, 0, collector)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("YARA scan failed: %v", err),
		})
		return
	}

	// Format results
	results := make([]Match, 0, len(collector.matches))
	for _, m := range collector.matches {
		match := Match{
			Rule: m.Rule,
			Tags: m.Tags,
		}
		for _, s := range m.Strings {
			match.Strings = append(match.Strings, fmt.Sprintf("%s:%s", s.Name, s.Data))
		}
		results = append(results, match)
	}

	c.JSON(http.StatusOK, ScanResponse{
		Matches:    results,
		MatchCount: len(results),
	})
}

func scanFileHandler(c *gin.Context) {
	rulesMutex.RLock()
	rules := compiledRules
	rulesMutex.RUnlock()

	if rules == nil {
		c.JSON(http.StatusServiceUnavailable, ErrorResponse{
			Error: "No YARA rules loaded",
		})
		return
	}

	var req ScanRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error: "No file path provided",
		})
		return
	}

	if _, err := os.Stat(req.Path); os.IsNotExist(err) {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error: "File not found",
		})
		return
	}

	// Scan with YARA (rules already checked above)
	collector := &matchCollector{matches: make([]yara.MatchRule, 0)}
	err := rules.ScanFile(req.Path, 0, 0, collector)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error: fmt.Sprintf("YARA scan failed: %v", err),
		})
		return
	}

	// Format results
	results := make([]Match, 0, len(collector.matches))
	for _, m := range collector.matches {
		match := Match{
			Rule: m.Rule,
			Tags: m.Tags,
		}
		results = append(results, match)
	}

	c.JSON(http.StatusOK, ScanResponse{
		Matches:    results,
		MatchCount: len(results),
	})
}

func main() {
	// Load rules at startup
	if err := loadRules(); err != nil {
		log.Printf("Error loading YARA rules: %v", err)
		log.Println("Service may not function correctly")
	}

	// Set Gin to release mode
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Routes
	r.GET("/health", healthHandler)
	r.POST("/scan", scanHandler)
	r.POST("/scan-file", scanFileHandler)
	r.POST("/reload", reloadRulesHandler)

	log.Println("YARA Scanner service starting on :8081")
	if err := r.Run(":8081"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
