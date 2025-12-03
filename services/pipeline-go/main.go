package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gabriel-vasile/mimetype"
	"gopkg.in/yaml.v3"
)

// ScoringConfig holds the scoring weights and thresholds
type ScoringConfig struct {
	Weights struct {
		MimeMismatch   int `yaml:"mime_mismatch"`
		ClamavInfected int `yaml:"clamav_infected"`
		YaraMatch      int `yaml:"yara_match"`
		HighEntropy    int `yaml:"high_entropy"`
	} `yaml:"weights"`
	Thresholds struct {
		AutoApprove  int `yaml:"auto_approve"`
		ManualReview int `yaml:"manual_review"`
		Quarantine   int `yaml:"quarantine"`
	} `yaml:"thresholds"`
}

// ScanResult holds the results of scanning a file
type ScanResult struct {
	Path         string
	MimeType     string
	ClamAVResult string
	YaraMatches  []string
	Entropy      float64
	Score        int
	Decision     string
	Error        error
}

// Simple Shannon entropy
func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var freq [256]float64
	for _, v := range b {
		freq[v]++
	}
	var ent float64
	ln := float64(len(b))
	for i := 0; i < 256; i++ {
		if freq[i] == 0 {
			continue
		}
		p := freq[i] / ln
		ent -= p * math.Log2(p)
	}
	return ent
}

func scanClamAV(path string, clamdAddr string) (string, error) {
	// Parse address (format: tcp://host:port)
	addr := strings.TrimPrefix(clamdAddr, "tcp://")
	if addr == clamdAddr {
		// If no tcp:// prefix, assume it's already host:port
		addr = clamdAddr
	}

	// Connect to ClamAV daemon with timeout
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return "", fmt.Errorf("failed to connect to ClamAV: %w", err)
	}
	defer conn.Close()

	// Set read/write timeouts
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Try INSTREAM first, fall back to SCAN if INSTREAM is not supported
	// First, try zINSTREAM command
	command := []byte("zINSTREAM\n")
	_, err = conn.Write(command)
	if err != nil {
		return "", fmt.Errorf("failed to send INSTREAM command: %w", err)
	}

	// Read file
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	// Send file data in chunks
	buf := make([]byte, 4096)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			// Send chunk size (network byte order, 4 bytes)
			chunkSize := uint32(n)
			_, err = conn.Write([]byte{
				byte(chunkSize >> 24),
				byte(chunkSize >> 16),
				byte(chunkSize >> 8),
				byte(chunkSize),
			})
			if err != nil {
				return "", fmt.Errorf("failed to send chunk size: %w", err)
			}
			// Send chunk data
			_, err = conn.Write(buf[:n])
			if err != nil {
				return "", fmt.Errorf("failed to send chunk data: %w", err)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read file: %w", err)
		}
	}

	// Send zero-length chunk to signal end
	_, err = conn.Write([]byte{0, 0, 0, 0})
	if err != nil {
		return "", fmt.Errorf("failed to send end marker: %w", err)
	}

	// Read response
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		// Try reading without expecting newline
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1024)
		n, readErr := reader.Read(buf)
		if readErr == nil && n > 0 {
			response = string(buf[:n])
		} else {
			return "", fmt.Errorf("failed to read response: %w", err)
		}
	}

	response = strings.TrimSpace(response)

	// If INSTREAM is not supported, fall back to SCAN command
	// Note: SCAN only works if the file is accessible from within the ClamAV container
	if strings.Contains(response, "UNKNOWN COMMAND") {
		// Close current connection and try SCAN instead
		conn.Close()

		// For SCAN, we need the file to be accessible to ClamAV
		// When running locally with containerized ClamAV, files must be mounted
		// For now, return a clear error that will be handled gracefully
		return "", fmt.Errorf("INSTREAM not supported and SCAN requires file access from container (mount directories or use local ClamAV)")
	}

	if strings.HasSuffix(response, "FOUND") {
		// Extract virus name: format is "path: <virus_name> FOUND" or "stream: <virus_name> FOUND"
		parts := strings.Fields(response)
		if len(parts) >= 2 {
			virusName := strings.Join(parts[1:len(parts)-1], " ")
			return virusName, nil
		}
		return "Unknown threat", nil
	} else if strings.HasSuffix(response, "OK") {
		return "", nil // No threat found
	}

	return "", fmt.Errorf("unexpected response: %s", response)
}

func scanYARA(path string, yaraHost string, yaraPort string) ([]string, error) {
	url := fmt.Sprintf("http://%s:%s/scan-file", yaraHost, yaraPort)

	reqBody := map[string]string{"path": path}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("YARA scanner error: %s", string(body))
	}

	var result struct {
		Matches []struct {
			Rule string `json:"rule"`
		} `json:"matches"`
		MatchCount int `json:"match_count"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	matches := make([]string, 0, len(result.Matches))
	for _, m := range result.Matches {
		matches = append(matches, m.Rule)
	}
	return matches, nil
}

func loadScoringConfig(path string) (*ScoringConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config ScoringConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func processFile(path string, config *ScoringConfig, clamdAddr string, yaraHost string, yaraPort string, incomingDir string, quarantineDir string) *ScanResult {
	result := &ScanResult{Path: path}

	// MIME detection
	mt, err := mimetype.DetectFile(path)
	if err != nil {
		result.Error = fmt.Errorf("MIME detection failed: %w", err)
		return result
	}
	result.MimeType = mt.String()

	// ClamAV scan (non-fatal - continue even if ClamAV is unavailable)
	clamResult, err := scanClamAV(path, clamdAddr)
	if err != nil {
		// Log error but don't fail the scan - ClamAV might be unavailable in local dev
		log.Printf("[%s] ClamAV warning: %v (scanning continues)", filepath.Base(path), err)
		result.ClamAVResult = ""
	} else {
		result.ClamAVResult = clamResult
	}

	// YARA scan
	yaraMatches, err := scanYARA(path, yaraHost, yaraPort)
	if err != nil {
		log.Printf("[%s] YARA error: %v", filepath.Base(path), err)
	} else {
		result.YaraMatches = yaraMatches
	}

	// Entropy calculation
	f, err := os.Open(path)
	if err == nil {
		buf := make([]byte, 65536)
		n, _ := f.Read(buf)
		result.Entropy = entropy(buf[:n])
		if closeErr := f.Close(); closeErr != nil {
			log.Printf("[%s] Warning: failed to close file: %v", filepath.Base(path), closeErr)
		}
	}

	// Calculate score
	result.Score = 0
	if result.ClamAVResult != "" {
		result.Score += config.Weights.ClamavInfected
	}
	if len(result.YaraMatches) > 0 {
		result.Score += config.Weights.YaraMatch * len(result.YaraMatches)
	}
	if result.Entropy > 6.5 {
		result.Score += config.Weights.HighEntropy
	}

	// Make decision
	if result.Score >= config.Thresholds.Quarantine {
		result.Decision = "quarantine"
		dst := filepath.Join(quarantineDir, filepath.Base(path))
		if err := os.Rename(path, dst); err != nil {
			result.Error = fmt.Errorf("failed to quarantine: %w", err)
		} else {
			log.Printf("[%s] Quarantined (score: %d) -> %s", filepath.Base(path), result.Score, dst)
		}
	} else if result.Score >= config.Thresholds.ManualReview {
		result.Decision = "manual_review"
		log.Printf("[%s] Manual review required (score: %d)", filepath.Base(path), result.Score)
	} else {
		result.Decision = "auto_approve"
		log.Printf("[%s] Auto-approved (score: %d)", filepath.Base(path), result.Score)
	}

	// Log details
	log.Printf("[%s] MIME: %s, ClamAV: %s, YARA: %d matches, Entropy: %.3f, Score: %d, Decision: %s",
		filepath.Base(path), result.MimeType, result.ClamAVResult, len(result.YaraMatches),
		result.Entropy, result.Score, result.Decision)

	return result
}

func findFiles(dir string) ([]string, error) {
	var files []string
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func worker(id int, jobs <-chan string, results chan<- *ScanResult, wg *sync.WaitGroup,
	config *ScoringConfig, clamdAddr string, yaraHost string, yaraPort string,
	incomingDir string, quarantineDir string) {
	defer wg.Done()
	for path := range jobs {
		log.Printf("[Worker %d] Processing: %s", id, filepath.Base(path))
		result := processFile(path, config, clamdAddr, yaraHost, yaraPort, incomingDir, quarantineDir)
		results <- result
	}
}

func main() {
	// Configuration from environment
	incomingDir := os.Getenv("INCOMING_DIR")
	if incomingDir == "" {
		// Default to local path (works both locally and in containers if mounted)
		incomingDir = "./incoming"
	}
	quarantineDir := os.Getenv("QUARANTINE_DIR")
	if quarantineDir == "" {
		// Default to local path (works both locally and in containers if mounted)
		quarantineDir = "./quarantine"
	}
	configPath := os.Getenv("SCORING_CONFIG")
	if configPath == "" {
		// Try local path first (for running outside containers)
		if _, err := os.Stat("./config/scoring.yaml"); err == nil {
			configPath = "./config/scoring.yaml"
		} else if _, err := os.Stat("config/scoring.yaml"); err == nil {
			configPath = "config/scoring.yaml"
		} else {
			// Fall back to container path
			configPath = "/config/scoring.yaml"
		}
	}
	clamdHost := os.Getenv("CLAMD_HOST")
	if clamdHost == "" {
		// Default to localhost for local runs, clamav for container runs
		clamdHost = "localhost"
	}
	clamdPort := os.Getenv("CLAMD_PORT")
	if clamdPort == "" {
		clamdPort = "3310"
	}
	clamdAddr := fmt.Sprintf("tcp://%s:%s", clamdHost, clamdPort)
	yaraHost := os.Getenv("YARA_HOST")
	if yaraHost == "" {
		// Default to localhost for local runs, yara-scanner for container runs
		yaraHost = "localhost"
	}
	yaraPort := os.Getenv("YARA_PORT")
	if yaraPort == "" {
		yaraPort = "8081"
	}
	numWorkers := 5 // Default to 5 concurrent workers
	if w := os.Getenv("NUM_WORKERS"); w != "" {
		fmt.Sscanf(w, "%d", &numWorkers)
	}

	// Load scoring configuration
	config, err := loadScoringConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load scoring config: %v", err)
	}

	// Ensure quarantine directory exists
	if err := os.MkdirAll(quarantineDir, 0755); err != nil {
		log.Fatalf("Failed to create quarantine directory: %v", err)
	}

	log.Printf("Pipeline starting: incoming=%s, quarantine=%s, workers=%d", incomingDir, quarantineDir, numWorkers)
	log.Printf("ClamAV: %s, YARA: %s:%s", clamdAddr, yaraHost, yaraPort)

	// Create channels for worker pool
	jobs := make(chan string, 100)
	results := make(chan *ScanResult, 100)

	// Start workers
	var wg sync.WaitGroup
	for i := 1; i <= numWorkers; i++ {
		wg.Add(1)
		go worker(i, jobs, results, &wg, config, clamdAddr, yaraHost, yaraPort, incomingDir, quarantineDir)
	}

	// Process results in background
	go func() {
		for result := range results {
			if result.Error != nil {
				log.Printf("[%s] Error: %v", filepath.Base(result.Path), result.Error)
			}
		}
	}()

	// Main loop: scan directory periodically
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	processedFiles := make(map[string]bool)
	var mu sync.Mutex

	for {
		// Find all files in incoming directory
		files, err := findFiles(incomingDir)
		if err != nil {
			log.Printf("Error scanning directory: %v", err)
			<-ticker.C
			continue
		}

		// Process new files
		mu.Lock()
		newFiles := 0
		for _, file := range files {
			if !processedFiles[file] {
				processedFiles[file] = true
				select {
				case jobs <- file:
					newFiles++
				default:
					log.Printf("Job queue full, skipping: %s", filepath.Base(file))
				}
			}
		}
		mu.Unlock()

		if newFiles > 0 {
			log.Printf("Queued %d new file(s) for processing", newFiles)
		}

		<-ticker.C
	}
}
