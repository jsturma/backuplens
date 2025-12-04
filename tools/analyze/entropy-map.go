package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gabriel-vasile/mimetype"
)

// FileType represents the detected file type
type FileType int

const (
	Text   FileType = iota // SQL, logs, text files
	Binary                 // Binary files (pgBackRest, etc.)
)

// entropy calculates Shannon entropy for a byte slice (same as pipeline)
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

// detectFileType detects the file type using MIME type detection (more accurate than extension)
func detectFileType(filename string) FileType {
	// Use mimetype library for accurate detection
	mt, err := mimetype.DetectFile(filename)
	if err != nil {
		// Fallback to extension-based detection if mimetype fails
		log.Printf("Warning: MIME type detection failed for %s, using extension fallback: %v", filename, err)
		return detectFileTypeByExtension(filename)
	}

	mimeType := mt.String()

	// Text-based MIME types
	textMimeTypes := []string{
		"text/",
		"application/json",
		"application/xml",
		"application/yaml",
		"application/x-yaml",
		"application/x-sh",
		"application/javascript",
		"application/x-javascript",
		"application/x-python",
		"application/x-perl",
		"application/x-ruby",
		"application/x-php",
		"application/x-shellscript",
		"application/x-sql",
		"application/x-csv",
		"application/x-www-form-urlencoded",
	}

	for _, textMime := range textMimeTypes {
		if strings.HasPrefix(mimeType, textMime) {
			return Text
		}
	}

	// Binary MIME types (images, executables, archives, etc.)
	// Everything else is considered binary
	return Binary
}

// detectFileTypeByExtension is a fallback that uses file extension
func detectFileTypeByExtension(filename string) FileType {
	ext := strings.ToLower(filepath.Ext(filename))
	textExtensions := []string{
		".sql", ".log", ".txt", ".yaml", ".yml", ".json",
		".xml", ".html", ".htm", ".css", ".js", ".sh",
		".py", ".pl", ".rb", ".php", ".go", ".java",
		".c", ".cpp", ".h", ".hpp", ".cs", ".rs",
		".md", ".markdown", ".csv", ".tsv", ".ini",
		".conf", ".config", ".cfg", ".properties",
	}

	for _, textExt := range textExtensions {
		if ext == textExt {
			return Text
		}
	}

	// Default to binary
	return Binary
}

// readTextFile reads a text file line by line and calculates entropy for each line
func readTextFile(filename string) ([]float64, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entropies []float64
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		ent := entropy(line)
		entropies = append(entropies, ent)
	}
	return entropies, scanner.Err()
}

// readBinaryFile reads a binary file in 1KB blocks and calculates entropy for each block
func readBinaryFile(filename string) ([]float64, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entropies []float64
	buffer := make([]byte, 1024) // 1KB block
	for {
		n, err := file.Read(buffer)
		if err != nil && err != io.EOF {
			return nil, err
		}
		if n == 0 {
			break
		}
		ent := entropy(buffer[:n])
		entropies = append(entropies, ent)
	}
	return entropies, nil
}

// printHistogram displays an ASCII histogram of the entropy distribution
func printHistogram(data []float64, binSize float64) {
	if len(data) == 0 {
		return
	}

	sort.Float64s(data)
	min, max := data[0], data[len(data)-1]

	// Number of bins
	bins := int((max-min)/binSize) + 1
	if bins <= 0 {
		bins = 1
	}
	counts := make([]int, bins)

	for _, v := range data {
		bin := int((v - min) / binSize)
		if bin >= bins {
			bin = bins - 1
		}
		if bin < 0 {
			bin = 0
		}
		counts[bin]++
	}

	// Find maximum for normalization
	maxCount := 0
	for _, c := range counts {
		if c > maxCount {
			maxCount = c
		}
	}
	if maxCount == 0 {
		maxCount = 1 // Avoid division by zero
	}

	// Display histogram
	fmt.Println("\nEntropy Distribution Histogram:")
	fmt.Println(strings.Repeat("-", 60))
	for i, c := range counts {
		binMin := min + float64(i)*binSize
		binMax := binMin + binSize
		barLength := c * 50 / maxCount
		if barLength > 50 {
			barLength = 50
		}
		bar := strings.Repeat("█", barLength)
		fmt.Printf("%.2f-%.2f: %5d |%s\n", binMin, binMax, c, bar)
	}
	fmt.Println(strings.Repeat("-", 60))
}

// suggestThreshold suggests a threshold based on the distribution
func suggestThreshold(data []float64, fileType FileType) float64 {
	if len(data) == 0 {
		return 6.5 // Default threshold (same as pipeline)
	}
	sort.Float64s(data)
	n := len(data)
	// For text files, use a lower percentile
	if fileType == Text {
		idx := int(float64(n) * 0.90)
		if idx >= n {
			idx = n - 1
		}
		return data[idx]
	}
	// For binary files, use a higher percentile
	idx := int(float64(n) * 0.95)
	if idx >= n {
		idx = n - 1
	}
	return data[idx]
}

// AnalysisResult represents the JSON output structure
type AnalysisResult struct {
	File               string            `json:"file"`
	MimeType           string            `json:"mime_type,omitempty"`
	FileType           string            `json:"file_type"` // "text" or "binary"
	Statistics         Statistics        `json:"statistics"`
	SuggestedThreshold float64           `json:"suggested_threshold"`
	PipelineThreshold  PipelineThreshold `json:"pipeline_threshold"`
	Histogram          []HistogramBin    `json:"histogram,omitempty"`
	Error              string            `json:"error,omitempty"`
}

type Statistics struct {
	Min     float64 `json:"min"`
	Max     float64 `json:"max"`
	Median  float64 `json:"median"`
	Mean    float64 `json:"mean"`
	Samples int     `json:"samples"`
}

type PipelineThreshold struct {
	Threshold      float64 `json:"threshold"`
	AboveThreshold int     `json:"above_threshold"`
	Percentage     float64 `json:"percentage"`
}

type HistogramBin struct {
	Range string `json:"range"`
	Count int    `json:"count"`
}

func generateHistogramBins(data []float64, binSize float64) []HistogramBin {
	if len(data) == 0 {
		return nil
	}

	sort.Float64s(data)
	min, max := data[0], data[len(data)-1]
	bins := int((max-min)/binSize) + 1
	if bins <= 0 {
		bins = 1
	}
	counts := make([]int, bins)

	for _, v := range data {
		bin := int((v - min) / binSize)
		if bin >= bins {
			bin = bins - 1
		}
		if bin < 0 {
			bin = 0
		}
		counts[bin]++
	}

	var histogram []HistogramBin
	for i, c := range counts {
		binMin := min + float64(i)*binSize
		binMax := binMin + binSize
		histogram = append(histogram, HistogramBin{
			Range: fmt.Sprintf("%.2f-%.2f", binMin, binMax),
			Count: c,
		})
	}

	return histogram
}

func analyzeFile(filename string) (*AnalysisResult, []float64) {
	result := &AnalysisResult{
		File: filename,
	}

	// Detect MIME type
	mt, mimeErr := mimetype.DetectFile(filename)
	if mimeErr == nil {
		result.MimeType = mt.String()
	}

	fileType := detectFileType(filename)
	if fileType == Text {
		result.FileType = "text"
	} else {
		result.FileType = "binary"
	}

	var entropies []float64
	var err error

	switch fileType {
	case Text:
		entropies, err = readTextFile(filename)
	case Binary:
		entropies, err = readBinaryFile(filename)
	}

	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	if len(entropies) == 0 {
		result.Error = "no data to analyze"
		return result, nil
	}

	// Calculate statistics
	sort.Float64s(entropies)
	result.Statistics = Statistics{
		Min:     entropies[0],
		Max:     entropies[len(entropies)-1],
		Median:  entropies[len(entropies)/2],
		Mean:    average(entropies),
		Samples: len(entropies),
	}

	// Generate histogram
	result.Histogram = generateHistogramBins(entropies, 0.5)

	// Suggested threshold
	result.SuggestedThreshold = suggestThreshold(entropies, fileType)

	// Pipeline threshold analysis
	aboveThreshold := 0
	for _, e := range entropies {
		if e > 6.5 {
			aboveThreshold++
		}
	}
	percentage := float64(aboveThreshold) / float64(len(entropies)) * 100
	result.PipelineThreshold = PipelineThreshold{
		Threshold:      6.5,
		AboveThreshold: aboveThreshold,
		Percentage:     percentage,
	}

	return result, entropies
}

func main() {
	jsonFlag := flag.Bool("json", false, "Output results in JSON format")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [--json] <file1> [file2] [file3]...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  --json    Output results in JSON format\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	var results []*AnalysisResult
	var allEntropies [][]float64

	for _, filename := range flag.Args() {
		result, entropies := analyzeFile(filename)
		results = append(results, result)
		allEntropies = append(allEntropies, entropies)
	}

	if *jsonFlag {
		// Output JSON
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if len(results) == 1 {
			encoder.Encode(results[0])
		} else {
			encoder.Encode(results)
		}
	} else {
		// Output text format
		for i, result := range results {
			if result.Error != "" {
				log.Printf("Error analyzing %s: %s\n", result.File, result.Error)
				continue
			}

			entropies := allEntropies[i]
			fileType := Text
			if result.FileType == "binary" {
				fileType = Binary
			}

			fmt.Printf("\n=== Analyzing file: %s ===\n", result.File)
			if result.MimeType != "" {
				fmt.Printf("MIME type: %s\n", result.MimeType)
			}
			if fileType == Text {
				fmt.Println("Detected type: Text (analyzing line by line)")
			} else {
				fmt.Println("Detected type: Binary (analyzing in 1KB blocks)")
			}

			fmt.Printf("\nEntropy statistics (bits/byte):\n")
			fmt.Printf("  Min: %.3f, Max: %.3f\n", result.Statistics.Min, result.Statistics.Max)
			fmt.Printf("  Median: %.3f, Mean: %.3f\n", result.Statistics.Median, result.Statistics.Mean)
			fmt.Printf("  Samples: %d\n", result.Statistics.Samples)

			// Histogram
			printHistogram(entropies, 0.5)

			fmt.Printf("\nSuggested threshold for anomaly detection: %.3f\n", result.SuggestedThreshold)
			fmt.Printf("  (Pipeline uses 6.5 as high entropy threshold)\n")
			if fileType == Text {
				fmt.Println("  - Below threshold: normal text or SQL")
				fmt.Println("  - Above threshold: encoded, encrypted, or binary data")
			} else {
				fmt.Println("  - Below threshold: normal binary data")
				fmt.Println("  - Above threshold: highly random areas (encryption, compression)")
			}

			if result.PipelineThreshold.AboveThreshold > 0 {
				fmt.Printf("\n  Samples above pipeline threshold (6.5): %d (%.1f%%)\n",
					result.PipelineThreshold.AboveThreshold, result.PipelineThreshold.Percentage)
			}
		}
	}
}

func printHistogramFromBins(bins []HistogramBin) {
	if len(bins) == 0 {
		return
	}

	maxCount := 0
	for _, bin := range bins {
		if bin.Count > maxCount {
			maxCount = bin.Count
		}
	}
	if maxCount == 0 {
		maxCount = 1
	}

	fmt.Println("\nEntropy Distribution Histogram:")
	fmt.Println(strings.Repeat("-", 60))
	for _, bin := range bins {
		barLength := bin.Count * 50 / maxCount
		if barLength > 50 {
			barLength = 50
		}
		bar := strings.Repeat("█", barLength)
		fmt.Printf("%s: %5d |%s\n", bin.Range, bin.Count, bar)
	}
	fmt.Println(strings.Repeat("-", 60))
}

func average(data []float64) float64 {
	sum := 0.0
	for _, v := range data {
		sum += v
	}
	return sum / float64(len(data))
}
