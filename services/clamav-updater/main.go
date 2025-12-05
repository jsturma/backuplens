package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type UpdateResponse struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

type HealthResponse struct {
	Status     string `json:"status"`
	ClamAVHost string `json:"clamav_host"`
}

var (
	clamavHost = "clamav"
	clamavPort = "3310"
)

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, HealthResponse{
		Status:     "healthy",
		ClamAVHost: fmt.Sprintf("%s:%s", clamavHost, clamavPort),
	})
}

func detectContainerRuntime() string {
	// Check for Podman binary first (preferred)
	if _, err := exec.LookPath("podman"); err == nil {
		// Check if Podman socket is mounted (indicates we're in a Podman environment)
		// Use a file access check that works even with permission issues
		_, statErr := os.Stat("/run/podman/podman.sock")
		// If file exists (even if we can't read it due to permissions), socket is mounted
		if statErr == nil || !os.IsNotExist(statErr) {
			// Socket file exists (even if we can't access it), use Podman
			return "podman"
		}
		// Also try Podman for local runs (without socket check)
		// Try a simple command to see if Podman works
		cmd := exec.Command("podman", "version", "--format", "{{.Version}}")
		cmd.Stderr = nil
		cmd.Stdout = nil
		if err := cmd.Run(); err == nil {
			return "podman"
		}
	}

	// Fall back to Docker
	if _, err := exec.LookPath("docker"); err == nil {
		return "docker"
	}

	return ""
}

func updateClamAVHandler(c *gin.Context) {
	// Detect container runtime (Podman or Docker)
	runtime := detectContainerRuntime()
	if runtime == "" {
		c.JSON(http.StatusInternalServerError, UpdateResponse{
			Success:   false,
			Message:   "Neither Podman nor Docker found in PATH",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	// Execute freshclam in the ClamAV container
	var cmd *exec.Cmd
	if runtime == "podman" {
		// Use Podman - only set CONTAINER_HOST if socket is mounted (in container)
		// On macOS, Podman uses SSH connections automatically, so don't override
		cmd = exec.Command("podman", "exec", "clamav", "freshclam")
		// Check if we're in a container environment with socket mounted
		_, statErr := os.Stat("/run/podman/podman.sock")
		if statErr == nil || !os.IsNotExist(statErr) {
			// Socket exists (even if we can't read it), set CONTAINER_HOST for remote mode
			// Also disable local storage to avoid overlayfs conflicts
			cmd.Env = append(os.Environ(),
				"CONTAINER_HOST=unix:///run/podman/podman.sock",
				"CONTAINERS_CONF=/dev/null", // Disable local config to force remote mode
			)
		}
		// If socket doesn't exist (local macOS run), Podman will use default connection
	} else {
		cmd = exec.Command(runtime, "exec", "clamav", "freshclam")
	}

	output, err := cmd.CombinedOutput()
	outputStr := string(output)

	// Check for specific error conditions in output
	if err != nil {
		// Check for rate limiting (429/403 errors)
		if strings.Contains(outputStr, "error code 429") || strings.Contains(outputStr, "error code 403") {
			log.Printf("ClamAV update rate limited (%s): %s", runtime, outputStr)
			c.JSON(http.StatusTooManyRequests, UpdateResponse{
				Success:   false,
				Message:   fmt.Sprintf("Rate limited by ClamAV CDN. Please wait before retrying.\n\n%s", outputStr),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
			return
		}

		// Check for outdated ClamAV version
		if strings.Contains(outputStr, "OUTDATED") {
			log.Printf("ClamAV installation is outdated (%s): %s", runtime, outputStr)
			c.JSON(http.StatusBadRequest, UpdateResponse{
				Success:   false,
				Message:   fmt.Sprintf("ClamAV installation is outdated. Please update the ClamAV container image.\n\n%s", outputStr),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
			return
		}

		// Check for cooldown period
		if strings.Contains(outputStr, "cool-down") || strings.Contains(outputStr, "retry-after") {
			log.Printf("ClamAV update on cooldown (%s): %s", runtime, outputStr)
			c.JSON(http.StatusTooManyRequests, UpdateResponse{
				Success:   false,
				Message:   fmt.Sprintf("Update on cooldown. Please wait before retrying.\n\n%s", outputStr),
				Timestamp: time.Now().UTC().Format(time.RFC3339),
			})
			return
		}

		// Generic error
		log.Printf("ClamAV update failed (%s): %v, output: %s", runtime, err, outputStr)
		c.JSON(http.StatusInternalServerError, UpdateResponse{
			Success:   false,
			Message:   fmt.Sprintf("Update failed (%s): %v\n\nOutput: %s", runtime, err, outputStr),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	log.Printf("ClamAV database updated successfully (%s): %s", runtime, outputStr)
	c.JSON(http.StatusOK, UpdateResponse{
		Success:   true,
		Message:   fmt.Sprintf("Database updated successfully (%s)\n%s", runtime, outputStr),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

func main() {
	// Get configuration from environment
	if h := os.Getenv("CLAMAV_HOST"); h != "" {
		clamavHost = h
	}
	if p := os.Getenv("CLAMAV_PORT"); p != "" {
		clamavPort = p
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// Routes
	r.GET("/health", healthHandler)
	r.POST("/update", updateClamAVHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	log.Printf("ClamAV Updater service starting on :%s", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
