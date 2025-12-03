package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
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
	// Check for Podman first (preferred)
	if _, err := exec.LookPath("podman"); err == nil {
		// Verify podman is working
		cmd := exec.Command("podman", "version", "--format", "{{.Version}}")
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
	cmd := exec.Command(runtime, "exec", "clamav", "freshclam")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("ClamAV update failed (%s): %v, output: %s", runtime, err, string(output))
		c.JSON(http.StatusInternalServerError, UpdateResponse{
			Success:   false,
			Message:   fmt.Sprintf("Update failed (%s): %v\nOutput: %s", runtime, err, string(output)),
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	log.Printf("ClamAV database updated successfully (%s): %s", runtime, string(output))
	c.JSON(http.StatusOK, UpdateResponse{
		Success:   true,
		Message:   fmt.Sprintf("Database updated successfully (%s)\n%s", runtime, string(output)),
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
