package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestFinalProductionValidation performs comprehensive production readiness validation
func TestFinalProductionValidation(t *testing.T) {
	t.Log("🚀 Final Production Deployment Validation")
	t.Log("==========================================")

	// Step 1: Configuration validation
	t.Log("Step 1: Configuration Structure Validation")

	data, err := os.ReadFile("config.json")
	if err != nil {
		t.Errorf("Cannot read config.json: %v", err)
		return
	}

	var config struct {
		Server struct {
			Interface string `json:"interface"`
			Port      int    `json:"port"`
		} `json:"server"`
		Database struct {
			Type string `json:"type"`
			Path string `json:"path"`
		} `json:"database"`
		Security struct {
			SessionMaxAge     int      `json:"session_max_age"`
			RateLimitRequests int      `json:"rate_limit_requests"`
			RateLimitWindow   int      `json:"rate_limit_window"`
			EnableHTTPS       bool     `json:"enable_https"`
			CertFile          string   `json:"cert_file"`
			KeyFile           string   `json:"key_file"`
			AllowedOrigins    []string `json:"allowed_origins"`
		} `json:"security"`
		Cluster struct {
			Enabled     bool     `json:"enabled"`
			NodeID      string   `json:"node_id"`
			GossipNodes []string `json:"gossip_nodes"`
		} `json:"cluster"`
		Storage struct {
			URL            string `json:"url"`
			HealthCheckURL string `json:"health_check_url"`
		} `json:"storage"`
	}

	if err := json.Unmarshal(data, &config); err != nil {
		t.Errorf("Invalid JSON in config.json: %v", err)
		return
	}

	t.Log("✅ Configuration structure is valid")

	// Step 2: Server configuration validation
	t.Log("Step 2: Server Configuration Validation")

	if config.Server.Interface == "" {
		t.Error("Server interface not configured")
	} else {
		t.Logf("✅ Server interface: %s", config.Server.Interface)
	}

	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		t.Error("Invalid server port")
	} else {
		t.Logf("✅ Server port: %d", config.Server.Port)
	}

	// Step 3: Database configuration validation
	t.Log("Step 3: Database Configuration Validation")

	if config.Database.Type == "" {
		t.Error("Database type not configured")
	} else {
		t.Logf("✅ Database type: %s", config.Database.Type)
	}

	if config.Database.Path == "" {
		t.Error("Database path not configured")
	} else {
		t.Logf("✅ Database path: %s", config.Database.Path)
	}

	// Step 4: Security configuration validation
	t.Log("Step 4: Security Configuration Validation")

	secretKey := os.Getenv("SECRET_KEY")
	if secretKey == "" {
		t.Error("SECRET_KEY environment variable not set")
	} else if len(secretKey) < 32 {
		t.Error("SECRET_KEY too short for production (minimum 32 characters)")
	} else {
		t.Logf("✅ Secret key length: %d characters", len(secretKey))

		// Check for weak patterns
		secretLower := strings.ToLower(secretKey)
		weakPatterns := []string{"password", "12345", "admin", "test"}
		hasWeakPattern := false
		for _, pattern := range weakPatterns {
			if strings.Contains(secretLower, pattern) {
				t.Errorf("Secret key contains weak pattern: %s", pattern)
				hasWeakPattern = true
			}
		}
		if !hasWeakPattern {
			t.Log("✅ Secret key appears secure")
		}
	}

	if config.Security.RateLimitRequests <= 0 {
		t.Error("Rate limiting not configured")
	} else {
		t.Logf("✅ Rate limiting: %d requests per %d seconds",
			config.Security.RateLimitRequests, config.Security.RateLimitWindow)
	}

	if !config.Security.EnableHTTPS {
		t.Log("WARNING: HTTPS not enabled - consider enabling for production")
	} else {
		t.Log("✅ HTTPS enabled")
		if config.Security.CertFile == "" || config.Security.KeyFile == "" {
			t.Error("HTTPS enabled but certificate files not specified")
		}
	}

	// Step 5: Environment validation
	t.Log("Step 5: Environment Validation")

	ginMode := os.Getenv("GIN_MODE")
	if ginMode != "release" {
		t.Log("WARNING: GIN_MODE not set to 'release'")
	} else {
		t.Log("✅ GIN_MODE set to release")
	}

	// Step 6: File structure validation
	t.Log("Step 6: File Structure Validation")

	requiredFiles := []string{
		"main.go",
		"routes.go",
		"models.go",
		"config.go",
		"middleware.go",
		"errors.go",
		"go.mod",
		"ghostkey_server.exe",
	}

	fileErrors := 0
	for _, file := range requiredFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			t.Errorf("Required file missing: %s", file)
			fileErrors++
		} else {
			t.Logf("✅ %s exists", file)
		}
	}

	// Step 7: Directory structure validation
	t.Log("Step 7: Directory Structure Validation")

	requiredDirs := []string{
		"logs",
		"data",
		"uploads",
		"backups",
		"cargo_files",
	}

	dirErrors := 0
	for _, dir := range requiredDirs {
		if info, err := os.Stat(dir); os.IsNotExist(err) {
			t.Errorf("Required directory missing: %s", dir)
			dirErrors++
		} else if !info.IsDir() {
			t.Errorf("%s exists but is not a directory", dir)
			dirErrors++
		} else {
			t.Logf("✅ Directory %s exists", dir)
		}
	}

	// Step 8: Build validation
	t.Log("Step 8: Build Validation")

	if _, err := os.Stat("ghostkey_server.exe"); os.IsNotExist(err) {
		t.Error("Application executable not found")
	} else {
		t.Log("✅ Application executable exists")
	}

	// Step 9: Support scripts validation
	t.Log("Step 9: Support Scripts Validation")

	supportScripts := []string{
		"start-server.ps1",
		"backup.ps1",
		"install-service.ps1",
	}

	for _, script := range supportScripts {
		if _, err := os.Stat(script); os.IsNotExist(err) {
			t.Logf("Optional script missing: %s", script)
		} else {
			t.Logf("✅ %s exists", script)
		}
	}

	// Final summary
	t.Log("")
	t.Log("🏁 FINAL DEPLOYMENT SUMMARY")
	t.Log("===========================")

	totalErrors := fileErrors + dirErrors
	if secretKey == "" || len(secretKey) < 32 {
		totalErrors++
	}
	if config.Security.RateLimitRequests <= 0 {
		totalErrors++
	}

	if totalErrors == 0 {
		t.Log("🎉 ALL PRODUCTION VALIDATION CHECKS PASSED!")
		t.Log("✅ Configuration is valid")
		t.Log("✅ Security settings are configured")
		t.Log("✅ All required files exist")
		t.Log("✅ Directory structure is correct")
		t.Log("✅ Application is built and ready")
		t.Log("")
		t.Log("🚀 READY FOR PRODUCTION DEPLOYMENT!")
		t.Log("")
		t.Log("Next steps:")
		t.Log("1. Start the server: .\\start-server.ps1")
		t.Log("2. Test all endpoints")
		t.Log("3. Monitor logs and performance")
		t.Log("4. Set up regular backups")
		t.Log("5. Configure monitoring/alerting")
	} else {
		t.Errorf("❌ %d critical issues found - address before deploying", totalErrors)
	}
}

// TestProductionSecurityChecklist performs security-focused validation
func TestProductionSecurityChecklist(t *testing.T) {
	t.Log("🔒 Production Security Checklist")
	t.Log("================================")

	securityChecks := []struct {
		name string
		test func() error
	}{
		{
			"Secret key is set and secure",
			func() error {
				secretKey := os.Getenv("SECRET_KEY")
				if secretKey == "" {
					return fmt.Errorf("SECRET_KEY not set")
				}
				if len(secretKey) < 32 {
					return fmt.Errorf("SECRET_KEY too short")
				}
				return nil
			},
		},
		{
			"Configuration file has proper structure",
			func() error {
				data, err := os.ReadFile("config.json")
				if err != nil {
					return err
				}
				var config map[string]interface{}
				return json.Unmarshal(data, &config)
			},
		},
		{
			"Rate limiting is configured",
			func() error {
				data, err := os.ReadFile("config.json")
				if err != nil {
					return err
				}
				var config struct {
					Security struct {
						RateLimitRequests int `json:"rate_limit_requests"`
					} `json:"security"`
				}
				if err := json.Unmarshal(data, &config); err != nil {
					return err
				}
				if config.Security.RateLimitRequests <= 0 {
					return fmt.Errorf("rate limiting not configured")
				}
				return nil
			},
		},
		{
			"GIN_MODE set to release",
			func() error {
				if os.Getenv("GIN_MODE") != "release" {
					return fmt.Errorf("GIN_MODE not set to release")
				}
				return nil
			},
		},
		{
			"Application executable exists",
			func() error {
				if _, err := os.Stat("ghostkey_server.exe"); os.IsNotExist(err) {
					return fmt.Errorf("executable not found")
				}
				return nil
			},
		},
	}

	passed := 0
	total := len(securityChecks)

	for _, check := range securityChecks {
		if err := check.test(); err != nil {
			t.Errorf("❌ %s: %v", check.name, err)
		} else {
			t.Logf("✅ %s", check.name)
			passed++
		}
	}

	t.Logf("\nSecurity Checklist: %d/%d checks passed", passed, total)

	if passed == total {
		t.Log("🔒 All security checks passed! Production ready.")
	} else {
		t.Errorf("❌ %d security checks failed.", total-passed)
	}
}
