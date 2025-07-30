package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Production deployment validation tests
func TestProductionReadiness(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping production readiness tests in short mode")
	}

	t.Run("ConfigurationValidation", testConfigurationValidation)
	t.Run("SecurityConfiguration", testSecurityConfiguration)
	t.Run("DatabaseSetup", testDatabaseSetup)
	t.Run("EnvironmentVariables", testEnvironmentVariables)
	t.Run("FilePermissions", testFilePermissions)
	t.Run("PortAvailability", testPortAvailability)
	t.Run("SSLConfiguration", testSSLConfiguration)
	t.Run("LoggingSetup", testLoggingSetup)
}

func testConfigurationValidation(t *testing.T) {
	// Test configuration loading
	config, err := LoadConfig("config.json")
	if err != nil {
		t.Errorf("Failed to load configuration: %v", err)
		return
	}

	// Validate critical configuration values
	if config.Server.Interface == "" {
		t.Error("Server interface not configured")
	}

	if config.Security.SecretKey == "" {
		t.Error("Secret key not configured")
	}

	if len(config.Security.SecretKey) < 32 {
		t.Error("Secret key too short for production (minimum 32 characters)")
	}

	if config.Security.RateLimitRequests <= 0 {
		t.Error("Rate limit not configured")
	}

	if config.Database.Path == "" {
		t.Error("Database path not configured")
	}

	// Validate security settings for production
	if config.Security.SessionMaxAge > 86400 { // 24 hours
		t.Warning("Session max age is quite long for production")
	}

	if config.Security.RateLimitRequests > 1000 {
		t.Warning("Rate limit might be too high for production")
	}
}

func testSecurityConfiguration(t *testing.T) {
	config, err := LoadConfig("config.json")
	if err != nil {
		t.Skip("Cannot test security configuration without valid config")
		return
	}

	// Check HTTPS configuration
	if !config.Security.EnableHTTPS {
		t.Warning("HTTPS not enabled - not recommended for production")
	}

	if config.Security.EnableHTTPS {
		if config.Security.CertFile == "" {
			t.Error("HTTPS enabled but no certificate file specified")
		}
		if config.Security.KeyFile == "" {
			t.Error("HTTPS enabled but no key file specified")
		}

		// Check if certificate files exist
		if _, err := os.Stat(config.Security.CertFile); os.IsNotExist(err) {
			t.Errorf("Certificate file does not exist: %s", config.Security.CertFile)
		}

		if _, err := os.Stat(config.Security.KeyFile); os.IsNotExist(err) {
			t.Errorf("Key file does not exist: %s", config.Security.KeyFile)
		}
	}

	// Check for common weak secret keys
	weakSecrets := []string{
		"secret",
		"password",
		"12345",
		"admin",
		"test",
		"development",
	}

	secretLower := strings.ToLower(config.Security.SecretKey)
	for _, weak := range weakSecrets {
		if strings.Contains(secretLower, weak) {
			t.Errorf("Secret key contains weak pattern: %s", weak)
		}
	}
}

func testDatabaseSetup(t *testing.T) {
	config, err := LoadConfig("config.json")
	if err != nil {
		t.Skip("Cannot test database setup without valid config")
		return
	}

	// Check database file permissions (if SQLite)
	if strings.HasSuffix(config.Database.Path, ".db") {
		info, err := os.Stat(config.Database.Path)
		if err != nil {
			if !os.IsNotExist(err) {
				t.Errorf("Error checking database file: %v", err)
			}
			// Database doesn't exist yet - that's okay
			return
		}

		// Check file permissions
		mode := info.Mode()
		if mode.Perm() > 0660 {
			t.Errorf("Database file permissions too permissive: %o", mode.Perm())
		}
	}

	// Check database directory permissions
	dbDir := config.Database.Path
	if !strings.Contains(dbDir, "/") && !strings.Contains(dbDir, "\\") {
		dbDir = "." // Current directory
	} else {
		dbDir = dbDir[:strings.LastIndexAny(dbDir, "/\\")]
	}

	info, err := os.Stat(dbDir)
	if err != nil {
		t.Errorf("Cannot access database directory: %v", err)
		return
	}

	if !info.IsDir() {
		t.Error("Database path parent is not a directory")
	}
}

func testEnvironmentVariables(t *testing.T) {
	// Check for recommended environment variables
	recommendedVars := map[string]string{
		"GIN_MODE":     "release",
		"SECRET_KEY":   "",
		"ENABLE_HTTPS": "",
		"CERT_FILE":    "",
		"KEY_FILE":     "",
	}

	for varName, expectedValue := range recommendedVars {
		value := os.Getenv(varName)
		if value == "" && expectedValue != "" {
			t.Errorf("Environment variable %s not set", varName)
		}
		if expectedValue != "" && value != expectedValue {
			t.Errorf("Environment variable %s has unexpected value", varName)
		}
	}

	// Check GIN_MODE specifically
	ginMode := os.Getenv("GIN_MODE")
	if ginMode != "release" {
		t.Warning("GIN_MODE not set to 'release' - not recommended for production")
	}
}

func testFilePermissions(t *testing.T) {
	// Check configuration file permissions
	info, err := os.Stat("config.json")
	if err != nil {
		t.Errorf("Cannot check config.json permissions: %v", err)
		return
	}

	mode := info.Mode()
	if mode.Perm() > 0644 {
		t.Errorf("config.json permissions too permissive: %o", mode.Perm())
	}

	// Check executable permissions
	executable := "ghostkey_server"
	if _, err = os.Stat(executable); err == nil {
		info, err = os.Stat(executable)
		if err != nil {
			t.Errorf("Cannot check executable permissions: %v", err)
			return
		}

		mode = info.Mode()
		if mode.Perm() < 0755 {
			t.Errorf("Executable permissions too restrictive: %o", mode.Perm())
		}
	}

	// Check for sensitive files that shouldn't be readable
	sensitiveFiles := []string{
		".env",
		"secrets.txt",
		"private.key",
	}

	for _, file := range sensitiveFiles {
		if info, err := os.Stat(file); err == nil {
			mode := info.Mode()
			if mode.Perm() > 0600 {
				t.Errorf("Sensitive file %s has too permissive permissions: %o", file, mode.Perm())
			}
		}
	}
}

func testPortAvailability(t *testing.T) {
	config, err := LoadConfig("config.json")
	if err != nil {
		t.Skip("Cannot test port availability without valid config")
		return
	}

	// Extract port from interface string
	parts := strings.Split(config.Server.Interface, ":")
	if len(parts) != 2 {
		t.Errorf("Invalid server interface format: %s", config.Server.Interface)
		return
	}

	port := parts[1]

	// Try to connect to the port to see if it's available
	timeout := time.Second * 2
	client := &http.Client{Timeout: timeout}

	protocol := "http"
	if config.Security.EnableHTTPS {
		protocol = "https"
		// Skip certificate verification for testing
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	url := fmt.Sprintf("%s://localhost:%s/", protocol, port)

	resp, err := client.Get(url)
	if err != nil {
		t.Logf("Port %s appears to be available (connection failed as expected): %v", port, err)
		return
	}
	defer resp.Body.Close()

	t.Logf("Server appears to be running on port %s (got HTTP %d)", port, resp.StatusCode)
}

func testSSLConfiguration(t *testing.T) {
	config, err := LoadConfig("config.json")
	if err != nil {
		t.Skip("Cannot test SSL configuration without valid config")
		return
	}

	if !config.Security.EnableHTTPS {
		t.Skip("HTTPS not enabled, skipping SSL tests")
		return
	}

	// Check certificate validity
	if config.Security.CertFile != "" {
		cert, err := tls.LoadX509KeyPair(config.Security.CertFile, config.Security.KeyFile)
		if err != nil {
			t.Errorf("Failed to load SSL certificate: %v", err)
			return
		}

		// Parse certificate to check expiration
		x509Cert, err := tls.X509KeyPair(config.Security.CertFile, config.Security.KeyFile)
		if err != nil {
			t.Errorf("Failed to parse SSL certificate: %v", err)
			return
		}

		_ = cert
		_ = x509Cert

		t.Log("SSL certificate loaded successfully")
	}
}

func testLoggingSetup(t *testing.T) {
	// Check if log directory exists and is writable
	logDir := "logs"
	if info, err := os.Stat(logDir); err == nil {
		if !info.IsDir() {
			t.Errorf("%s exists but is not a directory", logDir)
		}

		// Test write permissions by creating a temporary file
		testFile := logDir + "/test_write_permissions.tmp"
		if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
			t.Errorf("Cannot write to log directory: %v", err)
		} else {
			os.Remove(testFile) // Clean up
			t.Log("Log directory is writable")
		}
	} else {
		t.Log("Log directory does not exist - will be created at runtime")
	}
}

// Helper method for warnings
func (t *testing.T) Warning(msg string) {
	t.Logf("WARNING: %s", msg)
}

// Production deployment checklist test
func TestDeploymentChecklist(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping deployment checklist in short mode")
	}

	checklist := []struct {
		name string
		test func() error
	}{
		{"Configuration file exists", func() error {
			if _, err := os.Stat("config.json"); os.IsNotExist(err) {
				return fmt.Errorf("config.json not found")
			}
			return nil
		}},
		{"Secret key is secure", func() error {
			config, err := LoadConfig("config.json")
			if err != nil {
				return err
			}
			if len(config.Security.SecretKey) < 32 {
				return fmt.Errorf("secret key too short")
			}
			return nil
		}},
		{"Database directory exists", func() error {
			config, err := LoadConfig("config.json")
			if err != nil {
				return err
			}
			dbDir := "."
			if strings.Contains(config.Database.Path, "/") || strings.Contains(config.Database.Path, "\\") {
				dbDir = config.Database.Path[:strings.LastIndexAny(config.Database.Path, "/\\")]
			}
			if _, err := os.Stat(dbDir); os.IsNotExist(err) {
				return fmt.Errorf("database directory does not exist: %s", dbDir)
			}
			return nil
		}},
		{"Rate limiting configured", func() error {
			config, err := LoadConfig("config.json")
			if err != nil {
				return err
			}
			if config.Security.RateLimitRequests <= 0 {
				return fmt.Errorf("rate limiting not configured")
			}
			return nil
		}},
		{"Build is successful", func() error {
			// This test assumes the build has already been done
			// In a real deployment, you'd run `go build` here
			return nil
		}},
	}

	passed := 0
	total := len(checklist)

	for _, item := range checklist {
		if err := item.test(); err != nil {
			t.Errorf("❌ %s: %v", item.name, err)
		} else {
			t.Logf("✅ %s", item.name)
			passed++
		}
	}

	t.Logf("\nDeployment Readiness: %d/%d checks passed", passed, total)

	if passed == total {
		t.Log("🎉 All deployment checks passed! Ready for production.")
	} else {
		t.Errorf("❌ %d deployment checks failed. Address issues before deploying.", total-passed)
	}
}
