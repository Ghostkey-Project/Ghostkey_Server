package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Integration test suite
func TestIntegrationSuite(t *testing.T) {
	// Setup test environment
	gin.SetMode(gin.TestMode)

	// Create test database
	testDB, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	// Migrate the schema
	testDB.AutoMigrate(&User{}, &ESPDevice{}, &Command{}, &FileMetadata{}, &Counter{})

	// Replace global db with test database
	originalDB := db
	db = testDB
	defer func() { db = originalDB }()

	// Load test configuration
	testConfig, err := LoadConfig("config.json")
	if err != nil {
		// Use default configuration if config file doesn't exist
		testConfig = &ServerConfig{
			Server: ServerSettings{
				Interface: ":8080",
			},
			Security: SecuritySettings{
				SecretKey:         "test-secret-key-12345678901234567890",
				RateLimitRequests: 100,
				RateLimitWindow:   60,
				SessionMaxAge:     3600,
				EnableHTTPS:       false,
			},
			Database: DatabaseSettings{
				Path: ":memory:",
			},
		}
	}

	// Replace global server config
	originalConfig := serverConfig
	serverConfig = testConfig
	defer func() { serverConfig = originalConfig }()

	// Create test router with middleware
	router := gin.New()
	router.Use(SecurityHeadersMiddleware())
	router.Use(CORSMiddleware())
	router.Use(RateLimitMiddleware(testConfig.Security.RateLimitRequests, time.Duration(testConfig.Security.RateLimitWindow)*time.Second))

	// Setup sessions
	store := cookie.NewStore([]byte(testConfig.Security.SecretKey))
	store.Options(sessions.Options{
		MaxAge:   testConfig.Security.SessionMaxAge,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Disable for testing
	})
	router.Use(sessions.Sessions("testsession", store))

	// Register routes
	registerRoutes(router)

	// Run integration tests
	t.Run("AuthenticationFlow", func(t *testing.T) {
		testAuthenticationFlow(t, router)
	})

	t.Run("DeviceManagement", func(t *testing.T) {
		testDeviceManagement(t, router)
	})

	t.Run("CommandManagement", func(t *testing.T) {
		testCommandManagement(t, router)
	})

	t.Run("FileUploadFlow", func(t *testing.T) {
		testFileUploadFlow(t, router)
	})

	t.Run("SecurityHeaders", func(t *testing.T) {
		testSecurityHeaders(t, router)
	})

	t.Run("RateLimiting", func(t *testing.T) {
		testRateLimiting(t, router)
	})

	t.Run("ErrorHandling", func(t *testing.T) {
		testErrorHandling(t, router)
	})
}

// Test complete authentication flow
func testAuthenticationFlow(t *testing.T, router *gin.Engine) {
	// Test user registration
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/register", strings.NewReader("username=testuser&password=testpass123&secret_key="+serverConfig.Security.SecretKey))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("User registration failed. Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Test login with valid credentials
	w = httptest.NewRecorder()
	loginData := map[string]string{
		"username": "testuser",
		"password": "testpass123",
	}
	jsonData, _ := json.Marshal(loginData)
	req, _ = http.NewRequest("POST", "/authenticate", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Authentication failed. Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Test login with invalid credentials
	w = httptest.NewRecorder()
	loginData = map[string]string{
		"username": "testuser",
		"password": "wrongpassword",
	}
	jsonData, _ = json.Marshal(loginData)
	req, _ = http.NewRequest("POST", "/authenticate", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected authentication failure. Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

// Test device registration and management
func testDeviceManagement(t *testing.T, router *gin.Engine) {
	// Register a device
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/register_device", strings.NewReader("esp_id=TEST_ESP_001&esp_secret_key=secret123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("testuser", "testpass123")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Device registration failed. Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}

	// Try to register the same device again (should fail)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/register_device", strings.NewReader("esp_id=TEST_ESP_001&esp_secret_key=secret123"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("testuser", "testpass123")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusConflict {
		t.Errorf("Expected device conflict. Expected status %d, got %d", http.StatusConflict, w.Code)
	}

	// Remove the device
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("DELETE", "/remove_device?esp_id=TEST_ESP_001&secret_key=secret123", nil)
	req.SetBasicAuth("testuser", "testpass123")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Device removal failed. Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

// Test command management flow
func testCommandManagement(t *testing.T, router *gin.Engine) {
	// First register a device
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/register_device", strings.NewReader("esp_id=CMD_TEST_ESP&esp_secret_key=cmdsecret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("testuser", "testpass123")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Device registration for command test failed. Status: %d, Body: %s", w.Code, w.Body.String())
	}

	// Add commands
	commands := []string{"RESTART", "UPDATE_CONFIG", "GET_STATUS"}
	for _, cmd := range commands {
		w = httptest.NewRecorder()
		req, _ = http.NewRequest("POST", "/command", strings.NewReader("esp_id=CMD_TEST_ESP&command="+cmd))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("testuser", "testpass123")
		router.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Command addition failed for %s. Status: %d, Body: %s", cmd, w.Code, w.Body.String())
		}
	}

	// Load commands using loadedCommand endpoint
	loadPayload := LoadedCommandPayload{
		EspID:    "CMD_TEST_ESP",
		Commands: []string{"BULK_CMD_1", "BULK_CMD_2", "BULK_CMD_3"},
	}
	jsonData, _ := json.Marshal(loadPayload)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/loaded_command", bytes.NewBuffer(jsonData))
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth("testuser", "testpass123")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Bulk command loading failed. Status: %d, Body: %s", w.Code, w.Body.String())
	}

	// Get loaded commands
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/loaded_command?esp_id=CMD_TEST_ESP", nil)
	req.SetBasicAuth("testuser", "testpass123")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Getting loaded commands failed. Status: %d, Body: %s", w.Code, w.Body.String())
	}

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)

	// Check if commands were loaded correctly
	if data, ok := response["data"].(map[string]interface{}); ok {
		if commands, ok := data["commands"].([]interface{}); ok {
			if len(commands) != 3 {
				t.Errorf("Expected 3 loaded commands, got %d", len(commands))
			}
		}
	}

	// Test device getting commands
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/get_command?esp_id=CMD_TEST_ESP&esp_secret_key=cmdsecret", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Device getting command failed. Status: %d, Body: %s", w.Code, w.Body.String())
	}
}

// Test file upload functionality
func testFileUploadFlow(t *testing.T, router *gin.Engine) {
	// Create a temporary file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_upload.txt")
	testContent := "This is a test file for upload integration testing."
	err := os.WriteFile(tmpFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Open the file
	file, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer file.Close()

	// Create multipart form
	var b bytes.Buffer
	writer := multipart.NewWriter(&b)

	// Add form fields
	writer.WriteField("esp_id", "UPLOAD_TEST_ESP")
	writer.WriteField("delivery_key", "test_delivery_key")
	writer.WriteField("encryption_password", "test_encryption_pass")

	// Add file
	part, err := writer.CreateFormFile("file", "test_upload.txt")
	if err != nil {
		t.Fatalf("Failed to create form file: %v", err)
	}

	_, err = io.Copy(part, file)
	if err != nil {
		t.Fatalf("Failed to copy file content: %v", err)
	}

	writer.Close()

	// Make request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/cargo_delivery", &b)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.SetBasicAuth("testuser", "testpass123")
	router.ServeHTTP(w, req)

	// File upload should succeed (even if storage server is not available)
	if w.Code != http.StatusOK {
		t.Errorf("File upload failed. Expected status %d, got %d. Body: %s", http.StatusOK, w.Code, w.Body.String())
	}
}

// Test security headers are applied
func testSecurityHeaders(t *testing.T, router *gin.Engine) {
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/", nil)
	router.ServeHTTP(w, req)

	expectedHeaders := map[string]string{
		"X-Content-Type-Options":  "nosniff",
		"X-Frame-Options":         "DENY",
		"X-XSS-Protection":        "1; mode=block",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"Content-Security-Policy": "default-src 'self'",
	}

	for header, expectedValue := range expectedHeaders {
		actualValue := w.Header().Get(header)
		if actualValue != expectedValue {
			t.Errorf("Security header %s missing or incorrect. Expected: %s, Got: %s", header, expectedValue, actualValue)
		}
	}
}

// Test rate limiting functionality
func testRateLimiting(t *testing.T, router *gin.Engine) {
	// Create a dedicated router with very low rate limit for testing
	testRouter := gin.New()
	testRouter.Use(RateLimitMiddleware(2, time.Second)) // 2 requests per second
	testRouter.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Make requests that should succeed
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "127.0.0.1:8080" // Same IP for all requests
		testRouter.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Request %d should have succeeded. Got status: %d", i+1, w.Code)
		}
	}

	// This request should be rate limited
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	testRouter.ServeHTTP(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected rate limiting. Expected status %d, got %d", http.StatusTooManyRequests, w.Code)
	}
}

// Test error handling consistency
func testErrorHandling(t *testing.T, router *gin.Engine) {
	// Test invalid JSON
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/authenticate", strings.NewReader("{invalid json"))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Invalid JSON should return 400. Got: %d", w.Code)
	}

	// Check response format
	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	if err != nil {
		t.Errorf("Error response should be valid JSON: %v", err)
	}

	// Check for standardized error format
	if _, exists := response["error"]; !exists {
		t.Error("Error response should contain 'error' field")
	}

	if _, exists := response["code"]; !exists {
		t.Error("Error response should contain 'code' field")
	}

	// Test unauthorized access
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/register_device", strings.NewReader("esp_id=TEST&esp_secret_key=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// No auth header
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Unauthorized access should return 401. Got: %d", w.Code)
	}
}
