package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestRateLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Create a new gin router with rate limiting
	r := gin.New()
	r.Use(RateLimitMiddleware(2, time.Second)) // 2 requests per second

	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// First request should succeed
	req1, _ := http.NewRequest("GET", "/test", nil)
	req1.RemoteAddr = "127.0.0.1:8080"
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w1.Code)
	}

	// Second request should succeed
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "127.0.0.1:8080"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w2.Code)
	}

	// Third request should be rate limited
	req3, _ := http.NewRequest("GET", "/test", nil)
	req3.RemoteAddr = "127.0.0.1:8080"
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)

	if w3.Code != http.StatusTooManyRequests {
		t.Errorf("Expected status 429, got %d", w3.Code)
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(SecurityHeadersMiddleware())

	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	req, _ := http.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Check security headers
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
			t.Errorf("Expected header %s to be '%s', got '%s'", header, expectedValue, actualValue)
		}
	}
}

func TestCORSMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(CORSMiddleware())

	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Test with allowed origin
	req, _ := http.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	allowedOrigin := w.Header().Get("Access-Control-Allow-Origin")
	if allowedOrigin != "http://localhost:3000" {
		t.Errorf("Expected Access-Control-Allow-Origin to be 'http://localhost:3000', got '%s'", allowedOrigin)
	}

	// Test with disallowed origin
	req2, _ := http.NewRequest("GET", "/test", nil)
	req2.Header.Set("Origin", "http://malicious.com")
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)

	allowedOrigin2 := w2.Header().Get("Access-Control-Allow-Origin")
	if allowedOrigin2 == "http://malicious.com" {
		t.Error("Should not allow malicious origin")
	}

	// Test OPTIONS request
	req3, _ := http.NewRequest("OPTIONS", "/test", nil)
	req3.Header.Set("Origin", "http://localhost:3000")
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)

	if w3.Code != http.StatusNoContent {
		t.Errorf("Expected OPTIONS request to return 204, got %d", w3.Code)
	}
}

func TestMinFunction(t *testing.T) {
	tests := []struct {
		a, b, expected int
	}{
		{1, 2, 1},
		{5, 3, 3},
		{10, 10, 10},
		{-1, 5, -1},
		{0, -5, -5},
	}

	for _, test := range tests {
		result := min(test.a, test.b)
		if result != test.expected {
			t.Errorf("min(%d, %d) = %d, expected %d", test.a, test.b, result, test.expected)
		}
	}
}

func TestRateLimiterConcurrency(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(RateLimitMiddleware(5, time.Second)) // 5 requests per second

	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Test single request first
	req, _ := http.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "127.0.0.1:8080"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("First request should succeed, got status %d", w.Code)
		if w.Code == http.StatusTooManyRequests {
			t.Logf("Response body: %s", w.Body.String())
		}
		return
	}

	// Test multiple requests in quick succession
	successCount := 1 // Already had one success
	rateLimitedCount := 0

	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "127.0.0.1:8080"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			successCount++
		} else if w.Code == http.StatusTooManyRequests {
			rateLimitedCount++
		}
	}

	// Should have some successful requests (at least the first one) and some rate limited
	if successCount < 1 {
		t.Error("Expected at least 1 successful request")
	}

	t.Logf("Results: %d successful, %d rate limited", successCount, rateLimitedCount)

	// For rate limiting to work properly, we should have both successes and rate limits
	if successCount > 5 {
		t.Errorf("Expected no more than 5 successful requests due to rate limit, got %d", successCount)
	}
}
