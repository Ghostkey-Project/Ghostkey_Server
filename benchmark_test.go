package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// Benchmark tests for middleware performance
func BenchmarkRateLimitMiddleware(b *testing.B) {
	gin.SetMode(gin.TestMode)

	// Create router with rate limit middleware
	router := gin.New()
	router.Use(RateLimitMiddleware(1000, time.Second)) // High limit for benchmarking
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "127.0.0.1:8080"
		router.ServeHTTP(w, req)
	}
}

func BenchmarkSecurityHeadersMiddleware(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(SecurityHeadersMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
	}
}

func BenchmarkCORSMiddleware(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(CORSMiddleware())
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.Header.Set("Origin", "https://example.com")
		router.ServeHTTP(w, req)
	}
}

func BenchmarkAllMiddleware(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(SecurityHeadersMiddleware())
	router.Use(CORSMiddleware())
	router.Use(RateLimitMiddleware(1000, time.Second))
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "127.0.0.1:8080"
		req.Header.Set("Origin", "https://example.com")
		router.ServeHTTP(w, req)
	}
}

func BenchmarkWithoutMiddleware(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
	}
}

// Benchmark different error response methods
func BenchmarkStandardErrorResponse(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		RespondBadRequest(c, "Test error message")
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
	}
}

func BenchmarkOldErrorResponse(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Test error message"})
	})

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		router.ServeHTTP(w, req)
	}
}

// Concurrent benchmark to test middleware under load
func BenchmarkMiddlewareConcurrent(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(SecurityHeadersMiddleware())
	router.Use(CORSMiddleware())
	router.Use(RateLimitMiddleware(10000, time.Second)) // High limit for benchmarking
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/test", nil)
			req.RemoteAddr = "127.0.0.1:8080"
			req.Header.Set("Origin", "https://example.com")
			router.ServeHTTP(w, req)
		}
	})
}

// Memory allocation benchmarks
func BenchmarkRateLimiterMemory(b *testing.B) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	router.Use(RateLimitMiddleware(1000, time.Second))
	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "127.0.0.1:8080"
		router.ServeHTTP(w, req)
	}
}

func BenchmarkConfigLoading(b *testing.B) {
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		config, err := LoadConfig("config.json")
		if err != nil {
			// Use default config for benchmarking
			config = &ServerConfig{
				Server: ServerSettings{Interface: ":8080"},
				Security: SecuritySettings{
					SecretKey:         "benchmark-key-1234567890123456",
					RateLimitRequests: 100,
					RateLimitWindow:   60,
					SessionMaxAge:     3600,
				},
			}
		}
		_ = config
	}
}

// Input sanitization benchmark
func BenchmarkSanitizeInput(b *testing.B) {
	testInput := "test_input_with_special_chars_<script>alert('xss')</script>"

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		sanitized := sanitizeInput(testInput)
		_ = sanitized
	}
}
