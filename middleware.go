// middleware.go
package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	clients map[string]*ClientLimit
	mutex   sync.RWMutex
}

// ClientLimit represents rate limiting information for a client
type ClientLimit struct {
	tokens    int
	lastToken time.Time
	mutex     sync.Mutex
}

// RateLimitMiddleware implements rate limiting middleware
func RateLimitMiddleware(maxRequests int, windowDuration time.Duration) gin.HandlerFunc {
	// Create a fresh rate limiter instance for this middleware
	rl := &RateLimiter{
		clients: make(map[string]*ClientLimit),
	}

	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		rl.mutex.RLock()
		client, exists := rl.clients[clientIP]
		rl.mutex.RUnlock()

		if !exists {
			rl.mutex.Lock()
			rl.clients[clientIP] = &ClientLimit{
				tokens:    maxRequests,
				lastToken: time.Now(),
			}
			client = rl.clients[clientIP]
			rl.mutex.Unlock()
		}

		client.mutex.Lock()
		now := time.Now()
		elapsed := now.Sub(client.lastToken)

		// Refill tokens based on elapsed time
		tokensToAdd := int(elapsed / (windowDuration / time.Duration(maxRequests)))
		if tokensToAdd > 0 {
			client.tokens = min(maxRequests, client.tokens+tokensToAdd)
			client.lastToken = now
		}

		if client.tokens <= 0 {
			client.mutex.Unlock()
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Rate limit exceeded. Please try again later.",
			})
			c.Abort()
			return
		}

		client.tokens--
		client.mutex.Unlock()

		c.Next()
	}
}

// SecurityHeadersMiddleware adds security headers
func SecurityHeadersMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Security headers
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Header("Content-Security-Policy", "default-src 'self'")

		// HTTPS enforcement (when not in development)
		if gin.Mode() == gin.ReleaseMode {
			c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

			// Redirect HTTP to HTTPS
			if c.Request.Header.Get("X-Forwarded-Proto") == "http" {
				c.Redirect(http.StatusMovedPermanently, "https://"+c.Request.Host+c.Request.RequestURI)
				c.Abort()
				return
			}
		}

		c.Next()
	}
}

// CORSMiddleware handles Cross-Origin Resource Sharing
func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")

		// Define allowed origins
		allowedOrigins := []string{
			"http://localhost:3000",
			"http://localhost:5000",
			"http://127.0.0.1:3000",
			"http://127.0.0.1:5000",
		}

		// Check if origin is allowed
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				c.Header("Access-Control-Allow-Origin", origin)
				break
			}
		}

		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}

// LoggingMiddleware provides structured logging
func LoggingMiddleware() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return fmt.Sprintf(`{"time":"%s","method":"%s","path":"%s","status":%d,"latency":"%s","ip":"%s","user_agent":"%s","error":"%s"}`+"\n",
			param.TimeStamp.Format(time.RFC3339),
			param.Method,
			param.Path,
			param.StatusCode,
			param.Latency,
			param.ClientIP,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	})
}

// Helper function for min (Go 1.21+ has this built-in)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
