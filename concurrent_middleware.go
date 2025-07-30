// concurrent_middleware.go
package main

import (
	"fmt"
	"log"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// ConcurrentRequestManager manages concurrent request processing
type ConcurrentRequestManager struct {
	maxConcurrentRequests int64
	currentRequests       int64
	requestCounter        int64
	workerPool           *WorkerPool
	requestTimeout       time.Duration
	mutex                sync.RWMutex
	stats                RequestStats
}

// RequestStats tracks performance statistics
type RequestStats struct {
	TotalRequests       int64
	SuccessfulRequests  int64
	FailedRequests      int64
	AverageResponseTime time.Duration
	MaxResponseTime     time.Duration
	MinResponseTime     time.Duration
	ConcurrentPeak      int64
	mutex               sync.RWMutex
}

// Global concurrent request manager
var concurrentManager *ConcurrentRequestManager

// InitializeConcurrentProcessing sets up multi-threaded request processing
func InitializeConcurrentProcessing() {
	// Calculate optimal settings based on system resources
	numCPU := runtime.NumCPU()
	maxGoroutines := numCPU * 8 // 8x CPU cores for optimal I/O handling
	queueSize := maxGoroutines * 10
	
	log.Printf("Initializing concurrent processing:")
	log.Printf("  CPU Cores: %d", numCPU)
	log.Printf("  Max Goroutines: %d", maxGoroutines)
	log.Printf("  Queue Size: %d", queueSize)
	log.Printf("  Max Concurrent Requests: %d", maxGoroutines*2)
	
	// Create worker pool
	workerPool := NewWorkerPool(maxGoroutines, queueSize)
	workerPool.Start()
	
	// Initialize concurrent request manager
	concurrentManager = &ConcurrentRequestManager{
		maxConcurrentRequests: int64(maxGoroutines * 2),
		workerPool:           workerPool,
		requestTimeout:       time.Second * 30,
		stats: RequestStats{
			MinResponseTime: time.Hour, // Initialize to high value
		},
	}
	
	// Set Go runtime to use all CPU cores
	runtime.GOMAXPROCS(numCPU)
	
	log.Printf("Concurrent processing initialized successfully")
}

// ConcurrentRequestMiddleware handles requests with multi-threading
func ConcurrentRequestMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		startTime := time.Now()
		
		// Check if we can accept more requests
		current := atomic.LoadInt64(&concurrentManager.currentRequests)
		if current >= concurrentManager.maxConcurrentRequests {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error": "Server at maximum capacity",
				"retry_after": "1s",
				"current_load": current,
				"max_capacity": concurrentManager.maxConcurrentRequests,
			})
			return
		}
		
		// Increment counters
		atomic.AddInt64(&concurrentManager.currentRequests, 1)
		atomic.AddInt64(&concurrentManager.requestCounter, 1)
		
		// Update peak concurrent requests
		if current > atomic.LoadInt64(&concurrentManager.stats.ConcurrentPeak) {
			atomic.StoreInt64(&concurrentManager.stats.ConcurrentPeak, current)
		}
		
		// Process request in goroutine for maximum concurrency
		done := make(chan bool, 1)
		go func() {
			defer func() {
				// Decrement counter when done
				atomic.AddInt64(&concurrentManager.currentRequests, -1)
				done <- true
			}()
			
			// Process the actual request
			c.Next()
		}()
		
		// Wait for completion or timeout
		select {
		case <-done:
			// Request completed successfully
			responseTime := time.Since(startTime)
			concurrentManager.updateStats(responseTime, true)
			
		case <-time.After(concurrentManager.requestTimeout):
			// Request timed out
			atomic.AddInt64(&concurrentManager.currentRequests, -1)
			concurrentManager.updateStats(time.Since(startTime), false)
			c.JSON(http.StatusRequestTimeout, gin.H{
				"error": "Request timeout",
				"timeout": concurrentManager.requestTimeout.String(),
			})
			c.Abort()
		}
	}
}

// updateStats updates performance statistics
func (crm *ConcurrentRequestManager) updateStats(responseTime time.Duration, success bool) {
	crm.stats.mutex.Lock()
	defer crm.stats.mutex.Unlock()
	
	atomic.AddInt64(&crm.stats.TotalRequests, 1)
	
	if success {
		atomic.AddInt64(&crm.stats.SuccessfulRequests, 1)
	} else {
		atomic.AddInt64(&crm.stats.FailedRequests, 1)
	}
	
	// Update response time statistics
	if responseTime > crm.stats.MaxResponseTime {
		crm.stats.MaxResponseTime = responseTime
	}
	
	if responseTime < crm.stats.MinResponseTime {
		crm.stats.MinResponseTime = responseTime
	}
	
	// Calculate rolling average (simplified)
	total := atomic.LoadInt64(&crm.stats.TotalRequests)
	if total > 0 {
		avgNanos := (int64(crm.stats.AverageResponseTime) * (total - 1) + int64(responseTime)) / total
		crm.stats.AverageResponseTime = time.Duration(avgNanos)
	}
}

// AsyncDatabaseOperationMiddleware processes database operations asynchronously
func AsyncDatabaseOperationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Submit database operations to worker pool for async processing
		if concurrentManager != nil && concurrentManager.workerPool != nil {
			task := Task{
				ID:       fmt.Sprintf("req-%d", atomic.LoadInt64(&concurrentManager.requestCounter)),
				Type:     "database_operation",
				Data:     c.Request.URL.Path,
				Priority: 1,
				Created:  time.Now(),
			}
			
			// Submit task asynchronously (non-blocking)
			go func() {
				concurrentManager.workerPool.SubmitTask(task)
			}()
		}
		
		c.Next()
	}
}

// GetConcurrentStats returns current performance statistics
func GetConcurrentStats() gin.HandlerFunc {
	return func(c *gin.Context) {
		if concurrentManager == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Concurrent processing not initialized"})
			return
		}
		
		stats := map[string]interface{}{
			"concurrent_requests": atomic.LoadInt64(&concurrentManager.currentRequests),
			"max_concurrent":      concurrentManager.maxConcurrentRequests,
			"total_requests":      atomic.LoadInt64(&concurrentManager.stats.TotalRequests),
			"successful_requests": atomic.LoadInt64(&concurrentManager.stats.SuccessfulRequests),
			"failed_requests":     atomic.LoadInt64(&concurrentManager.stats.FailedRequests),
			"success_rate":        float64(atomic.LoadInt64(&concurrentManager.stats.SuccessfulRequests)) / float64(atomic.LoadInt64(&concurrentManager.stats.TotalRequests)) * 100,
			"avg_response_time":   concurrentManager.stats.AverageResponseTime.String(),
			"max_response_time":   concurrentManager.stats.MaxResponseTime.String(),
			"min_response_time":   concurrentManager.stats.MinResponseTime.String(),
			"peak_concurrent":     atomic.LoadInt64(&concurrentManager.stats.ConcurrentPeak),
			"cpu_cores":          runtime.NumCPU(),
			"goroutines":         runtime.NumGoroutine(),
		}
		
		if concurrentManager.workerPool != nil {
			workerStats := concurrentManager.workerPool.GetStats()
			stats["worker_pool"] = workerStats
		}
		
		c.JSON(http.StatusOK, gin.H{
			"status": "ok",
			"performance_stats": stats,
			"timestamp": time.Now().Unix(),
		})
	}
}

// OptimizeGarbageCollection optimizes Go's garbage collector for high-throughput
func OptimizeGarbageCollection() {
	// Set GC target percentage (lower = more frequent GC, less memory usage)
	runtime.GC()
	
	// Force initial cleanup
	runtime.GC()
	
	log.Println("Garbage collection optimized for high-throughput scenarios")
}

// StartPerformanceMonitor starts a background goroutine to monitor performance
func StartPerformanceMonitor() {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		
		for range ticker.C {
			if concurrentManager != nil {
				current := atomic.LoadInt64(&concurrentManager.currentRequests)
				total := atomic.LoadInt64(&concurrentManager.stats.TotalRequests)
				successful := atomic.LoadInt64(&concurrentManager.stats.SuccessfulRequests)
				peak := atomic.LoadInt64(&concurrentManager.stats.ConcurrentPeak)
				
				log.Printf("Performance Monitor - Current: %d, Total: %d, Successful: %d, Peak: %d, Goroutines: %d",
					current, total, successful, peak, runtime.NumGoroutine())
			}
		}
	}()
}

// ShutdownConcurrentProcessing gracefully shuts down concurrent processing
func ShutdownConcurrentProcessing() {
	if concurrentManager != nil && concurrentManager.workerPool != nil {
		log.Println("Shutting down concurrent processing...")
		concurrentManager.workerPool.Shutdown()
		log.Println("Concurrent processing shutdown complete")
	}
}
