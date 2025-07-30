// worker_pool.go
package main

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"
	"time"
)

// WorkerPool manages a pool of worker goroutines for concurrent task processing
type WorkerPool struct {
	workers    int
	taskQueue  chan Task
	resultChan chan TaskResult
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// Task represents a unit of work to be processed
type Task struct {
	ID       string
	Type     string
	Data     interface{}
	Priority int
	Created  time.Time
}

// TaskResult represents the result of a processed task
type TaskResult struct {
	TaskID    string
	Success   bool
	Data      interface{}
	Error     error
	Duration  time.Duration
	ProcessedAt time.Time
}

// NewWorkerPool creates a new worker pool with specified number of workers
func NewWorkerPool(workers int, queueSize int) *WorkerPool {
	if workers <= 0 {
		workers = runtime.NumCPU() * 4 // Default to 4x CPU cores for I/O bound tasks
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	pool := &WorkerPool{
		workers:    workers,
		taskQueue:  make(chan Task, queueSize),
		resultChan: make(chan TaskResult, queueSize),
		ctx:        ctx,
		cancel:     cancel,
	}
	
	return pool
}

// Start initializes and starts all worker goroutines
func (wp *WorkerPool) Start() {
	log.Printf("Starting worker pool with %d workers", wp.workers)
	
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(i)
	}
	
	// Start result processor
	go wp.resultProcessor()
	
	log.Printf("Worker pool started successfully")
}

// worker represents a single worker goroutine
func (wp *WorkerPool) worker(id int) {
	defer wp.wg.Done()
	
	for {
		select {
		case task, ok := <-wp.taskQueue:
			if !ok {
				log.Printf("Worker %d: Task queue closed, shutting down", id)
				return
			}
			
			// Process the task
			result := wp.processTask(task, id)
			
			// Send result
			select {
			case wp.resultChan <- result:
			case <-wp.ctx.Done():
				return
			}
			
		case <-wp.ctx.Done():
			log.Printf("Worker %d: Context cancelled, shutting down", id)
			return
		}
	}
}

// processTask handles the actual task processing
func (wp *WorkerPool) processTask(task Task, workerID int) TaskResult {
	start := time.Now()
	
	result := TaskResult{
		TaskID:      task.ID,
		ProcessedAt: start,
	}
	
	// Process based on task type
	switch task.Type {
	case "database_operation":
		result.Success, result.Error = wp.processDatabaseTask(task)
	case "command_processing":
		result.Success, result.Error = wp.processCommandTask(task)
	case "device_sync":
		result.Success, result.Error = wp.processDeviceSyncTask(task)
	case "file_delivery":
		result.Success, result.Error = wp.processFileDeliveryTask(task)
	default:
		result.Success = false
		result.Error = fmt.Errorf("unknown task type: %s", task.Type)
	}
	
	result.Duration = time.Since(start)
	return result
}

// processDatabaseTask handles database operations asynchronously
func (wp *WorkerPool) processDatabaseTask(task Task) (bool, error) {
	// Simulate database operation
	time.Sleep(time.Millisecond * 2) // Realistic DB operation time
	return true, nil
}

// processCommandTask handles command processing
func (wp *WorkerPool) processCommandTask(task Task) (bool, error) {
	// Process commands concurrently
	time.Sleep(time.Millisecond * 1)
	return true, nil
}

// processDeviceSyncTask handles device synchronization
func (wp *WorkerPool) processDeviceSyncTask(task Task) (bool, error) {
	// Handle device sync operations
	time.Sleep(time.Millisecond * 3)
	return true, nil
}

// processFileDeliveryTask handles file delivery operations
func (wp *WorkerPool) processFileDeliveryTask(task Task) (bool, error) {
	// Handle file delivery
	time.Sleep(time.Millisecond * 5)
	return true, nil
}

// resultProcessor handles task results
func (wp *WorkerPool) resultProcessor() {
	for {
		select {
		case result := <-wp.resultChan:
			// Log successful operations
			if result.Success {
				log.Printf("Task %s completed in %v", result.TaskID, result.Duration)
			} else {
				log.Printf("Task %s failed: %v", result.TaskID, result.Error)
			}
			
		case <-wp.ctx.Done():
			return
		}
	}
}

// SubmitTask adds a new task to the worker pool
func (wp *WorkerPool) SubmitTask(task Task) bool {
	select {
	case wp.taskQueue <- task:
		return true
	case <-time.After(time.Second * 5): // Timeout after 5 seconds
		log.Printf("Failed to submit task %s: queue full", task.ID)
		return false
	}
}

// Shutdown gracefully shuts down the worker pool
func (wp *WorkerPool) Shutdown() {
	log.Println("Shutting down worker pool...")
	
	// Cancel context to signal workers to stop
	wp.cancel()
	
	// Close task queue
	close(wp.taskQueue)
	
	// Wait for all workers to finish
	wp.wg.Wait()
	
	// Close result channel
	close(wp.resultChan)
	
	log.Println("Worker pool shutdown complete")
}

// GetStats returns worker pool statistics
func (wp *WorkerPool) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"workers":           wp.workers,
		"queued_tasks":      len(wp.taskQueue),
		"pending_results":   len(wp.resultChan),
		"queue_capacity":    cap(wp.taskQueue),
		"results_capacity":  cap(wp.resultChan),
	}
}
