// constants.go
package main

// Constants for file delivery status and retry settings
const (
	StatusPending    = "pending"   // Indicates a file is pending delivery
	StatusCompleted  = "completed" // Indicates a file was delivered successfully
	StatusFailed     = "failed"    // Indicates a file delivery has failed
	MaxRetryAttempts = 5           // Maximum number of retry attempts for delivery
	RetryInterval    = 1 * 60      // Time interval between retry attempts in seconds
)
