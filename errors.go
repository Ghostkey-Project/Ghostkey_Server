// errors.go
package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// SuccessResponse represents a standardized success response
type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Error codes
const (
	ErrCodeValidation     = "VALIDATION_ERROR"
	ErrCodeAuthentication = "AUTHENTICATION_ERROR"
	ErrCodeAuthorization  = "AUTHORIZATION_ERROR"
	ErrCodeNotFound       = "NOT_FOUND"
	ErrCodeInternal       = "INTERNAL_ERROR"
	ErrCodeRateLimit      = "RATE_LIMIT_EXCEEDED"
	ErrCodeBadRequest     = "BAD_REQUEST"
	ErrCodeConflict       = "CONFLICT"
)

// Helper functions for consistent error responses
func RespondWithError(c *gin.Context, statusCode int, errorCode, message, details string) {
	c.JSON(statusCode, ErrorResponse{
		Error:   message,
		Code:    errorCode,
		Details: details,
	})
}

func RespondWithSuccess(c *gin.Context, statusCode int, message string, data interface{}) {
	response := SuccessResponse{
		Message: message,
	}
	if data != nil {
		response.Data = data
	}
	c.JSON(statusCode, response)
}

// Specific error response helpers
func RespondBadRequest(c *gin.Context, message string) {
	RespondWithError(c, http.StatusBadRequest, ErrCodeBadRequest, message, "")
}

func RespondUnauthorized(c *gin.Context, message string) {
	RespondWithError(c, http.StatusUnauthorized, ErrCodeAuthentication, message, "")
}

func RespondForbidden(c *gin.Context, message string) {
	RespondWithError(c, http.StatusForbidden, ErrCodeAuthorization, message, "")
}

func RespondNotFound(c *gin.Context, message string) {
	RespondWithError(c, http.StatusNotFound, ErrCodeNotFound, message, "")
}

func RespondInternalError(c *gin.Context, message string) {
	RespondWithError(c, http.StatusInternalServerError, ErrCodeInternal, message, "")
}

func RespondConflict(c *gin.Context, message string) {
	RespondWithError(c, http.StatusConflict, ErrCodeConflict, message, "")
}

func RespondSuccess(c *gin.Context, message string) {
	RespondWithSuccess(c, http.StatusOK, message, nil)
}

func RespondSuccessWithData(c *gin.Context, message string, data interface{}) {
	RespondWithSuccess(c, http.StatusOK, message, data)
}
