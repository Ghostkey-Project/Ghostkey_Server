package main

import (
	"testing"
	"mime/multipart"
	"bytes"
)

// TestValidateSecretKey tests the secret key validation function
func TestValidateSecretKey(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		shouldErr bool
	}{
		{
			name:      "Valid strong key",
			key:       "MySecur3K3y!WithMixedChar5&Symbols",
			shouldErr: false,
		},
		{
			name:      "Too short",
			key:       "short",
			shouldErr: true,
		},
		{
			name:      "Default key",
			key:       "test_secret_key",
			shouldErr: true,
		},
		{
			name:      "Weak key - default production",
			key:       "default-secret-key-change-in-production",
			shouldErr: true,
		},
		{
			name:      "Insufficient entropy - only lowercase",
			key:       "thisisalongkeywithonlylowercaseletters",
			shouldErr: true,
		},
		{
			name:      "Sufficient length but weak",
			key:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSecretKey(tt.key)
			if (err != nil) != tt.shouldErr {
				t.Errorf("validateSecretKey() error = %v, shouldErr %v", err, tt.shouldErr)
			}
		})
	}
}

// TestValidateInput tests the input validation function
func TestValidateInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{
			name:  "Valid input",
			input: "normal_username",
			valid: true,
		},
		{
			name:  "SQL injection attempt",
			input: "'; DROP TABLE users; --",
			valid: false,
		},
		{
			name:  "XSS attempt",
			input: "<script>alert('xss')</script>",
			valid: false,
		},
		{
			name:  "Union select attempt",
			input: "admin' UNION SELECT * FROM users--",
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validateInput(tt.input)
			if result != tt.valid {
				t.Errorf("validateInput() = %v, want %v for input: %s", result, tt.valid, tt.input)
			}
		})
	}
}

// TestValidateFileUpload tests file upload validation
func TestValidateFileUpload(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		size     int64
		shouldErr bool
	}{
		{
			name:     "Valid file",
			filename: "document.txt",
			size:     1024,
			shouldErr: false,
		},
		{
			name:     "Dangerous executable",
			filename: "malware.exe",
			size:     1024,
			shouldErr: true,
		},
		{
			name:     "Directory traversal",
			filename: "../../../etc/passwd",
			size:     1024,
			shouldErr: true,
		},
		{
			name:     "File too large",
			filename: "large.txt",
			size:     200 * 1024 * 1024, // 200MB
			shouldErr: true,
		},
		{
			name:     "Script file",
			filename: "malicious.sh",
			size:     1024,
			shouldErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock file header
			header := &multipart.FileHeader{
				Filename: tt.filename,
				Size:     tt.size,
			}
			
			err := validateFileUpload(header)
			if (err != nil) != tt.shouldErr {
				t.Errorf("validateFileUpload() error = %v, shouldErr %v", err, tt.shouldErr)
			}
		})
	}
}

// TestSanitizeInput tests input sanitization
func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Normal input",
			input:    "normal_text",
			expected: "normal_text",
		},
		{
			name:     "Input with null bytes",
			input:    "text\x00with\x00nulls",
			expected: "textwithnulls",
		},
		{
			name:     "Input with whitespace",
			input:    "  spaced text  ",
			expected: "spaced text",
		},
		{
			name:     "Very long input",
			input:    string(bytes.Repeat([]byte("a"), 2000)),
			expected: string(bytes.Repeat([]byte("a"), 1000)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeInput(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeInput() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestSanitizeUsername tests username sanitization
func TestSanitizeUsername(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Valid username",
			input:    "user_123",
			expected: "user_123",
		},
		{
			name:     "Email address",
			input:    "user@example.com",
			expected: "user@example.com",
		},
		{
			name:     "Username with invalid chars",
			input:    "user!@#$%name",
			expected: "user@name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeUsername(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeUsername() = %q, want %q", result, tt.expected)
			}
		})
	}
}