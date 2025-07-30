package main

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func TestUserSetPassword(t *testing.T) {
	user := &User{}
	password := "testpassword123"

	err := user.SetPassword(password)
	if err != nil {
		t.Fatalf("Expected no error setting password, got: %v", err)
	}

	if user.PasswordHash == "" {
		t.Error("Expected password hash to be set")
	}

	if user.PasswordHash == password {
		t.Error("Password hash should not equal plaintext password")
	}

	// Verify the hash is valid bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		t.Errorf("Password hash verification failed: %v", err)
	}
}

func TestUserCheckPassword(t *testing.T) {
	user := &User{}
	password := "testpassword123"
	wrongPassword := "wrongpassword"

	// Set password first
	err := user.SetPassword(password)
	if err != nil {
		t.Fatalf("Failed to set password: %v", err)
	}

	// Test correct password
	if !user.CheckPassword(password) {
		t.Error("Expected correct password to return true")
	}

	// Test wrong password
	if user.CheckPassword(wrongPassword) {
		t.Error("Expected wrong password to return false")
	}

	// Test empty password
	if user.CheckPassword("") {
		t.Error("Expected empty password to return false")
	}
}

func TestGossipPayload(t *testing.T) {
	// Test GossipPayload struct
	payload := GossipPayload{
		NodeID: "test-node-1",
		Users: []User{
			{Username: "testuser"},
		},
		ESPDevices: []ESPDevice{
			{EspID: "esp001", EspSecretKey: "secret123"},
		},
		Commands: []Command{
			{EspID: "esp001", Command: "ping"},
		},
		VersionVector: VersionVector{
			"node1": time.Now(),
			"node2": time.Now().Add(-1 * time.Hour),
		},
	}

	if payload.NodeID != "test-node-1" {
		t.Errorf("Expected NodeID 'test-node-1', got %s", payload.NodeID)
	}

	if len(payload.Users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(payload.Users))
	}

	if len(payload.ESPDevices) != 1 {
		t.Errorf("Expected 1 ESP device, got %d", len(payload.ESPDevices))
	}

	if len(payload.Commands) != 1 {
		t.Errorf("Expected 1 command, got %d", len(payload.Commands))
	}

	if len(payload.VersionVector) != 2 {
		t.Errorf("Expected 2 version vector entries, got %d", len(payload.VersionVector))
	}
}

func TestESPDevice(t *testing.T) {
	device := ESPDevice{
		EspID:        "esp001",
		EspSecretKey: "secret123",
	}

	if device.EspID != "esp001" {
		t.Errorf("Expected EspID 'esp001', got %s", device.EspID)
	}

	if device.EspSecretKey != "secret123" {
		t.Errorf("Expected EspSecretKey 'secret123', got %s", device.EspSecretKey)
	}

	// Test with last request time
	now := time.Now()
	device.LastRequestTime = &now

	if device.LastRequestTime == nil {
		t.Error("Expected LastRequestTime to be set")
	}

	if !device.LastRequestTime.Equal(now) {
		t.Error("LastRequestTime should equal the set time")
	}
}

func TestCommand(t *testing.T) {
	command := Command{
		EspID:   "esp001",
		Command: "reboot",
	}

	if command.EspID != "esp001" {
		t.Errorf("Expected EspID 'esp001', got %s", command.EspID)
	}

	if command.Command != "reboot" {
		t.Errorf("Expected Command 'reboot', got %s", command.Command)
	}
}

func TestLoadedCommandPayload(t *testing.T) {
	payload := LoadedCommandPayload{
		EspID:    "esp001",
		Commands: []string{"cmd1", "cmd2", "cmd3"},
	}

	if payload.EspID != "esp001" {
		t.Errorf("Expected EspID 'esp001', got %s", payload.EspID)
	}

	if len(payload.Commands) != 3 {
		t.Errorf("Expected 3 commands, got %d", len(payload.Commands))
	}

	expectedCommands := []string{"cmd1", "cmd2", "cmd3"}
	for i, cmd := range payload.Commands {
		if cmd != expectedCommands[i] {
			t.Errorf("Expected command '%s' at index %d, got '%s'", expectedCommands[i], i, cmd)
		}
	}
}

func TestFileMetadata(t *testing.T) {
	metadata := FileMetadata{
		FileName:           "test.txt",
		OriginalFileName:   "original.txt",
		FilePath:           "/path/to/test.txt",
		EspID:              "esp001",
		DeliveryKey:        "key123",
		EncryptionPassword: "password123",
		Status:             StatusPending,
		RetryCount:         0,
	}

	if metadata.FileName != "test.txt" {
		t.Errorf("Expected FileName 'test.txt', got %s", metadata.FileName)
	}

	if metadata.Status != StatusPending {
		t.Errorf("Expected Status '%s', got %s", StatusPending, metadata.Status)
	}

	if metadata.RetryCount != 0 {
		t.Errorf("Expected RetryCount 0, got %d", metadata.RetryCount)
	}
}

func TestCounter(t *testing.T) {
	counter := Counter{
		ID:    1,
		Value: 42,
	}

	if counter.ID != 1 {
		t.Errorf("Expected ID 1, got %d", counter.ID)
	}

	if counter.Value != 42 {
		t.Errorf("Expected Value 42, got %d", counter.Value)
	}
}
