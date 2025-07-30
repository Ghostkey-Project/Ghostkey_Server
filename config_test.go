package main

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Set required environment variable for test
	os.Setenv("SECRET_KEY", "test_secret_key_that_is_long_enough_for_validation")
	defer os.Unsetenv("SECRET_KEY")

	// Test with empty config file
	config, err := LoadConfig("")
	if err != nil {
		t.Fatalf("Expected no error with empty config file, got: %v", err)
	}

	// Test default values
	if config.Server.Port != 5000 {
		t.Errorf("Expected default port 5000, got %d", config.Server.Port)
	}

	if config.Database.Type != "sqlite" {
		t.Errorf("Expected default database type 'sqlite', got %s", config.Database.Type)
	}

	if config.Security.SessionMaxAge != 86400 {
		t.Errorf("Expected default session max age 86400, got %d", config.Security.SessionMaxAge)
	}
}

func TestLoadConfigFromEnv(t *testing.T) {
	// Set environment variables
	os.Setenv("SECRET_KEY", "test_secret_key_that_is_long_enough_for_validation")
	os.Setenv("PORT", "8080")
	os.Setenv("DB_TYPE", "postgres")
	os.Setenv("CLUSTER_ENABLED", "false") // Set to false to avoid NODE_ID requirement

	defer func() {
		os.Unsetenv("SECRET_KEY")
		os.Unsetenv("PORT")
		os.Unsetenv("DB_TYPE")
		os.Unsetenv("CLUSTER_ENABLED")
	}()

	config, err := LoadConfig("")
	if err != nil {
		t.Fatalf("Expected no error loading config from env, got: %v", err)
	}

	if config.Security.SecretKey != "test_secret_key_that_is_long_enough_for_validation" {
		t.Errorf("Expected secret key from env, got %s", config.Security.SecretKey)
	}

	if config.Server.Port != 8080 {
		t.Errorf("Expected port 8080 from env, got %d", config.Server.Port)
	}

	if config.Database.Type != "postgres" {
		t.Errorf("Expected database type 'postgres' from env, got %s", config.Database.Type)
	}

	if config.Cluster.Enabled {
		t.Error("Expected cluster disabled from env")
	}
}

func TestValidateConfig(t *testing.T) {
	// Test missing secret key
	config := &ServerConfig{}
	err := validateConfig(config)
	if err == nil {
		t.Error("Expected error for missing secret key")
	}

	// Test short secret key
	config.Security.SecretKey = "short"
	err = validateConfig(config)
	if err == nil {
		t.Error("Expected error for short secret key")
	}

	// Test valid config
	config.Security.SecretKey = "this_is_a_long_enough_secret_key_for_testing"
	err = validateConfig(config)
	if err != nil {
		t.Errorf("Expected no error for valid config, got: %v", err)
	}

	// Test HTTPS config validation
	config.Security.EnableHTTPS = true
	err = validateConfig(config)
	if err == nil {
		t.Error("Expected error for HTTPS enabled without cert files")
	}

	config.Security.CertFile = "cert.pem"
	config.Security.KeyFile = "key.pem"
	err = validateConfig(config)
	if err != nil {
		t.Errorf("Expected no error for valid HTTPS config, got: %v", err)
	}
}

func TestGetDatabaseDSN(t *testing.T) {
	config := &ServerConfig{
		Database: DatabaseSettings{
			Type: "sqlite",
			Path: "test.db",
		},
	}

	dsn := config.GetDatabaseDSN()
	if dsn != "test.db" {
		t.Errorf("Expected SQLite DSN 'test.db', got %s", dsn)
	}

	config.Database = DatabaseSettings{
		Type:     "postgres",
		Host:     "localhost",
		Port:     5432,
		Username: "user",
		Password: "pass",
		Database: "testdb",
	}

	dsn = config.GetDatabaseDSN()
	expected := "host=localhost port=5432 user=user password=pass dbname=testdb sslmode=disable"
	if dsn != expected {
		t.Errorf("Expected PostgreSQL DSN '%s', got %s", expected, dsn)
	}
}
