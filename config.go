// config.go
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// ServerConfig holds all server configuration
type ServerConfig struct {
	Server   ServerSettings   `json:"server"`
	Database DatabaseSettings `json:"database"`
	Security SecuritySettings `json:"security"`
	Cluster  ClusterSettings  `json:"cluster"`
	Storage  StorageSettings  `json:"storage"`
}

// ServerSettings contains server-specific configuration
type ServerSettings struct {
	Interface    string `json:"interface"`
	Port         int    `json:"port"`
	ReadTimeout  int    `json:"read_timeout"`
	WriteTimeout int    `json:"write_timeout"`
	IdleTimeout  int    `json:"idle_timeout"`
}

// DatabaseSettings contains database configuration
type DatabaseSettings struct {
	Type     string `json:"type"`
	Path     string `json:"path"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	Database string `json:"database"`
}

// SecuritySettings contains security-related configuration
type SecuritySettings struct {
	SecretKey         string   `json:"-"` // Never serialize secret key
	SessionMaxAge     int      `json:"session_max_age"`
	RateLimitRequests int      `json:"rate_limit_requests"`
	RateLimitWindow   int      `json:"rate_limit_window"`
	EnableHTTPS       bool     `json:"enable_https"`
	CertFile          string   `json:"cert_file"`
	KeyFile           string   `json:"key_file"`
	AllowedOrigins    []string `json:"allowed_origins"`
}

// ClusterSettings contains clustering configuration
type ClusterSettings struct {
	Enabled      bool     `json:"enabled"`
	NodeID       string   `json:"node_id"`
	GossipNodes  []string `json:"gossip_nodes"`
	SyncInterval int      `json:"sync_interval"`
}

// StorageSettings contains storage server configuration
type StorageSettings struct {
	URL            string `json:"url"`
	HealthCheckURL string `json:"health_check_url"`
	Timeout        int    `json:"timeout"`
	RetryAttempts  int    `json:"retry_attempts"`
	RetryInterval  int    `json:"retry_interval"`
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig(configPath string) (*ServerConfig, error) {
	// Default configuration
	config := &ServerConfig{
		Server: ServerSettings{
			Interface:    ":5000",
			Port:         5000,
			ReadTimeout:  30,
			WriteTimeout: 30,
			IdleTimeout:  120,
		},
		Database: DatabaseSettings{
			Type: "sqlite",
			Path: "data.db",
		},
		Security: SecuritySettings{
			SessionMaxAge:     86400, // 24 hours
			RateLimitRequests: 100,
			RateLimitWindow:   60, // 1 minute
			EnableHTTPS:       false,
			AllowedOrigins: []string{
				"http://localhost:3000",
				"http://localhost:5000",
				"http://127.0.0.1:3000",
				"http://127.0.0.1:5000",
			},
		},
		Cluster: ClusterSettings{
			Enabled:      false,
			NodeID:       "",
			GossipNodes:  []string{},
			SyncInterval: 60,
		},
		Storage: StorageSettings{
			URL:            "http://localhost:6000",
			HealthCheckURL: "http://localhost:6000/health",
			Timeout:        30,
			RetryAttempts:  5,
			RetryInterval:  60,
		},
	}

	// Load from file if it exists
	if configPath != "" {
		if err := loadConfigFromFile(config, configPath); err != nil {
			return nil, fmt.Errorf("failed to load config from file: %v", err)
		}
	}

	// Override with environment variables
	loadConfigFromEnv(config)

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %v", err)
	}

	return config, nil
}

// loadConfigFromFile loads configuration from JSON file
func loadConfigFromFile(config *ServerConfig, path string) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, use defaults
		}
		return err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	return decoder.Decode(config)
}

// loadConfigFromEnv loads configuration from environment variables
func loadConfigFromEnv(config *ServerConfig) {
	// Security settings (most important)
	if secretKey := os.Getenv("SECRET_KEY"); secretKey != "" {
		config.Security.SecretKey = secretKey
	}

	// Server settings
	if port := os.Getenv("PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			config.Server.Port = p
			config.Server.Interface = fmt.Sprintf(":%d", p)
		}
	}
	if iface := os.Getenv("SERVER_INTERFACE"); iface != "" {
		config.Server.Interface = iface
	}

	// Database settings
	if dbType := os.Getenv("DB_TYPE"); dbType != "" {
		config.Database.Type = dbType
	}
	if dbPath := os.Getenv("DB_PATH"); dbPath != "" {
		config.Database.Path = dbPath
	}
	if dbHost := os.Getenv("DB_HOST"); dbHost != "" {
		config.Database.Host = dbHost
	}
	if dbPort := os.Getenv("DB_PORT"); dbPort != "" {
		if p, err := strconv.Atoi(dbPort); err == nil {
			config.Database.Port = p
		}
	}
	if dbUser := os.Getenv("DB_USERNAME"); dbUser != "" {
		config.Database.Username = dbUser
	}
	if dbPass := os.Getenv("DB_PASSWORD"); dbPass != "" {
		config.Database.Password = dbPass
	}
	if dbName := os.Getenv("DB_DATABASE"); dbName != "" {
		config.Database.Database = dbName
	}

	// Cluster settings
	if enabled := os.Getenv("CLUSTER_ENABLED"); enabled != "" {
		config.Cluster.Enabled = strings.ToLower(enabled) == "true"
	}
	if nodeID := os.Getenv("NODE_ID"); nodeID != "" {
		config.Cluster.NodeID = nodeID
	}
	if gossipNodes := os.Getenv("GOSSIP_NODES"); gossipNodes != "" {
		config.Cluster.GossipNodes = strings.Split(gossipNodes, ",")
	}

	// Storage settings
	if storageURL := os.Getenv("STORAGE_URL"); storageURL != "" {
		config.Storage.URL = storageURL
		config.Storage.HealthCheckURL = storageURL + "/health"
	}

	// Security settings
	if httpsEnabled := os.Getenv("ENABLE_HTTPS"); httpsEnabled != "" {
		config.Security.EnableHTTPS = strings.ToLower(httpsEnabled) == "true"
	}
	if certFile := os.Getenv("CERT_FILE"); certFile != "" {
		config.Security.CertFile = certFile
	}
	if keyFile := os.Getenv("KEY_FILE"); keyFile != "" {
		config.Security.KeyFile = keyFile
	}
}

// validateConfig validates the configuration
func validateConfig(config *ServerConfig) error {
	if config.Security.SecretKey == "" {
		return fmt.Errorf("SECRET_KEY is required")
	}

	if len(config.Security.SecretKey) < 32 {
		return fmt.Errorf("SECRET_KEY must be at least 32 characters long")
	}

	if config.Security.EnableHTTPS {
		if config.Security.CertFile == "" || config.Security.KeyFile == "" {
			return fmt.Errorf("CERT_FILE and KEY_FILE are required when HTTPS is enabled")
		}
	}

	if config.Cluster.Enabled && config.Cluster.NodeID == "" {
		return fmt.Errorf("NODE_ID is required when cluster mode is enabled")
	}

	return nil
}

// GetDatabaseDSN returns the database connection string
func (c *ServerConfig) GetDatabaseDSN() string {
	switch strings.ToLower(c.Database.Type) {
	case "sqlite":
		return c.Database.Path
	case "postgres", "postgresql":
		return fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
			c.Database.Host, c.Database.Port, c.Database.Username, c.Database.Password, c.Database.Database)
	case "mysql":
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			c.Database.Username, c.Database.Password, c.Database.Host, c.Database.Port, c.Database.Database)
	default:
		return c.Database.Path
	}
}
