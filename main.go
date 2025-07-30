// main.go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

// Config struct to hold configuration values
type Config struct {
	ServerInterface string   `json:"server_interface"` // Server listening interface and port
	GossipNodes     []string `json:"gossip_nodes"`     // List of other nodes for gossip protocol
	NodeID          string   `json:"node_id"`          // Unique identifier for this node
	ClusterEnabled  bool     `json:"cluster_enabled"`  // Whether to enable cluster mode
}

var (
	db           *gorm.DB
	config       Config
	serverConfig *ServerConfig
)

func main() {
	var err error

	// Initialize multi-threading and concurrent processing FIRST for maximum performance
	log.Println("🚀 Initializing multi-threaded high-performance server...")
	InitializeConcurrentProcessing()
	OptimizeGarbageCollection()
	StartPerformanceMonitor()

	// Load server configuration
	serverConfig, err = LoadConfig("config.json")
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Load legacy configuration for backward compatibility
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatalf("Failed to open config file: %v", err)
	}
	defer configFile.Close()

	// Parse configuration file
	if err := json.NewDecoder(configFile).Decode(&config); err != nil {
		log.Fatalf("Failed to parse config file: %v", err)
	}

	// Initialize the SQLite database connection with optimized settings
	db, err = gorm.Open(sqlite.Open(serverConfig.Database.Path), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// Configure database connection pool for better concurrent performance
	sqlDB, err := db.DB()
	if err != nil {
		log.Fatalf("Failed to get underlying database connection: %v", err)
	}

	// Set connection pool settings for high concurrency
	sqlDB.SetMaxIdleConns(25)           // Maximum number of idle connections
	sqlDB.SetMaxOpenConns(100)          // Maximum number of open connections
	sqlDB.SetConnMaxLifetime(time.Hour) // Maximum connection lifetime

	log.Printf("Database connection pool configured: MaxIdle=%d, MaxOpen=%d, MaxLifetime=1h", 25, 100)

	// Perform automatic schema migration
	db.AutoMigrate(&User{}, &ESPDevice{}, &Command{}, &FileMetadata{}, &Counter{})

	// Create a new Gin router for handling HTTP requests with multi-threading optimizations
	r := gin.Default()

	// Add high-performance concurrent processing middleware FIRST
	r.Use(ConcurrentRequestMiddleware())
	r.Use(AsyncDatabaseOperationMiddleware())

	// Add security middleware
	r.Use(SecurityHeadersMiddleware())
	r.Use(CORSMiddleware())
	r.Use(LoggingMiddleware())
	r.Use(RateLimitMiddleware(serverConfig.Security.RateLimitRequests, time.Duration(serverConfig.Security.RateLimitWindow)*time.Second))

	// Retrieve secret key from environment variables for session store
	secretKey := serverConfig.Security.SecretKey
	if secretKey == "" {
		log.Fatalf("SECRET_KEY environment variable is required")
	}

	log.Printf("Session store initialized successfully")

	// Set up session middleware using the secret key
	store := cookie.NewStore([]byte(secretKey))
	store.Options(sessions.Options{
		MaxAge:   serverConfig.Security.SessionMaxAge,
		Path:     "/",
		HttpOnly: true,
		Secure:   serverConfig.Security.EnableHTTPS,
	})
	r.Use(sessions.Sessions("mysession", store))

	// Register all the API routes
	registerRoutes(r) 
	
	// Add performance monitoring endpoint
	r.GET("/performance", GetConcurrentStats())
	r.GET("/stats", GetConcurrentStats()) // Initialize the sync system if cluster mode is enabled
	if config.ClusterEnabled {
		if config.NodeID == "" {
			// Generate a random node ID if not provided
			config.NodeID = fmt.Sprintf("node-%d", time.Now().UnixNano())
			log.Printf("No node ID provided, generated: %s", config.NodeID)
		}

		log.Printf("Cluster mode enabled, node ID: %s", config.NodeID)
		initSync(config.NodeID)
	} else {
		// Start the gossip protocol in a separate goroutine (legacy mode)
		go startGossip()
	}

	// Start the file delivery background service
	log.Println("Starting file delivery service...")
	startFileDeliveryService()

	// Run a check for storage server availability
	go func() {
		// Initial check
		if isStorageServerOnline() {
			log.Println("Storage server is online and responding to health checks")
		} else {
			log.Println("WARNING: Storage server (Ghostkey_Depo) is offline! File delivery will be queued until it's available.")
			log.Println("Make sure Ghostkey_Depo is running on port 6000 or adjust the configuration.")
		}

		// Periodically check status
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			if isStorageServerOnline() {
				log.Println("Storage server connection status: Online")
			} else {
				log.Println("Storage server connection status: Offline")
			}
		}
	}()

	// Run the Gin server on the configured interface with optimized settings
	server := &http.Server{
		Addr:           serverConfig.Server.Interface,
		Handler:        r,
		ReadTimeout:    time.Duration(serverConfig.Server.ReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(serverConfig.Server.WriteTimeout) * time.Second,
		IdleTimeout:    time.Duration(serverConfig.Server.IdleTimeout) * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Configure the server for high concurrency
	server.SetKeepAlivesEnabled(true)

	// Create a channel to listen for interrupt signals
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		if serverConfig.Security.EnableHTTPS && serverConfig.Security.CertFile != "" && serverConfig.Security.KeyFile != "" {
			log.Printf("Starting HTTPS server on %s with optimized settings", serverConfig.Server.Interface)
			log.Printf("Server configuration: ReadTimeout=%ds, WriteTimeout=%ds, IdleTimeout=%ds", 
				serverConfig.Server.ReadTimeout, serverConfig.Server.WriteTimeout, serverConfig.Server.IdleTimeout)
			if err := server.ListenAndServeTLS(serverConfig.Security.CertFile, serverConfig.Security.KeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to run HTTPS server: %v", err)
			}
		} else {
			log.Printf("Starting HTTP server on %s with optimized settings", serverConfig.Server.Interface)
			log.Printf("Server configuration: ReadTimeout=%ds, WriteTimeout=%ds, IdleTimeout=%ds", 
				serverConfig.Server.ReadTimeout, serverConfig.Server.WriteTimeout, serverConfig.Server.IdleTimeout)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to run server: %v", err)
			}
		}
	}()

	log.Println("Server started successfully with high-concurrency optimizations")
	log.Println("Press Ctrl+C to shutdown server...")

	// Wait for interrupt signal
	<-quit
	log.Println("Shutting down server...")

	// Create a context with timeout for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	} else {
		log.Println("Server shutdown complete")
	}
	
	// Shutdown concurrent processing
	ShutdownConcurrentProcessing()
}

// startGossip starts the gossip protocol at regular intervals
func startGossip() {
	// Create a ticker to trigger gossip at specified intervals
	ticker := time.NewTicker(1 * time.Minute) // Adjust the interval as needed
	for range ticker.C {
		// Call the gossip function when the ticker ticks
		gossip()
	}
}

// gossip performs the gossip protocol
func gossip() {
	// Check if gossip nodes are configured
	if len(config.GossipNodes) == 0 {
		log.Println("No gossip nodes configured, skipping gossip process")
		return
	}

	// Select a random gossip node to communicate with
	targetNode := config.GossipNodes[rand.Intn(len(config.GossipNodes))]
	var localVersionVector VersionVector

	// Fetch the local version vector
	db.Model(&Command{}).Pluck("updated_at", &localVersionVector)

	// Fetch local commands
	var localCommands []Command
	db.Find(&localCommands)

	// Fetch local devices
	var localDevices []ESPDevice
	db.Find(&localDevices)

	// Fetch local users
	var localUsers []User
	db.Find(&localUsers)

	// Construct payload
	payload := GossipPayload{
		VersionVector: localVersionVector,
		Commands:      localCommands,
		ESPDevices:    localDevices,
		Users:         localUsers,
	}

	// Marshal the payload to JSON and send it to the target node
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		log.Printf("Failed to marshal gossip payload: %v", err)
		return
	}

	// Send the payload to the target node
	resp, err := http.Post(targetNode+"/gossip", "application/json", bytes.NewReader(payloadBytes))
	if err != nil {
		log.Printf("Failed to gossip with %s: %v", targetNode, err)
		return
	}
	defer resp.Body.Close()

	// Check if the response status is OK
	if resp.StatusCode != http.StatusOK {
		log.Printf("Received non-OK status code from %s: %v", targetNode, resp.StatusCode)
		return
	}

	// Decode the response payload
	var remotePayload GossipPayload
	if err := json.NewDecoder(resp.Body).Decode(&remotePayload); err != nil {
		log.Printf("Failed to decode gossip payload from %s: %v", targetNode, err)
		return
	}

	// Merge remote commands
	for _, remoteCommand := range remotePayload.Commands {
		var localCommand Command
		if err := db.Where("id = ?", remoteCommand.ID).First(&localCommand).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				db.Create(&remoteCommand)
			} else {
				log.Printf("Failed to check existing command: %v", err)
			}
		} else {
			if remoteCommand.UpdatedAt.After(localCommand.UpdatedAt) {
				db.Save(&remoteCommand)
			}
		}
	}

	// Merge remote devices
	for _, remoteDevice := range remotePayload.ESPDevices {
		var localDevice ESPDevice
		if err := db.Where("esp_id = ?", remoteDevice.EspID).First(&localDevice).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				db.Create(&remoteDevice)
			} else {
				log.Printf("Failed to check existing device: %v", err)
			}
		} else {
			if remoteDevice.UpdatedAt.After(localDevice.UpdatedAt) {
				db.Save(&remoteDevice)
			}
		}
	}

	// Merge remote users
	for _, remoteUser := range remotePayload.Users {
		var localUser User
		if err := db.Where("id = ?", remoteUser.ID).First(&localUser).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				db.Create(&remoteUser)
			} else {
				log.Printf("Failed to check existing user: %v", err)
			}
		} else {
			if remoteUser.UpdatedAt.After(localUser.UpdatedAt) {
				db.Save(&remoteUser)
			}
		}
	}
}
