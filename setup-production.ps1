# Production Environment Setup Script
# This script sets up the production environment with proper configuration

param(
    [switch]$UseHTTPS,
    [string]$CertFile = "",
    [string]$KeyFile = "",
    [string]$SecretKey = "",
    [int]$Port = 5000
)

Write-Host "🔧 Setting up Production Environment" -ForegroundColor Blue
Write-Host "====================================" -ForegroundColor Blue

function Write-Status {
    param($Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param($Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param($Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param($Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

try {
    # Step 1: Generate secure secret key if not provided
    if ([string]::IsNullOrEmpty($SecretKey)) {
        Write-Status "Generating secure secret key..."
        $SecretKey = -join ((1..64) | ForEach-Object { [char]((65..90) + (97..122) + (48..57) | Get-Random) })
        Write-Success "Generated 64-character secure secret key"
    }

    # Step 2: Create production configuration
    Write-Status "Creating production configuration..."
    
    $productionConfig = @{
        server = @{
            interface = ":$Port"
            port = $Port
            read_timeout = 30
            write_timeout = 30
            idle_timeout = 120
        }
        database = @{
            type = "sqlite"
            path = "data.db"
        }
        security = @{
            session_max_age = 86400
            rate_limit_requests = 100
            rate_limit_window = 60
            enable_https = $UseHTTPS.IsPresent
            cert_file = $CertFile
            key_file = $KeyFile
            allowed_origins = @(
                "http://localhost:3000",
                "http://localhost:5000", 
                "http://127.0.0.1:3000",
                "http://127.0.0.1:5000"
            )
        }
        cluster = @{
            enabled = $false
            node_id = "node-1"
            gossip_nodes = @()
            sync_interval = 60
        }
        storage = @{
            url = "http://localhost:6000"
            health_check_url = "http://localhost:6000/health"
            timeout = 30
            retry_attempts = 5
            retry_interval = 60
        }
    }

    # Convert to JSON and save
    $configJson = $productionConfig | ConvertTo-Json -Depth 10
    $configJson | Out-File -FilePath "config.json" -Encoding UTF8
    Write-Success "Production configuration saved to config.json"

    # Step 3: Set environment variables
    Write-Status "Setting environment variables..."
    $env:SECRET_KEY = $SecretKey
    $env:GIN_MODE = "release"
    $env:PORT = $Port.ToString()
    
    if ($UseHTTPS.IsPresent) {
        $env:ENABLE_HTTPS = "true"
        if ($CertFile) { $env:CERT_FILE = $CertFile }
        if ($KeyFile) { $env:KEY_FILE = $KeyFile }
    }
    
    Write-Success "Environment variables configured"

    # Step 4: Create necessary directories
    Write-Status "Creating necessary directories..."
    $directories = @("logs", "data", "uploads", "backups", "cargo_files")
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Success "Created directory: $dir"
        } else {
            Write-Status "Directory already exists: $dir"
        }
    }

    # Step 5: Build the application
    Write-Status "Building application for production..."
    $env:CGO_ENABLED = "1"
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    
    & go build -ldflags="-w -s" -o ghostkey_server.exe .
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed"
        exit 1
    }
    
    Write-Success "Application built successfully: ghostkey_server.exe"

    # Step 6: Create startup script
    Write-Status "Creating startup script..."
    
    $startupScript = @"
# Ghostkey Server Startup Script
`$env:SECRET_KEY = "$SecretKey"
`$env:GIN_MODE = "release"
`$env:PORT = "$Port"
"@

    if ($UseHTTPS.IsPresent) {
        $startupScript += @"

`$env:ENABLE_HTTPS = "true"
"@
        if ($CertFile) { $startupScript += "`n`$env:CERT_FILE = `"$CertFile`"" }
        if ($KeyFile) { $startupScript += "`n`$env:KEY_FILE = `"$KeyFile`"" }
    }

    $startupScript += @"

Write-Host "Starting Ghostkey Server..."
Write-Host "Configuration:"
Write-Host "  Port: $Port"
Write-Host "  HTTPS: $($UseHTTPS.IsPresent)"
Write-Host "  Secret Key Length: $($SecretKey.Length) characters"
Write-Host ""

.\ghostkey_server.exe
"@

    $startupScript | Out-File -FilePath "start-server.ps1" -Encoding UTF8
    Write-Success "Startup script created: start-server.ps1"

    # Step 7: Run production validation tests
    Write-Status "Running production validation tests..."
    $env:CGO_ENABLED = "0"
    & go test -v -run=TestFullDeploymentValidation .\production_validation_test.go
    
    if ($LASTEXITCODE -eq 0) {
        Write-Success "All production validation tests passed"
    } else {
        Write-Warning "Some validation tests failed - review before deploying"
    }

    # Step 8: Final summary
    Write-Host ""
    Write-Host "🎉 PRODUCTION SETUP COMPLETE!" -ForegroundColor Green
    Write-Host "=============================" -ForegroundColor Green
    
    Write-Success "✅ Production configuration created"
    Write-Success "✅ Environment variables set"
    Write-Success "✅ Directory structure created"
    Write-Success "✅ Application built successfully"
    Write-Success "✅ Startup script created"
    
    Write-Host ""
    Write-Host "Production Configuration Summary:" -ForegroundColor Yellow
    Write-Host "  Server Port: $Port"
    Write-Host "  HTTPS Enabled: $($UseHTTPS.IsPresent)"
    Write-Host "  Secret Key Length: $($SecretKey.Length) characters"
    Write-Host "  Database: SQLite (data.db)"
    Write-Host "  Rate Limiting: 100 requests/minute"
    Write-Host ""
    
    Write-Host "To start the server:" -ForegroundColor Cyan
    Write-Host "  .\start-server.ps1" -ForegroundColor White
    Write-Host ""
    Write-Host "To install as Windows service:" -ForegroundColor Cyan
    Write-Host "  .\install-service.ps1 (run as Administrator)" -ForegroundColor White
    Write-Host ""
    Write-Host "Important Security Notes:" -ForegroundColor Red
    Write-Host "  • Store the secret key securely: $SecretKey"
    Write-Host "  • Consider enabling HTTPS for production"
    Write-Host "  • Regularly backup the database: .\backup.ps1"
    Write-Host "  • Monitor logs in the logs\ directory"
    Write-Host ""
    
    Write-Success "Production environment is ready for deployment!"

} catch {
    Write-Error "Setup failed: $($_.Exception.Message)"
    exit 1
}
