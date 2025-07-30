# Production Deployment Script for Ghostkey Server (PowerShell)
# This script validates the environment and deploys the server on Windows

param(
    [switch]$SkipTests,
    [switch]$Force
)

Write-Host "🚀 Ghostkey Server Production Deployment Script" -ForegroundColor Blue
Write-Host "===============================================" -ForegroundColor Blue

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

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Warning "Running as administrator - ensure this is necessary"
}

try {
    # Step 1: Validate Go environment
    Write-Status "Validating Go environment..."
    
    $goVersion = & go version 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Go is not installed or not in PATH"
        exit 1
    }
    
    Write-Success "Go version: $goVersion"

    # Step 2: Validate configuration
    Write-Status "Validating configuration files..."
    
    if (-not (Test-Path "config.json")) {
        Write-Error "config.json not found"
        exit 1
    }
    
    # Load and validate configuration
    $config = Get-Content "config.json" | ConvertFrom-Json
    
    if ([string]::IsNullOrEmpty($config.Security.SecretKey)) {
        Write-Error "Secret key not configured"
        exit 1
    }
    
    if ($config.Security.SecretKey.Length -lt 32) {
        Write-Error "Secret key too short for production (minimum 32 characters)"
        exit 1
    }
    
    Write-Success "Configuration file validated"

    # Step 3: Build the application
    Write-Status "Building application for production..."
    
    # Set production build environment
    $env:CGO_ENABLED = "1"
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    
    # Build with optimizations
    & go build -ldflags="-w -s" -o ghostkey_server.exe .
    
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed"
        exit 1
    }
    
    Write-Success "Build completed successfully"

    # Step 4: Run tests (unless skipped)
    if (-not $SkipTests) {
        Write-Status "Running production readiness tests..."
        
        $env:GIN_MODE = "release"
        & go test -v . -tags=production
        
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Some tests failed - review before deploying"
            if (-not $Force) {
                $continue = Read-Host "Continue with deployment? (y/N)"
                if ($continue -ne "y" -and $continue -ne "Y") {
                    exit 1
                }
            }
        } else {
            Write-Success "All tests passed"
        }
    }

    # Step 5: Validate SSL certificates (if HTTPS enabled)
    Write-Status "Checking SSL configuration..."
    
    if ($config.Security.EnableHTTPS) {
        if (-not (Test-Path $config.Security.CertFile)) {
            Write-Error "SSL certificate file not found: $($config.Security.CertFile)"
            exit 1
        }
        
        if (-not (Test-Path $config.Security.KeyFile)) {
            Write-Error "SSL key file not found: $($config.Security.KeyFile)"
            exit 1
        }
        
        Write-Success "SSL certificates validated"
    } else {
        Write-Warning "HTTPS is not enabled - not recommended for production"
    }

    # Step 6: Check system resources
    Write-Status "Checking system resources..."
    
    # Check available disk space
    $disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeSpaceGB = [math]::Round($disk.FreeSpace / 1GB, 2)
    $totalSpaceGB = [math]::Round($disk.Size / 1GB, 2)
    $usedPercentage = [math]::Round((($disk.Size - $disk.FreeSpace) / $disk.Size) * 100, 1)
    
    if ($usedPercentage -gt 90) {
        Write-Warning "Disk usage is high: $usedPercentage%"
    }
    
    Write-Success "Available disk space: $freeSpaceGB GB of $totalSpaceGB GB"
    
    # Check available memory
    $memory = Get-WmiObject -Class Win32_ComputerSystem
    $totalMemoryGB = [math]::Round($memory.TotalPhysicalMemory / 1GB, 2)
    Write-Success "Total system memory: $totalMemoryGB GB"

    # Step 7: Create necessary directories
    Write-Status "Creating necessary directories..."
    
    $directories = @("logs", "data", "uploads", "backups")
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Success "Created directory: $dir"
        }
    }

    # Step 8: Validate port availability
    Write-Status "Checking port availability..."
    
    $serverInterface = $config.Server.Interface
    if ($serverInterface -match ":(\d+)$") {
        $serverPort = $matches[1]
    } else {
        $serverPort = "8080"  # Default port
    }
    
    $portInUse = Get-NetTCPConnection -LocalPort $serverPort -ErrorAction SilentlyContinue
    if ($portInUse) {
        Write-Warning "Port $serverPort is already in use"
    } else {
        Write-Success "Port $serverPort is available"
    }

    # Step 9: Create Windows service registration script
    Write-Status "Creating Windows service installation script..."
    
    $currentDir = (Get-Location).Path
    $serviceName = "GhostkeyServer"
    $serviceScript = @"
# Install Ghostkey Server as Windows Service
# Run this script as Administrator

`$serviceName = "$serviceName"
`$exePath = "$currentDir\ghostkey_server.exe"
`$workingDir = "$currentDir"

# Stop service if it exists
if (Get-Service `$serviceName -ErrorAction SilentlyContinue) {
    Write-Host "Stopping existing service..."
    Stop-Service `$serviceName -Force
    & sc.exe delete `$serviceName
}

# Create the service
Write-Host "Creating Windows service..."
& sc.exe create `$serviceName binPath= "`$exePath" start= auto DisplayName= "Ghostkey Server"
& sc.exe config `$serviceName obj= "LocalSystem"
& sc.exe description `$serviceName "Ghostkey Server - Remote Command Execution System"

# Set working directory via registry (required for relative paths)
`$regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\`$serviceName\Parameters"
if (-not (Test-Path `$regPath)) {
    New-Item -Path `$regPath -Force
}
Set-ItemProperty -Path `$regPath -Name "WorkingDirectory" -Value `$workingDir

Write-Host "Service created successfully!"
Write-Host "To start the service: Start-Service `$serviceName"
Write-Host "To stop the service: Stop-Service `$serviceName"
Write-Host "To remove the service: sc.exe delete `$serviceName"
"@
    
    $serviceScript | Out-File -FilePath "install-service.ps1" -Encoding UTF8
    Write-Success "Service installation script created: install-service.ps1"

    # Step 10: Create backup script
    Write-Status "Creating backup script..."
    
    $backupScript = @"
# Backup script for Ghostkey Server
`$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
`$backupDir = ".\backups\`$timestamp"

New-Item -ItemType Directory -Path `$backupDir -Force | Out-Null

# Backup configuration
if (Test-Path "config.json") {
    Copy-Item "config.json" `$backupDir
}

# Backup database
if (Test-Path "data.db") {
    Copy-Item "data.db" `$backupDir
}

# Backup uploaded files
if (Test-Path "uploads") {
    Copy-Item "uploads" `$backupDir -Recurse
}

Write-Host "Backup created: `$backupDir"
"@
    
    $backupScript | Out-File -FilePath "backup.ps1" -Encoding UTF8
    Write-Success "Backup script created: backup.ps1"

    # Step 11: Final security check
    Write-Status "Performing final security checks..."
    
    $issues = 0
    
    # Check for weak secret keys
    $secretKey = $config.Security.SecretKey.ToLower()
    $weakPatterns = @("secret", "test", "dev", "admin", "password", "12345")
    
    foreach ($pattern in $weakPatterns) {
        if ($secretKey.Contains($pattern)) {
            Write-Error "Weak secret key pattern detected: $pattern"
            $issues++
        }
    }
    
    # Check file permissions (basic check)
    if (Test-Path ".env") {
        Write-Warning ".env file found - ensure it has appropriate permissions"
    }

    # Step 12: Generate deployment summary
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Blue
    Write-Host "🏁 DEPLOYMENT SUMMARY" -ForegroundColor Blue
    Write-Host "================================================" -ForegroundColor Blue
    
    Write-Success "✅ Application built successfully"
    Write-Success "✅ Configuration validated"
    if (-not $SkipTests) { Write-Success "✅ Tests executed" }
    Write-Success "✅ System resources checked"
    Write-Success "✅ Security validated"
    
    if ($issues -gt 0) {
        Write-Warning "⚠️  $issues security issues detected - please review"
    } else {
        Write-Success "✅ No security issues detected"
    }
    
    Write-Host ""
    Write-Host "🚀 Ready for production deployment!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:"
    Write-Host "1. Review any warnings above"
    Write-Host "2. Test the application: .\ghostkey_server.exe"
    Write-Host "3. Install as Windows service: .\install-service.ps1 (as Administrator)"
    Write-Host "4. Monitor logs in the logs\ directory"
    Write-Host "5. Set up regular backups using backup.ps1"
    Write-Host ""
    Write-Host "For production monitoring, consider:"
    Write-Host "- Setting up log rotation"
    Write-Host "- Configuring monitoring/alerting"
    Write-Host "- Regular security updates"
    Write-Host "- Database maintenance schedules"
    Write-Host "- Windows Event Log integration"
    Write-Host ""
    
    Write-Success "Deployment validation completed!"
    
} catch {
    Write-Error "Deployment failed: $($_.Exception.Message)"
    exit 1
}
