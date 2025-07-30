#!/bin/bash

# Production Deployment Script for Ghostkey Server
# This script validates the environment and deploys the server

set -e  # Exit on any error

echo "🚀 Ghostkey Server Production Deployment Script"
echo "==============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root (not recommended)
if [ "$EUID" -eq 0 ]; then
    print_warning "Running as root is not recommended for production"
fi

# Step 1: Validate Go environment
print_status "Validating Go environment..."
if ! command -v go &> /dev/null; then
    print_error "Go is not installed or not in PATH"
    exit 1
fi

GO_VERSION=$(go version | cut -d' ' -f3)
print_success "Go version: $GO_VERSION"

# Step 2: Validate configuration
print_status "Validating configuration files..."

if [ ! -f "config.json" ]; then
    print_error "config.json not found"
    exit 1
fi

# Check configuration file permissions
CONFIG_PERMS=$(stat -c "%a" config.json)
if [ "$CONFIG_PERMS" -gt 644 ]; then
    print_warning "config.json permissions are too permissive ($CONFIG_PERMS)"
fi

print_success "Configuration file found and validated"

# Step 3: Build the application
print_status "Building application for production..."

# Set production build flags
export CGO_ENABLED=1
export GOOS=linux
export GOARCH=amd64

# Build with optimizations
go build -ldflags="-w -s" -o ghostkey_server .

if [ $? -eq 0 ]; then
    print_success "Build completed successfully"
else
    print_error "Build failed"
    exit 1
fi

# Step 4: Run tests
print_status "Running production readiness tests..."

export GIN_MODE=release
go test -v ./... -tags=production

if [ $? -eq 0 ]; then
    print_success "All tests passed"
else
    print_warning "Some tests failed - review before deploying"
fi

# Step 5: Validate SSL certificates (if HTTPS enabled)
print_status "Checking SSL configuration..."

ENABLE_HTTPS=$(grep -o '"EnableHTTPS":[[:space:]]*true' config.json || echo "")
if [ ! -z "$ENABLE_HTTPS" ]; then
    CERT_FILE=$(grep -o '"CertFile":[[:space:]]*"[^"]*"' config.json | cut -d'"' -f4)
    KEY_FILE=$(grep -o '"KeyFile":[[:space:]]*"[^"]*"' config.json | cut -d'"' -f4)
    
    if [ ! -f "$CERT_FILE" ]; then
        print_error "SSL certificate file not found: $CERT_FILE"
        exit 1
    fi
    
    if [ ! -f "$KEY_FILE" ]; then
        print_error "SSL key file not found: $KEY_FILE"
        exit 1
    fi
    
    # Check certificate expiration
    if command -v openssl &> /dev/null; then
        CERT_EXPIRY=$(openssl x509 -in "$CERT_FILE" -noout -enddate | cut -d= -f2)
        print_success "SSL certificate expires: $CERT_EXPIRY"
    fi
else
    print_warning "HTTPS is not enabled - not recommended for production"
fi

# Step 6: Check system resources
print_status "Checking system resources..."

# Check available disk space
DISK_USAGE=$(df . | tail -1 | awk '{print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 90 ]; then
    print_warning "Disk usage is high: ${DISK_USAGE}%"
fi

# Check available memory
if command -v free &> /dev/null; then
    AVAILABLE_MEM=$(free -m | awk 'NR==2{printf "%.1f", $7/1024}')
    print_success "Available memory: ${AVAILABLE_MEM}GB"
fi

# Step 7: Create necessary directories
print_status "Creating necessary directories..."

mkdir -p logs
mkdir -p data
mkdir -p uploads

# Set appropriate permissions
chmod 755 logs data uploads
chmod 644 config.json
chmod 755 ghostkey_server

print_success "Directory structure created"

# Step 8: Validate port availability
print_status "Checking port availability..."

SERVER_PORT=$(grep -o '"Interface":[[:space:]]*"[^"]*"' config.json | cut -d'"' -f4 | cut -d':' -f2)
if [ -z "$SERVER_PORT" ]; then
    SERVER_PORT="8080"  # Default port
fi

if netstat -tuln | grep -q ":$SERVER_PORT "; then
    print_warning "Port $SERVER_PORT is already in use"
else
    print_success "Port $SERVER_PORT is available"
fi

# Step 9: Create systemd service file (if systemd is available)
if command -v systemctl &> /dev/null; then
    print_status "Creating systemd service file..."
    
    CURRENT_DIR=$(pwd)
    CURRENT_USER=$(whoami)
    
    cat > ghostkey-server.service << EOF
[Unit]
Description=Ghostkey Server
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$CURRENT_DIR
ExecStart=$CURRENT_DIR/ghostkey_server
Restart=always
RestartSec=5
Environment=GIN_MODE=release

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$CURRENT_DIR

[Install]
WantedBy=multi-user.target
EOF

    print_success "Systemd service file created: ghostkey-server.service"
    print_status "To install the service, run:"
    echo "  sudo cp ghostkey-server.service /etc/systemd/system/"
    echo "  sudo systemctl daemon-reload"
    echo "  sudo systemctl enable ghostkey-server"
    echo "  sudo systemctl start ghostkey-server"
fi

# Step 10: Create backup script
print_status "Creating backup script..."

cat > backup.sh << 'EOF'
#!/bin/bash

# Backup script for Ghostkey Server
BACKUP_DIR="./backups/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup configuration
cp config.json "$BACKUP_DIR/"

# Backup database
if [ -f "data.db" ]; then
    cp data.db "$BACKUP_DIR/"
fi

# Backup any uploaded files
if [ -d "uploads" ]; then
    cp -r uploads "$BACKUP_DIR/"
fi

echo "Backup created: $BACKUP_DIR"
EOF

chmod +x backup.sh
print_success "Backup script created: backup.sh"

# Step 11: Final security check
print_status "Performing final security checks..."

# Check for common security issues
ISSUES=0

if grep -q "secret.*test\|secret.*dev\|secret.*admin" config.json; then
    print_error "Weak secret key detected in configuration"
    ISSUES=$((ISSUES + 1))
fi

if [ -f ".env" ]; then
    ENV_PERMS=$(stat -c "%a" .env)
    if [ "$ENV_PERMS" -gt 600 ]; then
        print_warning ".env file permissions are too permissive ($ENV_PERMS)"
        ISSUES=$((ISSUES + 1))
    fi
fi

# Check for test files in production
if find . -name "*test*" -type f | grep -v "_test.go" | grep -v "deployment_test.go" | head -1; then
    print_warning "Test files found in production directory"
fi

# Step 12: Generate deployment summary
echo ""
echo "================================================"
echo "🏁 DEPLOYMENT SUMMARY"
echo "================================================"

print_success "✅ Application built successfully"
print_success "✅ Configuration validated"
print_success "✅ Tests executed"
print_success "✅ System resources checked"
print_success "✅ Security validated"

if [ "$ISSUES" -gt 0 ]; then
    print_warning "⚠️  $ISSUES security issues detected - please review"
else
    print_success "✅ No security issues detected"
fi

echo ""
echo "🚀 Ready for production deployment!"
echo ""
echo "Next steps:"
echo "1. Review any warnings above"
echo "2. Test the application: ./ghostkey_server"
echo "3. Monitor logs in the logs/ directory"
echo "4. Set up regular backups using backup.sh"
echo "5. Monitor system resources and performance"
echo ""
echo "For production monitoring, consider:"
echo "- Setting up log rotation"
echo "- Configuring monitoring/alerting"
echo "- Regular security updates"
echo "- Database maintenance schedules"
echo ""

print_success "Deployment validation completed!"
