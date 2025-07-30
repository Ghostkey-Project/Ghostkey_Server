# Ghostkey Server Startup Script
$env:SECRET_KEY = "47m04Hzv1ryMESUWdauSCzLuOI8S2DfEJSk0AYbu9hjUvmrdL2dDfy4q1tBLNxFL"
$env:GIN_MODE = "release"
$env:PORT = "5000"
Write-Host "Starting Ghostkey Server..."
Write-Host "Configuration:"
Write-Host "  Port: 5000"
Write-Host "  HTTPS: False"
Write-Host "  Secret Key Length: 64 characters"
Write-Host ""

.\ghostkey_server.exe
