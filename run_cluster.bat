@echo off
REM run_cluster.bat - Script to run a local GhostkeyServer cluster for testing on Windows

REM Check if docker is installed
where docker >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: docker is not installed
    exit /b 1
)

REM Check if docker-compose is installed
where docker-compose >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo Error: docker-compose is not installed
    exit /b 1
)

REM Create a secret key if not provided
if "%SECRET_KEY%"=="" (
    for /f "tokens=1-3 delims=:." %%a in ("%TIME%") do (
        set SECRET_KEY=test_secret_key_%%a%%b%%c
    )
    echo Using generated SECRET_KEY: %SECRET_KEY%
)

echo Starting Ghostkey Server cluster with 3 nodes...
docker-compose -f docker-compose.cluster.yml up --build

REM The script will continue here when docker-compose is stopped
echo Cluster has been stopped
