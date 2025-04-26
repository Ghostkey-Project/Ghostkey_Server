#!/bin/sh
# run_cluster.sh - Script to run a local GhostkeyServer cluster for testing

# Check if docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: docker is not installed"
    exit 1
fi

# Check if docker-compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo "Error: docker-compose is not installed"
    exit 1
fi

# Create a secret key if not provided
if [ -z "$SECRET_KEY" ]; then
    export SECRET_KEY="test_secret_key_$(date +%s)"
    echo "Using generated SECRET_KEY: $SECRET_KEY"
fi

echo "Starting Ghostkey Server cluster with 3 nodes..."
docker-compose -f docker-compose.cluster.yml up --build

# The script will continue here when docker-compose is stopped
echo "Cluster has been stopped"
