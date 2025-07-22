#!/bin/bash

# SPIRE Trust Bundle Generator for Docker Compose Build Process
# This script ensures trust bundle is available before agent containers are built

set -e

echo "🔐 SPIRE Trust Bundle Generator"
echo "==============================="

# Configuration
TRUST_BUNDLE_DIR="./trust-bundle"
TRUST_BUNDLE_FILE="$TRUST_BUNDLE_DIR/trust-bundle.pem"
DOCKER_COMPOSE_FILE="./docker-compose.yml"

# Create trust bundle directory
mkdir -p "$TRUST_BUNDLE_DIR"

# Function to check if SPIRE server is running
check_spire_server() {
    local container_id=$(docker ps --filter "name=spire-server" --format "{{.ID}}" | head -1)
    if [ -n "$container_id" ]; then
        echo "✅ Found running SPIRE server: $container_id"
        return 0
    else
        echo "❌ SPIRE server container not found"
        return 1
    fi
}

# Function to extract trust bundle from running server
extract_from_running_server() {
    echo "📤 Extracting trust bundle from running SPIRE server..."
    local container_id=$(docker ps --filter "name=spire-server" --format "{{.ID}}" | head -1)
    
    if docker exec "$container_id" /opt/spire/bin/spire-server bundle show -format pem > "$TRUST_BUNDLE_FILE" 2>/dev/null; then
        echo "✅ Trust bundle extracted successfully"
        return 0
    else
        echo "❌ Failed to extract trust bundle from running server"
        return 1
    fi
}

# Function to start temporary SPIRE server to generate trust bundle
generate_with_temporary_server() {
    echo "🚀 Starting temporary SPIRE server to generate trust bundle..."
    
    # Start only the necessary services for trust bundle generation
    docker compose up -d postgres ecs-metadata-mock
    
    # Wait for postgres to be ready
    echo "⏳ Waiting for PostgreSQL to be ready..."
    sleep 5
    
    # Start SPIRE server
    docker compose up -d spire-server
    
    # Wait for SPIRE server to initialize
    echo "⏳ Waiting for SPIRE server to initialize..."
    sleep 15
    
    # Try to extract trust bundle
    local retries=5
    local count=0
    
    while [ $count -lt $retries ]; do
        if extract_from_running_server; then
            echo "✅ Trust bundle generated successfully"
            
            # Clean up temporary containers
            echo "🧹 Cleaning up temporary containers..."
            docker compose down
            
            return 0
        else
            count=$((count + 1))
            echo "⏳ Retry $count/$retries - waiting for server..."
            sleep 10
        fi
    done
    
    echo "❌ Failed to generate trust bundle after $retries attempts"
    docker compose down
    return 1
}

# Function to use existing trust bundle if valid
use_existing_bundle() {
    if [ -f "$TRUST_BUNDLE_FILE" ]; then
        echo "📋 Checking existing trust bundle..."
        local file_size=$(wc -c < "$TRUST_BUNDLE_FILE")
        
        if [ "$file_size" -gt 100 ]; then
            echo "✅ Using existing trust bundle ($file_size bytes)"
            return 0
        else
            echo "⚠️ Existing trust bundle too small, regenerating..."
            return 1
        fi
    else
        echo "❌ No existing trust bundle found"
        return 1
    fi
}

# Main logic
main() {
    echo "🔍 Checking for existing trust bundle..."
    
    # Try to use existing bundle first
    if use_existing_bundle; then
        echo "✅ Trust bundle ready for build process"
        return 0
    fi
    
    # Check if SPIRE server is already running
    if check_spire_server; then
        if extract_from_running_server; then
            echo "✅ Trust bundle ready for build process"
            return 0
        fi
    fi
    
    # Generate trust bundle with temporary server
    echo "🔄 Generating fresh trust bundle..."
    if generate_with_temporary_server; then
        echo "✅ Trust bundle ready for build process"
        return 0
    fi
    
    echo "❌ Failed to generate trust bundle"
    return 1
}

# Execute main function
main

# Display trust bundle info
if [ -f "$TRUST_BUNDLE_FILE" ]; then
    echo ""
    echo "📊 Trust Bundle Information:"
    echo "   File: $TRUST_BUNDLE_FILE"
    echo "   Size: $(wc -c < "$TRUST_BUNDLE_FILE") bytes"
    echo "   Lines: $(wc -l < "$TRUST_BUNDLE_FILE") lines"
    echo ""
    echo "🔍 Trust bundle preview:"
    head -3 "$TRUST_BUNDLE_FILE"
    echo "..."
    tail -2 "$TRUST_BUNDLE_FILE"
    echo ""
    echo "✅ Trust bundle ready for agent containers"
else
    echo "❌ Trust bundle generation failed"
    exit 1
fi
