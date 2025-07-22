#!/bin/bash

# SPIRE Fargate Mock Environment - Build with Trust Bundle
# This script ensures trust bundle is generated and deployed before building agent containers

set -e

echo "🚀 SPIRE Fargate Mock Environment Build"
echo "======================================"

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRUST_BUNDLE_DIR="$SCRIPT_DIR/trust-bundle"
TRUST_BUNDLE_FILE="$TRUST_BUNDLE_DIR/trust-bundle.pem"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Function to clean up any existing containers
cleanup_existing() {
    log_info "Cleaning up existing containers..."
    
    # Stop and remove existing containers
    docker compose down --remove-orphans || true
    
    # Remove any dangling containers
    docker container prune -f || true
    
    log_success "Cleanup completed"
}

# Function to generate trust bundle
generate_trust_bundle() {
    log_info "Generating trust bundle..."
    
    if [ -x "$SCRIPT_DIR/generate-trust-bundle.sh" ]; then
        if "$SCRIPT_DIR/generate-trust-bundle.sh"; then
            log_success "Trust bundle generated successfully"
            return 0
        else
            log_error "Trust bundle generation failed"
            return 1
        fi
    else
        log_error "Trust bundle generation script not found or not executable"
        return 1
    fi
}

# Function to verify trust bundle
verify_trust_bundle() {
    log_info "Verifying trust bundle..."
    
    if [ ! -f "$TRUST_BUNDLE_FILE" ]; then
        log_error "Trust bundle file not found: $TRUST_BUNDLE_FILE"
        return 1
    fi
    
    local file_size=$(wc -c < "$TRUST_BUNDLE_FILE")
    local line_count=$(wc -l < "$TRUST_BUNDLE_FILE")
    
    if [ "$file_size" -lt 100 ]; then
        log_error "Trust bundle file too small ($file_size bytes)"
        return 1
    fi
    
    # Check if file contains PEM format
    if ! grep -q "BEGIN CERTIFICATE" "$TRUST_BUNDLE_FILE"; then
        log_error "Trust bundle does not contain valid PEM certificates"
        return 1
    fi
    
    log_success "Trust bundle verified ($file_size bytes, $line_count lines)"
    return 0
}

# Function to distribute trust bundle to service directories
distribute_trust_bundle() {
    log_info "Distributing trust bundle to service directories..."
    
    # List of services that need trust bundle
    local services=("app-with-agent" "api-service-with-agent" "cli-client-with-agent")
    
    for service in "${services[@]}"; do
        if [ -d "$service" ]; then
            log_info "Copying trust bundle to $service/"
            if cp "$TRUST_BUNDLE_FILE" "$service/trust-bundle.pem"; then
                log_success "Trust bundle copied to $service/"
            else
                log_error "Failed to copy trust bundle to $service/"
                return 1
            fi
        else
            log_warning "Service directory $service not found"
        fi
    done
    
    log_success "Trust bundle distributed to all service directories"
    return 0
}

# Function to clean up distributed trust bundles
cleanup_distributed_bundles() {
    log_info "Cleaning up distributed trust bundles..."
    
    # List of services that have trust bundle copies
    local services=("app-with-agent" "api-service-with-agent" "cli-client-with-agent")
    
    for service in "${services[@]}"; do
        if [ -f "$service/trust-bundle.pem" ]; then
            rm -f "$service/trust-bundle.pem"
            log_info "Removed trust bundle from $service/"
        fi
    done
    
    log_success "Distributed trust bundles cleaned up"
}

# Function to build containers with trust bundle
build_containers() {
    log_info "Building containers with trust bundle..."
    
    # First, distribute trust bundle to service directories
    if ! distribute_trust_bundle; then
        log_error "Failed to distribute trust bundle"
        return 1
    fi
    
    # Build containers with --build flag to ensure fresh builds
    if docker compose build --no-cache; then
        log_success "All containers built successfully"
        
        # Clean up distributed trust bundles after successful build
        cleanup_distributed_bundles
        
        return 0
    else
        log_error "Container build failed"
        
        # Clean up distributed trust bundles after failed build
        cleanup_distributed_bundles
        
        return 1
    fi
}

# Function to start services
start_services() {
    log_info "Starting services..."
    
    # Start services in dependency order
    if docker compose up -d; then
        log_success "All services started successfully"
        return 0
    else
        log_error "Failed to start services"
        return 1
    fi
}

# Function to wait for services to be ready
wait_for_services() {
    log_info "Waiting for services to be ready..."
    
    # Wait for SPIRE server to be ready
    local retries=30
    local count=0
    
    while [ $count -lt $retries ]; do
        if docker compose ps | grep -q "spire-server.*healthy\|spire-server.*Up"; then
            log_success "SPIRE server is ready"
            break
        else
            count=$((count + 1))
            log_info "Waiting for SPIRE server... ($count/$retries)"
            sleep 2
        fi
    done
    
    if [ $count -eq $retries ]; then
        log_warning "SPIRE server readiness check timed out"
    fi
    
    # Wait for web applications to be ready
    sleep 5
    
    log_success "Services are ready"
}

# Function to display service status
display_status() {
    echo ""
    log_info "Service Status:"
    echo "=============="
    
    # Display running containers
    docker compose ps
    
    echo ""
    log_info "Service Endpoints:"
    echo "=================="
    echo "🌐 Web Application:     http://localhost:8080"
    echo "🔌 API Service:         http://localhost:8082"
    echo "🔧 SPIRE Server:        http://localhost:8081"
    echo "📊 ECS Metadata Mock:   http://localhost:8090"
    
    echo ""
    log_info "Trust Bundle Information:"
    echo "========================="
    if [ -f "$TRUST_BUNDLE_FILE" ]; then
        echo "📁 File: $TRUST_BUNDLE_FILE"
        echo "📊 Size: $(wc -c < "$TRUST_BUNDLE_FILE") bytes"
        echo "📄 Lines: $(wc -l < "$TRUST_BUNDLE_FILE") lines"
        echo "🕐 Modified: $(stat -f "%Sm" "$TRUST_BUNDLE_FILE")"
    else
        echo "❌ Trust bundle file not found"
    fi
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --clean-build    Clean all containers and rebuild from scratch"
    echo "  --no-start       Generate trust bundle and build containers but don't start services"
    echo "  --help           Show this help message"
    echo ""
    echo "This script automates the SPIRE Fargate mock environment build process:"
    echo "1. Generates fresh trust bundle"
    echo "2. Builds all containers with trust bundle"
    echo "3. Starts services in correct order"
    echo "4. Verifies service readiness"
}

# Parse command line arguments
CLEAN_BUILD=false
NO_START=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --clean-build)
            CLEAN_BUILD=true
            shift
            ;;
        --no-start)
            NO_START=true
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Main execution
main() {
    echo ""
    log_info "Starting SPIRE Fargate Mock Environment build process..."
    
    # Change to script directory
    cd "$SCRIPT_DIR"
    
    # Clean up if requested
    if [ "$CLEAN_BUILD" = true ]; then
        log_info "Performing clean build..."
        cleanup_existing
        
        # Remove trust bundle to force regeneration
        rm -f "$TRUST_BUNDLE_FILE"
        log_info "Removed existing trust bundle for fresh generation"
    fi
    
    # Step 1: Generate trust bundle
    if ! generate_trust_bundle; then
        log_error "Failed to generate trust bundle"
        exit 1
    fi
    
    # Step 2: Verify trust bundle
    if ! verify_trust_bundle; then
        log_error "Trust bundle verification failed"
        exit 1
    fi
    
    # Step 3: Build containers
    if ! build_containers; then
        log_error "Container build failed"
        exit 1
    fi
    
    # Step 4: Start services (unless --no-start is specified)
    if [ "$NO_START" != true ]; then
        if ! start_services; then
            log_error "Failed to start services"
            exit 1
        fi
        
        # Step 5: Wait for services to be ready
        wait_for_services
        
        # Step 6: Display status
        display_status
        
        echo ""
        log_success "SPIRE Fargate Mock Environment is ready!"
        echo ""
        log_info "Next steps:"
        echo "1. Visit http://localhost:8080 to access the web application"
        echo "2. Visit http://localhost:8082 to access the API service"
        echo "3. Test mTLS functionality between services"
        echo "4. Monitor logs with: docker-compose logs -f"
    else
        log_success "Build completed successfully (services not started)"
    fi
}

# Execute main function
main "$@"
