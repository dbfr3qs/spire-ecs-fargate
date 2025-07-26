#!/bin/bash

# SPIRE Fargate Envoy Service Mesh Example - Build with Trust Bundle
# This script builds the Envoy sidecar service mesh example with automated trust bundle management

set -e

echo "🚀 SPIRE Fargate Envoy Service Mesh Build"
echo "========================================"

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$SCRIPT_DIR")"

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

# Function to generate trust bundle using the fargate-spire-mock infrastructure
generate_trust_bundle() {
    log_info "Generating trust bundle using SPIRE infrastructure..."
    
    # Use the trust bundle generator from the original mock example
    if [ -f "$PARENT_DIR/fargate-spire-mock/generate-trust-bundle.sh" ]; then
        cd "$PARENT_DIR/fargate-spire-mock"
        bash generate-trust-bundle.sh
        TRUST_BUNDLE_SOURCE="$PARENT_DIR/fargate-spire-mock/trust-bundle/trust-bundle.pem"
        
        if [ -f "$TRUST_BUNDLE_SOURCE" ]; then
            log_success "Trust bundle generated successfully"
            return 0
        else
            log_error "Trust bundle generation failed"
            return 1
        fi
    else
        log_error "Trust bundle generator not found at $PARENT_DIR/fargate-spire-mock/generate-trust-bundle.sh"
        return 1
    fi
}

# Function to verify trust bundle
verify_trust_bundle() {
    local trust_bundle_file="$1"
    
    if [ ! -f "$trust_bundle_file" ]; then
        log_error "Trust bundle file not found: $trust_bundle_file"
        return 1
    fi
    
    # Check file size
    local file_size=$(stat -f%z "$trust_bundle_file" 2>/dev/null || stat -c%s "$trust_bundle_file" 2>/dev/null)
    if [ "$file_size" -lt 100 ]; then
        log_error "Trust bundle file too small: $file_size bytes"
        return 1
    fi
    
    # Check PEM format
    if ! grep -q "BEGIN CERTIFICATE" "$trust_bundle_file"; then
        log_error "Trust bundle does not contain valid PEM certificates"
        return 1
    fi
    
    log_success "Trust bundle verification passed ($file_size bytes)"
    return 0
}

# Function to distribute trust bundle to Envoy service directories
distribute_trust_bundle() {
    local source_bundle="$PARENT_DIR/fargate-spire-mock/trust-bundle/trust-bundle.pem"
    
    log_info "Distributing trust bundle to Envoy service directories..."
    
    if [ ! -f "$source_bundle" ]; then
        log_error "Source trust bundle not found: $source_bundle"
        return 1
    fi
    
    # Distribute to each Envoy service directory
    local services=("app-with-envoy" "api-service-with-envoy" "cli-client-with-envoy")
    
    for service in "${services[@]}"; do
        local dest_file="$SCRIPT_DIR/$service/trust-bundle.pem"
        cp "$source_bundle" "$dest_file"
        
        if verify_trust_bundle "$dest_file"; then
            log_success "Trust bundle distributed to $service"
        else
            log_error "Failed to distribute trust bundle to $service"
            return 1
        fi
    done
    
    log_success "Trust bundle distributed successfully to all Envoy services"
}

# Function to clean up distributed trust bundles
cleanup_distributed_bundles() {
    log_info "Cleaning up distributed trust bundles..."
    
    local services=("app-with-envoy" "api-service-with-envoy" "cli-client-with-envoy")
    
    for service in "${services[@]}"; do
        local bundle_file="$SCRIPT_DIR/$service/trust-bundle.pem"
        if [ -f "$bundle_file" ]; then
            rm -f "$bundle_file"
            log_info "Removed trust bundle from $service"
        fi
    done
    
    log_success "Distributed trust bundles cleaned up"
}

# Function to build SPIRE plugin binaries from source
build_plugin_binaries() {
    log_info "Building SPIRE plugin binaries from source..."
    
    local plugin_source_dir="$PARENT_DIR/.."
    local agent_dir="$plugin_source_dir/agent"
    local server_dir="$plugin_source_dir/server"
    
    # Verify directories exist
    if [ ! -d "$agent_dir" ]; then
        log_error "Agent plugin directory not found: $agent_dir"
        return 1
    fi
    
    if [ ! -d "$server_dir" ]; then
        log_error "Server plugin directory not found: $server_dir"
        return 1
    fi
    
    local original_dir=$(pwd)
    
    # Build agent plugin (has its own go.mod)
    log_info "Building agent plugin binary..."
    cd "$agent_dir"
    
    if GOOS=linux GOARCH=arm64 go build -o aws-fargate-nodeattestor .; then
        log_success "Agent plugin binary built successfully"
    else
        log_error "Failed to build agent plugin binary"
        cd "$original_dir"
        return 1
    fi
    
    # Build server plugin (has its own go.mod)
    log_info "Building server plugin binary..."
    cd "$server_dir"
    
    if GOOS=linux GOARCH=arm64 go build -o aws-fargate-server-nodeattestor .; then
        log_success "Server plugin binary built successfully"
    else
        log_error "Failed to build server plugin binary"
        cd "$original_dir"
        return 1
    fi
    
    # Copy agent binary to service directories
    local services=("app-with-envoy" "api-service-with-envoy" "cli-client-with-envoy")
    
    for service in "${services[@]}"; do
        cp "$agent_dir/aws-fargate-nodeattestor" "$SCRIPT_DIR/$service/"
        log_info "Copied agent plugin to $service"
    done
    
    # Copy server plugin to SPIRE server directory
    cp "$server_dir/aws-fargate-server-nodeattestor" "$PARENT_DIR/fargate-spire-mock/spire-server/"
    log_success "Copied server plugin to SPIRE server"
    
    # Clean up binaries from build directories
    rm -f "$agent_dir/aws-fargate-nodeattestor" "$server_dir/aws-fargate-server-nodeattestor"
    
    # Restore original directory
    cd "$original_dir"
    
    log_success "Plugin binaries built and distributed"
}

# Function to clean up plugin binaries
cleanup_plugin_binaries() {
    log_info "Cleaning up plugin binaries..."
    
    local services=("app-with-envoy" "api-service-with-envoy" "cli-client-with-envoy")
    
    for service in "${services[@]}"; do
        local binary_file="$SCRIPT_DIR/$service/aws-fargate-nodeattestor"
        if [ -f "$binary_file" ]; then
            rm -f "$binary_file"
            log_info "Removed agent plugin from $service"
        fi
    done
    
    log_success "Plugin binaries cleaned up"
}

# Function to build containers with Envoy sidecar architecture
build_containers() {
    log_info "Building Envoy sidecar containers..."
    
    cd "$SCRIPT_DIR"
    
    # Build containers with Docker Compose
    if docker compose build --no-cache; then
        log_success "Envoy sidecar containers built successfully"
    else
        log_error "Failed to build Envoy sidecar containers"
        return 1
    fi
}

# Function to start services
start_services() {
    log_info "Starting Envoy service mesh services..."
    
    cd "$SCRIPT_DIR"
    
    if docker compose up -d; then
        log_success "Envoy services started"
    else
        log_error "Failed to start Envoy services"
        return 1
    fi
}

# Function to wait for services to be ready
wait_for_services() {
    log_info "Waiting for services to be ready..."
    
    local max_wait=180
    local wait_time=0
    
    while [ $wait_time -lt $max_wait ]; do
        if curl -s -f http://localhost:8080/health >/dev/null 2>&1 && \
           curl -s -f http://localhost:8082/health >/dev/null 2>&1; then
            log_success "Services are ready!"
            return 0
        fi
        
        echo -n "."
        sleep 3
        wait_time=$((wait_time + 3))
    done
    
    log_warning "Services may not be fully ready yet (timeout after ${max_wait}s)"
    return 1
}

# Function to display service status
display_status() {
    log_info "Service mesh status:"
    echo ""
    echo "🌐 Web Application (with Envoy):    http://localhost:8080"
    echo "🔌 API Service (with Envoy):        http://localhost:8082"
    echo "📊 SPIRE Server:                    http://localhost:8081"
    echo "🖥️  ECS Metadata Mock:              http://localhost:8090"
    echo ""
    echo "📈 Envoy Admin Interfaces:"
    echo "   Web App Envoy:                   http://localhost:9901"
    echo "   API Service Envoy:               http://localhost:9902"
    echo "   CLI Client Envoy:                http://localhost:9903"
    echo ""
    echo "🔍 To test CLI client:"
    echo "   docker exec -it fargate-envoy-spire-cli-client-with-agent-1 /usr/local/bin/spire-cli"
    echo ""
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --clean-build    Clean build (remove existing containers and volumes)"
    echo "  --no-start       Build only, don't start services"
    echo "  --help          Show this help message"
    echo ""
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

# Main function
main() {
    local success=true
    
    # Trap to ensure cleanup on exit
    trap 'cleanup_distributed_bundles; cleanup_plugin_binaries' EXIT
    
    if [ "$CLEAN_BUILD" = true ]; then
        cleanup_existing
    fi
    
    # Generate and distribute trust bundle
    if ! generate_trust_bundle; then
        success=false
    fi
    
    if $success && ! distribute_trust_bundle; then
        success=false
    fi
    
    # Build plugin binaries
    if $success && ! build_plugin_binaries; then
        success=false
    fi
    
    # Build containers
    if $success && ! build_containers; then
        success=false
    fi
    
    # Start services if requested
    if $success && [ "$NO_START" = false ]; then
        if start_services && wait_for_services; then
            display_status
        else
            log_warning "Services started but may not be fully ready"
            display_status
        fi
    fi
    
    if $success; then
        log_success "🎉 SPIRE Fargate Envoy Service Mesh build completed successfully!"
    else
        log_error "❌ Build failed!"
        exit 1
    fi
}

# Execute main function
main "$@"
