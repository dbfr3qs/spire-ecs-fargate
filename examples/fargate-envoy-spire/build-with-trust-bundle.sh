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

# Function to generate trust bundle from the actual running SPIRE server
generate_trust_bundle() {
    log_info "Generating trust bundle from running SPIRE server..."
    
    # Check if SPIRE server is running
    if ! docker compose ps spire-server --status running --quiet >/dev/null 2>&1; then
        log_error "SPIRE server is not running. Please start the services first with 'docker compose up -d'"
        return 1
    fi
    
    log_info "SPIRE server is running, extracting current trust bundle..."
    
    # Get trust bundle directly from the running SPIRE server
    if docker exec fargate-envoy-spire-spire-server-1 /opt/spire/bin/spire-server bundle show -format pem > /tmp/current-trust-bundle.pem 2>/dev/null; then
        TRUST_BUNDLE_SOURCE="/tmp/current-trust-bundle.pem"
        log_success "Trust bundle extracted from running SPIRE server"
        return 0
    else
        log_error "Failed to extract trust bundle from running SPIRE server"
        log_error "This could happen if the SPIRE server is not fully initialized yet"
        log_info "Try waiting a few more seconds for the SPIRE server to be ready, then run again"
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
    local source_bundle="${TRUST_BUNDLE_SOURCE}"
    
    log_info "Distributing trust bundle to Envoy service directories..."
    
    if [ ! -f "$source_bundle" ]; then
        log_error "Source trust bundle not found: $source_bundle"
        return 1
    fi
    
    # Distribute to each Envoy service directory (including React app)
    local services=("app-with-envoy" "api-service-with-envoy" "cli-client-with-envoy" "react-app-with-envoy")
    
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
    
    local services=("app-with-envoy" "api-service-with-envoy" "cli-client-with-envoy" "react-app-with-envoy")
    
    for service in "${services[@]}"; do
        local bundle_file="$SCRIPT_DIR/$service/trust-bundle.pem"
        if [ -f "$bundle_file" ]; then
            rm -f "$bundle_file"
            log_info "Removed trust bundle from $service"
        fi
    done
    
    # Clean up temporary trust bundle
    if [ -f "/tmp/current-trust-bundle.pem" ]; then
        rm -f "/tmp/current-trust-bundle.pem"
    fi
    
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
    
    # Copy agent binary to service directories (including React app)
    local services=("app-with-envoy" "api-service-with-envoy" "cli-client-with-envoy" "react-app-with-envoy")
    
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
    
    local services=("app-with-envoy" "api-service-with-envoy" "cli-client-with-envoy" "react-app-with-envoy")
    
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

# Function to update trust bundles in running containers
update_running_containers() {
    log_info "Updating trust bundles in running containers..."
    
    local services=("api-service-with-agent" "demo-app" "cli-client-with-agent" "react-demo-app")
    local updated_containers=()
    
    for service in "${services[@]}"; do
        local container_name="fargate-envoy-spire-${service}-1"
        
        # Check if container is running
        if docker ps --format '{{.Names}}' | grep -q "^${container_name}$"; then
            log_info "Updating trust bundle in $container_name..."
            
            # Copy updated trust bundle to running container
            if docker cp "${TRUST_BUNDLE_SOURCE}" "${container_name}:/opt/spire/trust-bundle/trust-bundle.pem"; then
                log_success "Trust bundle updated in $container_name"
                updated_containers+=("$container_name")
            else
                log_warning "Failed to update trust bundle in $container_name"
            fi
        fi
    done
    
    # Restart containers that received trust bundle updates
    if [ ${#updated_containers[@]} -gt 0 ]; then
        log_info "Restarting containers with updated trust bundles..."
        for container in "${updated_containers[@]}"; do
            log_info "Restarting $container..."
            docker restart "$container" >/dev/null 2>&1
        done
        
        # Wait for containers to be healthy again
        log_info "Waiting for restarted containers to be healthy..."
        sleep 30
        
        log_success "Trust bundle updates completed"
    fi
}

# Function to verify and create SPIRE entries
verify_spire_entries() {
    log_info "Verifying SPIRE entries..."
    
    # Wait for SPIRE server to be ready
    local max_wait=60
    local wait_time=0
    
    while [ $wait_time -lt $max_wait ]; do
        if docker exec fargate-envoy-spire-spire-server-1 /opt/spire/bin/spire-server healthcheck >/dev/null 2>&1; then
            break
        fi
        
        sleep 2
        wait_time=$((wait_time + 2))
    done
    
    if [ $wait_time -ge $max_wait ]; then
        log_warning "SPIRE server not ready, skipping entry verification"
        return 1
    fi
    
    # Get existing entries
    local existing_entries=$(docker exec fargate-envoy-spire-spire-server-1 /opt/spire/bin/spire-server entry show 2>/dev/null || echo "")
    
    # Define required entries
    local required_entries=(
        "spiffe://example.org/api-service"
        "spiffe://example.org/demo-app" 
        "spiffe://example.org/cli-client"
        "spiffe://example.org/react-demo-app"
    )
    
    local parent_id="spiffe://example.org/aws_fargate_task/123456789012/test-cluster"
    
    # Check and create missing entries
    for spiffe_id in "${required_entries[@]}"; do
        if echo "$existing_entries" | grep -q "$spiffe_id"; then
            # Verify parent ID is correct
            if echo "$existing_entries" | grep -A5 "$spiffe_id" | grep -q "$parent_id"; then
                log_success "SPIRE entry verified: $spiffe_id"
            else
                log_warning "SPIRE entry has incorrect parent ID: $spiffe_id, recreating..."
                
                # Get entry ID and delete it
                local entry_id=$(echo "$existing_entries" | grep -B5 "$spiffe_id" | grep "Entry ID" | awk '{print $4}')
                if [ -n "$entry_id" ]; then
                    docker exec fargate-envoy-spire-spire-server-1 /opt/spire/bin/spire-server entry delete -entryID "$entry_id" >/dev/null 2>&1
                fi
                
                # Create new entry with correct parent ID
                docker exec fargate-envoy-spire-spire-server-1 /opt/spire/bin/spire-server entry create \
                    -spiffeID "$spiffe_id" \
                    -parentID "$parent_id" \
                    -selector unix:uid:0 >/dev/null 2>&1
                    
                log_success "SPIRE entry recreated: $spiffe_id"
            fi
        else
            log_info "Creating missing SPIRE entry: $spiffe_id"
            docker exec fargate-envoy-spire-spire-server-1 /opt/spire/bin/spire-server entry create \
                -spiffeID "$spiffe_id" \
                -parentID "$parent_id" \
                -selector unix:uid:0 >/dev/null 2>&1
                
            log_success "SPIRE entry created: $spiffe_id"
        fi
    done
    
    log_success "SPIRE entries verification completed"
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
        # Check core services
        local go_app_ready=$(curl -s -f http://localhost:8080/health >/dev/null 2>&1 && echo "true" || echo "false")
        local api_service_ready=$(curl -s -f http://localhost:8083/health >/dev/null 2>&1 && echo "true" || echo "false")
        local react_app_ready=$(curl -s -f http://localhost:3000/health >/dev/null 2>&1 && echo "true" || echo "false")
        
        if [ "$go_app_ready" = "true" ] && [ "$api_service_ready" = "true" ] && [ "$react_app_ready" = "true" ]; then
            log_success "All services are ready!"
            return 0
        fi
        
        echo -n "."
        sleep 3
        wait_time=$((wait_time + 3))
    done
    
    log_warning "Services may not be fully ready yet (timeout after ${max_wait}s)"
    log_info "Service status - Go App: $go_app_ready, API: $api_service_ready, React: $react_app_ready"
    return 1
}

# Function to display service status
display_status() {
    log_info "Service mesh status:"
    echo ""
    echo "🌐 Go Web Application (with Envoy):     http://localhost:8080"
    echo "⚛️  React Application (with Envoy):     http://localhost:3000"
    echo "🔌 API Service (with Envoy):            http://localhost:8083"
    echo "📊 SPIRE Server:                        http://localhost:8081"
    echo "🖥️  ECS Metadata Mock:                  http://localhost:8090"
    echo ""
    echo "📈 Envoy Admin Interfaces:"
    echo "   Go App Envoy:                        http://localhost:9901"
    echo "   API Service Envoy:                   http://localhost:9902"
    echo "   CLI Client Envoy:                    http://localhost:9903"
    echo "   React App Envoy:                     http://localhost:9904"
    echo ""
    echo "🔍 Test Commands:"
    echo "   CLI Client:    docker exec -it fargate-envoy-spire-cli-client-with-agent-1 /usr/local/bin/spire-cli"
    echo "   Go App API:    curl http://localhost:8080/api-call"
    echo "   React API:     curl http://localhost:3000/api-call"
    echo ""
    echo "🎯 mTLS Communication Test:"
    echo "   Both Go and React apps can call the API service through Envoy with automatic mTLS!"
    echo ""
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "This script builds and manages the SPIRE Envoy Service Mesh with guaranteed trust bundle synchronization."
    echo ""
    echo "Options:"
    echo "  --clean-build          Clean build (remove existing containers and volumes)"
    echo "  --no-start             Build only, don't start services"
    echo "  --update-trust-bundle  Update trust bundles in running containers (no rebuild)"
    echo "  --help                 Show this help message"
    echo ""
    echo "Features:"
    echo "  • Direct trust bundle extraction from running SPIRE server (no fallbacks)"
    echo "  • Support for Go and React applications with Envoy sidecars"
    echo "  • SPIRE entry verification and auto-creation"
    echo "  • Trust bundle updates without container rebuilds"
    echo "  • Automatic container restart and health verification"
    echo ""
}

# Parse command line arguments
CLEAN_BUILD=false
NO_START=false
UPDATE_TRUST_BUNDLE_ONLY=false

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
        --update-trust-bundle)
            UPDATE_TRUST_BUNDLE_ONLY=true
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
    
    # Trap to ensure cleanup on exit (but not for trust bundle only updates)
    if [ "$UPDATE_TRUST_BUNDLE_ONLY" = false ]; then
        trap 'cleanup_distributed_bundles; cleanup_plugin_binaries' EXIT
    fi
    
    # Handle trust bundle only update
    if [ "$UPDATE_TRUST_BUNDLE_ONLY" = true ]; then
        log_info "🔄 Trust bundle update mode - updating running containers only"
        
        if generate_trust_bundle && update_running_containers && verify_spire_entries; then
            log_success "🎉 Trust bundle update completed successfully!"
            display_status
        else
            log_error "❌ Trust bundle update failed!"
            exit 1
        fi
        return 0
    fi
    
    # Full build process
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
            # Verify and create SPIRE entries after services are running
            verify_spire_entries
            display_status
        else
            log_warning "Services started but may not be fully ready"
            display_status
        fi
    fi
    
    if $success; then
        log_success "🎉 SPIRE Fargate Envoy Service Mesh build completed successfully!"
        echo ""
        log_info "💡 Pro tip: Use '$0 --update-trust-bundle' to update trust bundles without rebuilding containers"
    else
        log_error "❌ Build failed!"
        exit 1
    fi
}

# Execute main function
main "$@"
