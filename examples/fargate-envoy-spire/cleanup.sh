#!/bin/bash

# SPIRE Fargate Envoy Service Mesh - Cleanup Script
# This script provides comprehensive cleanup for the Envoy service mesh example

set -e

echo "🧹 SPIRE Fargate Envoy Service Mesh Cleanup"
echo "==========================================="

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

# Function to stop and remove containers
cleanup_containers() {
    log_info "Stopping and removing Envoy service mesh containers..."
    
    cd "$SCRIPT_DIR"
    
    # Stop and remove containers
    if docker compose down --remove-orphans --volumes; then
        log_success "Containers stopped and removed"
    else
        log_warning "Some containers may not have been cleaned up properly"
    fi
    
    # Remove any dangling containers
    docker container prune -f || true
    
    log_success "Container cleanup completed"
}

# Function to remove images
cleanup_images() {
    log_info "Removing Envoy service mesh images..."
    
    local images=(
        "fargate-envoy-spire-demo-app"
        "fargate-envoy-spire-api-service-with-agent"
        "fargate-envoy-spire-cli-client-with-agent"
    )
    
    for image in "${images[@]}"; do
        if docker image inspect "$image" >/dev/null 2>&1; then
            docker image rm "$image" || log_warning "Failed to remove image: $image"
            log_info "Removed image: $image"
        fi
    done
    
    # Remove dangling images
    docker image prune -f || true
    
    log_success "Image cleanup completed"
}

# Function to remove volumes
cleanup_volumes() {
    log_info "Removing Envoy service mesh volumes..."
    
    local volumes=(
        "fargate-envoy-spire_postgres_data"
        "fargate-envoy-spire_spire_server_data"
        "fargate-envoy-spire_spire_agent_socket"
        "fargate-envoy-spire_spire_agent_socket_api"
        "fargate-envoy-spire_spire_agent_socket_cli"
    )
    
    for volume in "${volumes[@]}"; do
        if docker volume inspect "$volume" >/dev/null 2>&1; then
            docker volume rm "$volume" || log_warning "Failed to remove volume: $volume"
            log_info "Removed volume: $volume"
        fi
    done
    
    # Remove dangling volumes
    docker volume prune -f || true
    
    log_success "Volume cleanup completed"
}

# Function to clean up distributed trust bundles
cleanup_trust_bundles() {
    log_info "Cleaning up distributed trust bundles..."
    
    local services=("app-with-envoy" "api-service-with-envoy" "cli-client-with-envoy")
    
    for service in "${services[@]}"; do
        local bundle_file="$SCRIPT_DIR/$service/trust-bundle.pem"
        if [ -f "$bundle_file" ]; then
            rm -f "$bundle_file"
            log_info "Removed trust bundle from $service"
        fi
    done
    
    log_success "Trust bundle cleanup completed"
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
    
    # Clean up server plugin binary if exists
    local server_binary="$PARENT_DIR/fargate-spire-mock/spire-server/aws-fargate-server-nodeattestor"
    if [ -f "$server_binary" ]; then
        rm -f "$server_binary"
        log_info "Removed server plugin binary"
    fi
    
    log_success "Plugin binary cleanup completed"
}

# Function to clean up networks
cleanup_networks() {
    log_info "Cleaning up Docker networks..."
    
    local network="fargate-envoy-spire_spire-network"
    
    if docker network inspect "$network" >/dev/null 2>&1; then
        docker network rm "$network" || log_warning "Failed to remove network: $network"
        log_info "Removed network: $network"
    fi
    
    # Remove dangling networks
    docker network prune -f || true
    
    log_success "Network cleanup completed"
}

# Function to reset Envoy admin interfaces
reset_envoy_admin() {
    log_info "Resetting Envoy admin interface data..."
    
    # Admin interfaces run on containers, so stopping containers resets them
    # This is just a placeholder for any future admin-specific cleanup
    
    log_success "Envoy admin reset completed"
}

# Function to show cleanup summary
show_cleanup_summary() {
    log_success "🎉 Cleanup Summary:"
    echo ""
    echo "✅ Containers stopped and removed"
    echo "✅ Images removed"
    echo "✅ Volumes removed"
    echo "✅ Networks cleaned up"
    echo "✅ Trust bundles cleaned up"
    echo "✅ Plugin binaries cleaned up"
    echo "✅ Envoy admin interfaces reset"
    echo ""
    echo "The Envoy service mesh environment has been completely cleaned up."
    echo "You can now run './build-with-trust-bundle.sh' to rebuild from scratch."
    echo ""
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --containers-only    Stop and remove containers only"
    echo "  --images-only        Remove images only"
    echo "  --volumes-only       Remove volumes only"
    echo "  --files-only         Clean up files only (trust bundles, binaries)"
    echo "  --help              Show this help message"
    echo ""
    echo "Without options, performs complete cleanup of all components."
    echo ""
}

# Parse command line arguments
CONTAINERS_ONLY=false
IMAGES_ONLY=false
VOLUMES_ONLY=false
FILES_ONLY=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --containers-only)
            CONTAINERS_ONLY=true
            shift
            ;;
        --images-only)
            IMAGES_ONLY=true
            shift
            ;;
        --volumes-only)
            VOLUMES_ONLY=true
            shift
            ;;
        --files-only)
            FILES_ONLY=true
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
    log_info "Starting Envoy service mesh cleanup..."
    
    if [ "$CONTAINERS_ONLY" = true ]; then
        cleanup_containers
        log_success "Container-only cleanup completed!"
        
    elif [ "$IMAGES_ONLY" = true ]; then
        cleanup_images
        log_success "Image-only cleanup completed!"
        
    elif [ "$VOLUMES_ONLY" = true ]; then
        cleanup_volumes
        log_success "Volume-only cleanup completed!"
        
    elif [ "$FILES_ONLY" = true ]; then
        cleanup_trust_bundles
        cleanup_plugin_binaries
        log_success "File-only cleanup completed!"
        
    else
        # Complete cleanup
        cleanup_containers
        cleanup_images
        cleanup_volumes
        cleanup_networks
        cleanup_trust_bundles
        cleanup_plugin_binaries
        reset_envoy_admin
        show_cleanup_summary
    fi
}

# Execute main function
main "$@"
