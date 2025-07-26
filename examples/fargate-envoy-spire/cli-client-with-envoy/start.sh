#!/bin/bash

# Startup script for individual service containers
# This script handles the startup sequence within each container

set -e

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

# Wait for SPIRE agent socket to be available
wait_for_spire_agent() {
    local socket_path="/tmp/spire-agent/public/api.sock"
    local max_wait=60
    local wait_time=0
    
    log_info "Waiting for SPIRE agent socket..."
    
    while [ $wait_time -lt $max_wait ]; do
        if [ -S "$socket_path" ]; then
            log_success "SPIRE agent socket is ready"
            return 0
        fi
        
        sleep 2
        wait_time=$((wait_time + 2))
    done
    
    log_error "SPIRE agent socket not available after ${max_wait}s"
    return 1
}

# Wait for Envoy to be ready
wait_for_envoy() {
    local admin_port="${1:-9901}"
    local max_wait=30
    local wait_time=0
    
    log_info "Waiting for Envoy admin interface on port $admin_port..."
    
    while [ $wait_time -lt $max_wait ]; do
        if curl -s -f "http://localhost:$admin_port/ready" >/dev/null 2>&1; then
            log_success "Envoy is ready"
            return 0
        fi
        
        sleep 2
        wait_time=$((wait_time + 2))
    done
    
    log_warning "Envoy may not be fully ready (timeout after ${max_wait}s)"
    return 1
}

# Health check function
health_check() {
    local service_port="${1:-8080}"
    local health_endpoint="${2:-/health}"
    
    if curl -s -f "http://localhost:$service_port$health_endpoint" >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Main startup function
main() {
    log_info "Starting service initialization..."
    
    # Wait for dependencies
    if ! wait_for_spire_agent; then
        log_error "SPIRE agent startup failed"
        exit 1
    fi
    
    if ! wait_for_envoy; then
        log_warning "Envoy startup check failed, continuing anyway"
    fi
    
    log_success "Service initialization completed"
}

# Execute main function if script is run directly
if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    main "$@"
fi
