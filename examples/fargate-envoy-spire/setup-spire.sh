#!/bin/bash

# SPIRE Registration Setup for Envoy-SPIRE Integration Example
# This script creates all necessary SPIRE registration entries for the service mesh

set -e

echo "🔐 Setting up SPIRE registration entries for Envoy integration..."

SPIRE_SERVER_CONTAINER="fargate-envoy-spire-spire-server-1"

# Function to create registration entry with retry logic
create_entry() {
    local parent_id="$1"
    local spiffe_id="$2"
    local selector="$3"
    local description="$4"
    
    echo "Creating entry: $description"
    echo "  Parent ID: $parent_id"
    echo "  SPIFFE ID: $spiffe_id"
    echo "  Selector: $selector"
    
    for attempt in 1 2 3; do
        if docker exec "$SPIRE_SERVER_CONTAINER" \
            /opt/spire/bin/spire-server entry create \
            -parentID "$parent_id" \
            -spiffeID "$spiffe_id" \
            -selector "$selector"; then
            echo "✅ Successfully created: $description"
            return 0
        else
            echo "⚠️  Attempt $attempt failed for: $description"
            if [ $attempt -eq 3 ]; then
                echo "❌ Failed to create entry after 3 attempts: $description"
                return 1
            fi
            sleep 2
        fi
    done
}

# Wait for SPIRE server to be ready
echo "Waiting for SPIRE server to be ready..."
sleep 10

echo "🎯 Creating workload registration entries..."

# The parent ID for all workloads (ECS Fargate attested node)
PARENT_ID="spiffe://example.org/aws_fargate_task/123456789012/test-cluster"

# Create registration entries for each service
# These will be used by both the applications and their Envoy sidecars

# 1. Web Application (demo-app)
create_entry \
    "$PARENT_ID" \
    "spiffe://example.org/demo-app" \
    "unix:uid:0" \
    "Web Application (demo-app)"

# 2. API Service 
create_entry \
    "$PARENT_ID" \
    "spiffe://example.org/api-service" \
    "unix:uid:0" \
    "API Service"

# 3. CLI Client
create_entry \
    "$PARENT_ID" \
    "spiffe://example.org/cli-client" \
    "unix:uid:0" \
    "CLI Client"

echo ""
echo "📋 Listing all registration entries:"
docker exec "$SPIRE_SERVER_CONTAINER" \
    /opt/spire/bin/spire-server entry show

echo ""
echo "🎉 SPIRE registration setup complete!"
echo ""
echo "📍 Service Identities:"
echo "  • Web App:    spiffe://example.org/demo-app"
echo "  • API Service: spiffe://example.org/api-service" 
echo "  • CLI Client:  spiffe://example.org/cli-client"
echo ""
echo "🔗 Parent ID (ECS Fargate Node):"
echo "  • $PARENT_ID"
echo ""
echo "💡 Each service now has a unique SPIFFE identity that will be used by"
echo "   both the application and its Envoy sidecar for mTLS communication."
