#!/bin/bash

echo "🔧 SPIRE ECS Fargate Mock Setup Script"
echo "====================================="

# Get container IDs
echo "📋 Finding Docker containers..."
SPIRE_SERVER_ID=$(docker ps --filter "name=spire-server" --format "{{.ID}}" | head -1)
FARGATE_APP_ID=$(docker ps --filter "name=fargate-app" --format "{{.ID}}" | head -1)

if [ -z "$SPIRE_SERVER_ID" ]; then
    echo "❌ Error: SPIRE Server container not found. Make sure docker-compose is running."
    exit 1
fi

if [ -z "$FARGATE_APP_ID" ]; then
    echo "❌ Error: Fargate App container not found. Make sure docker-compose is running."
    exit 1
fi

echo "✅ SPIRE Server Container: $SPIRE_SERVER_ID"
echo "✅ Fargate App Container: $FARGATE_APP_ID"
echo ""

# Step 1: Generate join token
echo "🔑 Step 1: Generating join token..."
JOIN_TOKEN=$(docker exec $SPIRE_SERVER_ID /opt/spire/bin/spire-server token generate -spiffeID spiffe://example.org/fargate-task | grep "Token:" | awk '{print $2}')

if [ -z "$JOIN_TOKEN" ]; then
    echo "❌ Error: Failed to generate join token"
    exit 1
fi

echo "✅ Join token generated: $JOIN_TOKEN"
echo ""

# Step 2: Start SPIRE agent with join token
echo "🚀 Step 2: Starting SPIRE Agent with join token..."
docker exec -d $FARGATE_APP_ID /usr/local/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf -joinToken $JOIN_TOKEN

echo "✅ SPIRE Agent started"
echo ""

# Wait a moment for agent to start
echo "⏳ Waiting for SPIRE Agent to initialize..."
sleep 5

# Step 3: Register a workload
echo "📝 Step 3: Registering demo workload..."
docker exec $SPIRE_SERVER_ID /opt/spire/bin/spire-server entry create \
    -parentID spiffe://example.org/fargate-task \
    -spiffeID spiffe://example.org/demo-app \
    -selector unix:uid:0

echo "✅ Workload registered"
echo ""

# Step 4: Verify setup
echo "🔍 Step 4: Verifying setup..."
echo "Checking registered entries:"
docker exec $SPIRE_SERVER_ID /opt/spire/bin/spire-server entry show

echo ""
echo "🎉 Setup Complete!"
echo "==================="
echo "📱 Web Application: http://localhost:8080"
echo "🚢 ECS Metadata: http://localhost:8090/v4/metadata"
echo ""
echo "The web application should now show:"
echo "✅ Successful attestation status"
echo "🔐 X.509 SVID certificate details"
echo "🚢 ECS task metadata"
echo "🎯 Potential SPIRE selectors"
echo ""
echo "Refresh the web page to see the updated SPIRE credential information!"
