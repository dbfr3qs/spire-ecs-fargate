#!/bin/bash

echo "Starting SPIRE CLI Client with Agent..."

# Start SPIRE Agent with trust bundle configuration
echo "Starting SPIRE Agent with trust bundle configuration..."
echo "Agent config: /opt/spire/conf/agent/agent.conf"
echo "Trust bundle: /opt/spire/trust-bundle/trust-bundle.pem"

# Verify trust bundle exists
if [ ! -f "/opt/spire/trust-bundle/trust-bundle.pem" ]; then
    echo "❌ Warning: Trust bundle not found at /opt/spire/trust-bundle/trust-bundle.pem"
    echo "Agent may fail to start - trust bundle is required for secure bootstrap"
else
    echo "✅ Trust bundle found, starting agent..."
fi

/usr/local/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf &
AGENT_PID=$!

# Wait for agent to be ready
echo "Waiting for SPIRE Agent to initialize..."
sleep 10

# Function to handle shutdown
shutdown() {
    echo "Shutting down..."
    kill $AGENT_PID 2>/dev/null || true
    exit 0
}

# Set up signal handling
trap shutdown SIGTERM SIGINT

echo "SPIRE CLI Client Setup Complete!"
echo ""
echo "🚀 CLI Client Commands Available:"
echo ""
echo "  Show own identity:"
echo "    docker exec <container-name> /usr/local/bin/spire-cli -self"
echo ""
echo "  Query API service:"
echo "    docker exec <container-name> /usr/local/bin/spire-cli -query"
echo ""
echo "  Show both (own + API service):"
echo "    docker exec <container-name> /usr/local/bin/spire-cli -self -query"
echo ""
echo "  JSON output:"
echo "    docker exec <container-name> /usr/local/bin/spire-cli -self -json"
echo ""
echo "  Help:"
echo "    docker exec <container-name> /usr/local/bin/spire-cli -help"
echo ""
echo "📋 To complete SPIRE setup:"
echo "1. Get SPIRE server container: docker ps | grep spire-server"
echo "2. Register CLI workload: docker exec <spire-server-container> /opt/spire/bin/spire-server entry create -parentID spiffe://example.org/aws_fargate_task/123456789012/test-cluster -spiffeID spiffe://example.org/cli-client -selector unix:uid:0"
echo ""

# Keep the container running
while true; do
    # Check if agent is still running
    if ! kill -0 $AGENT_PID 2>/dev/null; then
        echo "SPIRE Agent has stopped unexpectedly"
        break
    fi
    
    sleep 30
done

echo "Main process exiting"
shutdown
