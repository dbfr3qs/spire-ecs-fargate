#!/bin/bash

echo "Starting SPIRE Agent and Attestation API Service..."

# Start the API service first (it can handle SPIRE being unavailable)
echo "Starting attestation API service..."
/usr/local/bin/attestation-api &
APP_PID=$!

echo "Attestation API service started on port 8080"

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

# Start SPIRE Agent in the background
/usr/local/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf &
AGENT_PID=$!

# Wait a moment for SPIRE Agent to initialize
echo "Waiting for SPIRE Agent to initialize..."
sleep 5

# Function to handle shutdown
shutdown() {
    echo "Shutting down..."
    kill $APP_PID 2>/dev/null || true
    kill $AGENT_PID 2>/dev/null || true
    exit 0
}

# Set up signal handling
trap shutdown SIGTERM SIGINT

echo "Setup complete!"
echo "Attestation API available at: http://localhost:8080/attestation"
echo "Health check available at: http://localhost:8080/health"
echo ""
echo "To complete SPIRE setup:"
echo "1. Get SPIRE server container: docker ps | grep spire-server"
echo "2. Generate join token: docker exec <container-id> /opt/spire/bin/spire-server token generate -spiffeID spiffe://example.org/api-service"
echo "3. Get this container ID: docker ps | grep api-service"
echo "4. Start agent: docker exec <container-id> /usr/local/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf -joinToken <token> &"
echo "5. Register workload: docker exec <spire-server-container> /opt/spire/bin/spire-server entry create -parentID spiffe://example.org/aws_fargate_task/123456789012/test-cluster -spiffeID spiffe://example.org/api-service -selector unix:uid:0"

# Keep the main process running
while true; do
    # Check if API service is still running
    if ! kill -0 $APP_PID 2>/dev/null; then
        echo "Attestation API service has stopped unexpectedly"
        break
    fi
    
    sleep 5
done

echo "Main process exiting"
shutdown
