#!/bin/bash

echo "Starting SPIRE Agent and Web Application..."

# Start the web application first (it can handle SPIRE being unavailable)
echo "Starting web application..."
/usr/local/bin/web-app &
APP_PID=$!

echo "Web application started on port 8080"

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
echo "Web application available at: http://localhost:8080"
echo "ECS metadata mock available at: http://localhost:8090/v4/metadata"
echo ""
echo "To complete SPIRE setup:"
echo "1. Get SPIRE server container: docker ps | grep spire-server"
echo "2. Generate join token: docker exec <container-id> /opt/spire/bin/spire-server token generate -spiffeID spiffe://example.org/fargate-task"
echo "3. Get this container ID: docker ps | grep fargate-app"
echo "4. Start agent: docker exec <container-id> /usr/local/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf -joinToken <token> &"
echo "5. Register workload: docker exec <spire-server-container> /opt/spire/bin/spire-server entry create -parentID spiffe://example.org/fargate-task -spiffeID spiffe://example.org/demo-app -selector unix:uid:0"

# Keep the main process running
while true; do
    # Check if web app is still running
    if ! kill -0 $APP_PID 2>/dev/null; then
        echo "Web application stopped, restarting..."
        /usr/local/bin/web-app &
        APP_PID=$!
    fi
    sleep 10
done
