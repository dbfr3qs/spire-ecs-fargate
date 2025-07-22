#!/bin/bash

echo "🔐 Extracting SPIRE Server Trust Bundle"
echo "======================================"

# Get SPIRE Server container ID
SPIRE_SERVER_ID=$(docker ps --filter "name=spire-server" --format "{{.ID}}" | head -1)

if [ -z "$SPIRE_SERVER_ID" ]; then
    echo "❌ Error: SPIRE Server container not found. Make sure docker-compose is running."
    exit 1
fi

echo "✅ SPIRE Server Container: $SPIRE_SERVER_ID"

# Create trust bundle directory if it doesn't exist
mkdir -p ./trust-bundle

# Extract trust bundle using spire-server bundle show command
echo "📤 Extracting trust bundle..."
docker exec $SPIRE_SERVER_ID /opt/spire/bin/spire-server bundle show -format pem > ./trust-bundle/trust-bundle.pem

if [ $? -eq 0 ] && [ -s ./trust-bundle/trust-bundle.pem ]; then
    echo "✅ Trust bundle extracted successfully to ./trust-bundle/trust-bundle.pem"
    echo "📊 Trust bundle size: $(wc -c < ./trust-bundle/trust-bundle.pem) bytes"
    echo ""
    echo "🔍 Trust bundle preview:"
    head -5 ./trust-bundle/trust-bundle.pem
    echo "..."
    tail -2 ./trust-bundle/trust-bundle.pem
else
    echo "❌ Error: Failed to extract trust bundle"
    exit 1
fi

echo ""
echo "✅ Trust bundle ready for agent configuration"
