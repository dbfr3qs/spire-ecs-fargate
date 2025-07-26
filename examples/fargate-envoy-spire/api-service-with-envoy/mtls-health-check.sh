#!/bin/bash
set -e

# mTLS Health Check Script for API Service
# Uses SPIRE Workload API to retrieve client certificates and perform mTLS request

SPIRE_AGENT_SOCKET="/tmp/spire-agent/public/api.sock"
API_ENDPOINT="https://localhost:8080/health"
TEMP_DIR="/tmp/health-check-certs"

# Create temporary directory for certificates
mkdir -p "$TEMP_DIR"

# Function to cleanup certificates
cleanup() {
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

# Check if SPIRE agent socket exists
if [ ! -S "$SPIRE_AGENT_SOCKET" ]; then
    echo "ERROR: SPIRE agent socket not found at $SPIRE_AGENT_SOCKET"
    exit 1
fi

# Use spire-agent api fetch to get X.509 certificates
echo "Fetching X.509 certificates from SPIRE agent..."

# Fetch X.509 bundle and SVIDs
if ! /usr/local/bin/spire-agent api fetch x509 -socketPath "$SPIRE_AGENT_SOCKET" -write "$TEMP_DIR" > /dev/null 2>&1; then
    echo "ERROR: Failed to fetch certificates from SPIRE agent"
    exit 1
fi

# Verify certificates were written (SPIRE agent creates numbered files)
if [ ! -f "$TEMP_DIR/svid.0.pem" ] || [ ! -f "$TEMP_DIR/svid.0.key" ] || [ ! -f "$TEMP_DIR/bundle.0.pem" ]; then
    echo "ERROR: Expected certificate files not found in $TEMP_DIR"
    ls -la "$TEMP_DIR" || true
    exit 1
fi

echo "Successfully retrieved certificates from SPIRE"
echo "Client certificate: $TEMP_DIR/svid.0.pem"
echo "Client key: $TEMP_DIR/svid.0.key" 
echo "CA bundle: $TEMP_DIR/bundle.0.pem"

# Perform mTLS health check request
echo "Performing mTLS health check to $API_ENDPOINT..."

if curl -s -f \
    --cert "$TEMP_DIR/svid.0.pem" \
    --key "$TEMP_DIR/svid.0.key" \
    --cacert "$TEMP_DIR/bundle.0.pem" \
    --insecure \
    --connect-timeout 5 \
    --max-time 10 \
    "$API_ENDPOINT" > /dev/null; then
    echo "mTLS health check PASSED"
    exit 0
else
    echo "ERROR: mTLS health check FAILED"
    exit 1
fi
