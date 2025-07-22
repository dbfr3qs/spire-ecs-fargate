# SPIRE ECS Fargate Mock Environment

This comprehensive example demonstrates a complete SPIRE-based zero-trust security architecture for ECS Fargate environments, showcasing:

🔐 **Identity-Based Security**: Automatic workload identity attestation using SPIRE
🛡️ **mTLS Communication**: Secure service-to-service communication with certificate rotation
🚀 **Production-Ready Automation**: Automated trust bundle generation and deployment
🏗️ **ECS Fargate Integration**: Custom plugins for AWS ECS Fargate attestation

## What This Example Demonstrates

### Core SPIRE Capabilities
- **Workload Identity Attestation**: Automatic identity provisioning for containerized workloads
- **X.509-SVID Certificate Management**: Automatic certificate issuance and rotation
- **JWT-SVID Token Generation**: Secure token-based authentication
- **Trust Bundle Management**: Automated certificate authority chain distribution
- **ECS Fargate Integration**: Custom attestation plugins for AWS ECS environment

### Security Features
- **mTLS Client-Server Communication**: Secure service-to-service communication
- **Certificate Rotation**: Automatic certificate renewal every 30 seconds
- **Trust Bundle Bootstrap**: Automated trust bundle deployment without circular dependencies
- **SPIFFE ID Validation**: Proper identity verification in mTLS handshakes
- **Fallback Mechanisms**: Graceful degradation when mTLS setup fails

### Production Patterns
- **Multi-Service Architecture**: Web app, API service, and CLI client examples
- **Container Orchestration**: Docker Compose with proper service dependencies
- **Monitoring & Logging**: Comprehensive logging for troubleshooting
- **Documentation**: Production-ready deployment guides

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│ ECS Fargate Mock Environment (Docker Compose)                                  │
│                                                                                 │
│  ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────────────────┐ │
│  │   Web App       │    │   API Service   │    │   CLI Client                │ │
│  │   (8080)        │    │   (8082)        │    │                             │ │
│  │                 │    │                 │    │                             │ │
│  │ • SPIRE Agent   │    │ • SPIRE Agent   │    │ • SPIRE Agent               │ │
│  │ • X.509 SVID    │◄──►│ • mTLS Server   │    │ • mTLS Client               │ │
│  │ • mTLS Client   │    │ • JSON API      │    │ • Command Line Interface    │ │
│  │ • Web Interface │    │ • CORS Support  │    │ • Attestation Queries       │ │
│  └─────────────────┘    └─────────────────┘    └─────────────────────────────┘ │
│           │                       │                          │                 │
│           │ Workload API (Unix Socket)                       │                 │
│           │                       │                          │                 │
│           │                       │                          │                 │
│           │         ┌─────────────┼──────────────────────────┼───────────┐     │
│           │         │             │                          │           │     │
│           │         │ ECS Metadata Requests (HTTP 8090)     │           │     │
│           │         │             │                          │           │     │
└───────────┼─────────┼─────────────┼──────────────────────────┼───────────┼─────┘
            │         │             │                          │           │
            │         │        gRPC (8081)                     │           │
            │         │             │                          │           │
            └─────────┼─────────────┼──────────────────────────┘           │
                      │             ▼                                      │
┌─────────────────────┼─────────────────────────────────────────────────────┼─────┐
│ SPIRE Server        │                                                     │     │
│ • Identity Management & CA Operations                                      │     │
│ • Custom ECS Fargate Attestation Plugin ◄──────────────────────────────────┘     │
│ • Registration Entry Management                                                   │
│ • Trust Bundle Generation (2478 bytes, 42 lines)                                │
└─────────────────────────────────────────────────────────────────────────────────┘
            ▲                                     ▲
            │                                     │
            │ PostgreSQL (5432)                   │ HTTP (8090)
            │                                     │
┌─────────────────────────────────┐    ┌─────────────────────────────────────────┐
│ PostgreSQL Database             │    │ Mock ECS Metadata Endpoint              │
│ • SPIRE Server Data Store      │    │ • Simulates AWS ECS Task Metadata v4   │
│ • Registration Entries         │    │ • Provides ECS attestation data        │
│ • Node Attestation Records     │    │ • Returns realistic task metadata      │
└─────────────────────────────────┘    └─────────────────────────────────────────┘
```

## Service Components

### 1. Web Application (`app-with-agent`)
- **Port**: 8080
- **Purpose**: Interactive web interface for SPIRE credential display and mTLS testing
- **Features**:
  - Real-time SPIRE credential display (X.509 SVID, JWT SVID, Trust Bundle)
  - mTLS API call testing with visual feedback
  - ECS metadata visualization
  - Certificate expiration tracking
  - Beautiful responsive web interface

### 2. API Service (`api-service-with-agent`)
- **Port**: 8082
- **Purpose**: JSON API service with mTLS server capabilities
- **Features**:
  - RESTful JSON API endpoints (/attestation, /health)
  - mTLS server with client certificate validation
  - CORS support for web application integration
  - Comprehensive attestation data in JSON format
  - Automatic certificate rotation

### 3. CLI Client (`cli-client-with-agent`)
- **Purpose**: Command-line interface for SPIRE operations and testing
- **Features**:
  - Self-identity queries (`-self`)
  - API service queries (`-query`)
  - JSON output formatting (`-json`)
  - mTLS client with custom DialTLS implementation
  - HTTP fallback mechanisms

### 4. SPIRE Server
- **Port**: 8081
- **Purpose**: Central identity authority and certificate management
- **Features**:
  - Custom ECS Fargate attestation plugin
  - X.509 and JWT SVID issuance
  - Trust bundle generation and management
  - Registration entry management
  - PostgreSQL backend storage

### 5. Mock ECS Metadata Endpoint
- **Port**: 8090
- **Purpose**: Simulates AWS ECS Task Metadata Endpoint v4
- **Features**:
  - Realistic ECS task and container metadata
  - Support for custom attestation plugins
  - ECS-specific selector generation
  - Task ARN and cluster information

### 6. PostgreSQL Database
- **Purpose**: SPIRE Server data persistence
- **Features**:
  - Registration entry storage
  - Node attestation records
  - Optimized for SPIRE concurrent operations
## Quick Start (Automated)

### 🚀 One-Command Deployment

```bash
cd examples/fargate-spire-mock
./build-with-trust-bundle.sh
```

**That's it!** The automated build script will:
- ✅ Generate fresh trust bundle
- ✅ Build all containers with trust bundle integration
- ✅ Start services in correct dependency order
- ✅ Verify service readiness
- ✅ Display service endpoints and status

### 🌐 Service Endpoints

After successful deployment, access these endpoints:
- **Web Application**: http://localhost:8080
- **API Service**: http://localhost:8082
- **SPIRE Server**: http://localhost:8081
- **ECS Metadata Mock**: http://localhost:8090

### 🔧 Build Options

```bash
# Clean build (force fresh trust bundle generation)
./build-with-trust-bundle.sh --clean-build

# Build only (don't start services)
./build-with-trust-bundle.sh --no-start

# Show help
./build-with-trust-bundle.sh --help
```

## Testing the Examples

### 1. Web Application Testing

**Interactive Web Interface**: http://localhost:8080

**What you'll see**:
- 🔑 **X.509 SVID Certificate**: Live certificate details with expiration tracking
- 🎫 **JWT SVID**: Token-based authentication credentials
- 🏛️ **Trust Bundle**: CA certificate chain information
- 🚢 **ECS Metadata**: Simulated AWS ECS task metadata
- 🔗 **mTLS Test Button**: Interactive mTLS communication testing

**Testing mTLS Communication**:
1. Click the "🔗 Call API Service (mTLS)" button
2. Observe the real-time mTLS connection logs
3. View the secure API response with SPIFFE ID validation
4. Certificate rotation happens automatically every 30 seconds

**JSON API Access**:
```bash
# Get comprehensive attestation data
curl http://localhost:8080/json

# Response includes:
# - attestation_status: "SUCCESS"
# - spiffe_id: "spiffe://example.org/demo-app"
# - certificate details and trust bundle
# - ECS metadata and selectors
```

### 2. API Service Testing

**RESTful JSON API**: http://localhost:8082

**Available Endpoints**:
```bash
# Get complete attestation data
curl http://localhost:8082/attestation

# Health check
curl http://localhost:8082/health

# Test mTLS server capabilities
curl -k https://localhost:8082/attestation
```

**Example Response**:
```json
{
  "attestation_status": "SUCCESS",
  "spiffe_id": "spiffe://example.org/api-service",
  "x509_svid": {
    "subject": "O=SPIRE,C=US",
    "issuer": "CN=SPIRE Server CA,O=SPIFFE,C=US",
    "serial_number": "12345...",
    "not_before": "2025-07-18T06:00:00Z",
    "not_after": "2025-07-18T06:30:00Z"
  },
  "trust_bundle": {
    "certificates": 1,
    "size_bytes": 826
  },
  "ecs_metadata": {
    "cluster": "test-cluster",
    "task_arn": "arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123def456",
    "service": "demo-service"
  }
}
```

### 3. CLI Client Testing

**Command-Line Interface**: Execute commands in the CLI client container

**Self-Identity Query**:
```bash
docker exec fargate-spire-mock-cli-client-with-agent-1 /usr/local/bin/spire-cli -self
```

**Expected Output**:
```
📍 SPIFFE ID: spiffe://example.org/cli-client
🔒 Attestation Status: SUCCESS
📜 Certificate Subject: O=SPIRE,C=US
⏰ Valid Until: 2025-07-18T06:30:00Z
```

**API Service Query**:
```bash
docker exec fargate-spire-mock-cli-client-with-agent-1 /usr/local/bin/spire-cli -query
```

**Expected Output**:
```
📡 API Service Response (Status: SUCCESS)
📍 SPIFFE ID: spiffe://example.org/api-service
🔒 Attestation Status: SUCCESS
📜 Certificate Subject: O=SPIRE,C=US
⏰ Valid Until: 2025-07-18T06:30:00Z
```

**Combined Query with JSON Output**:
```bash
docker exec fargate-spire-mock-cli-client-with-agent-1 /usr/local/bin/spire-cli -self -query -json
```

**CLI Features**:
- 🔍 **Self-Identity**: Query own SPIRE identity and certificates
- 🌐 **API Queries**: Test mTLS communication with API service
- 📊 **JSON Output**: Structured data for automation
- 🔄 **Fallback**: Automatic fallback to HTTP if mTLS fails
- 🛡️ **Certificate Validation**: Custom DialTLS with SPIFFE ID validation

### 4. Advanced Testing

**Certificate Rotation Monitoring**:
```bash
# Watch certificate rotation in real-time
docker logs fargate-spire-mock-fargate-app-1 -f | grep "mTLS client refreshed"
```

**mTLS Communication Verification**:
```bash
# Monitor mTLS handshakes
docker logs fargate-spire-mock-fargate-app-1 -f | grep "TLS handshake successful"
```

**Trust Bundle Validation**:
```bash
# Check trust bundle integrity
cat trust-bundle/trust-bundle.pem | openssl x509 -text -noout
```

**SPIRE Agent Status**:
```bash
# Check agent health
docker exec fargate-spire-mock-fargate-app-1 /usr/local/bin/spire-agent api fetch x509 -socketPath /tmp/spire-agent/public/api.sock
```

**Registration Entries**:
```bash
# List all workload registrations
docker exec fargate-spire-mock-spire-server-1 /opt/spire/bin/spire-server entry show
```

## Automated Trust Bundle System

### 🔄 Problem Solved

The automated system eliminates the circular dependency where:
- SPIRE agents need trust bundles to start
- Trust bundles can only be extracted from running SPIRE server
- `docker compose up --build` would fail with "certificate has expired" errors

### 🛠️ How It Works

1. **Trust Bundle Generation** (`generate-trust-bundle.sh`):
   - Uses existing valid trust bundle if available
   - Extracts from running SPIRE server if present
   - Starts temporary SPIRE server to generate fresh bundle
   - Validates bundle integrity (size, format, PEM structure)

2. **Build Orchestration** (`build-with-trust-bundle.sh`):
   - Generates/validates trust bundle before building
   - Distributes trust bundle to each service directory
   - Builds all containers with trust bundle integration
   - Starts services in correct dependency order
   - Cleans up temporary trust bundle copies

3. **Container Integration**:
   - Each agent container copies trust bundle during build
   - Trust bundle available at `/opt/spire/trust-bundle/trust-bundle.pem`
   - Agent configurations use `trust_bundle_path` for secure bootstrap

### 🔧 Manual Trust Bundle Operations

**Extract Current Trust Bundle**:
```bash
# Extract from running server
./extract-trust-bundle.sh

# Verify trust bundle
ls -la trust-bundle/trust-bundle.pem
cat trust-bundle/trust-bundle.pem | head -5
```

**Force Trust Bundle Regeneration**:
```bash
# Remove existing bundle and regenerate
rm -f trust-bundle/trust-bundle.pem
./generate-trust-bundle.sh
```

**Manual Build Process**:
```bash
# Generate trust bundle first
./generate-trust-bundle.sh

# Then use standard docker compose
docker compose up --build
```

## Development and Debugging

### 🔍 Monitoring Commands

**Service Status**:
```bash
# Check all services
docker compose ps

# View service logs
docker compose logs -f

# Specific service logs
docker compose logs -f spire-server
docker compose logs -f fargate-app
docker compose logs -f api-service-with-agent
```

**SPIRE Operations**:
```bash
# View registration entries
docker exec fargate-spire-mock-spire-server-1 /opt/spire/bin/spire-server entry show

# Check agent attestation
docker exec fargate-spire-mock-fargate-app-1 /usr/local/bin/spire-agent api fetch x509 -socketPath /tmp/spire-agent/public/api.sock

# Test ECS metadata endpoint
curl http://localhost:8090/v4/metadata
```

### 🐛 Troubleshooting

**Trust Bundle Issues**:
```bash
# Check trust bundle status
ls -la trust-bundle/trust-bundle.pem
wc -c trust-bundle/trust-bundle.pem  # Should be ~826 bytes

# Force regeneration
./build-with-trust-bundle.sh --clean-build
```

**mTLS Communication Issues**:
```bash
# Check certificate rotation
docker logs fargate-spire-mock-fargate-app-1 | grep "mTLS client refreshed"

# Verify TLS handshakes
docker logs fargate-spire-mock-fargate-app-1 | grep "TLS handshake successful"

# Test API service mTLS
curl -k https://localhost:8082/health
```

**Agent Connection Issues**:
```bash
# Check agent reattestations
docker logs fargate-spire-mock-fargate-app-1 | grep "Successfully reattested"

# Check socket permissions
docker exec fargate-spire-mock-fargate-app-1 ls -la /tmp/spire-agent/public/
```

## Architecture Details

### 🔐 Security Model

**Identity Attestation**:
- **Node Attestation**: Custom ECS Fargate plugin validates task identity
- **Workload Attestation**: Unix selectors (uid:0) for container processes
- **Trust Bootstrap**: Automated trust bundle deployment
- **Certificate Rotation**: Automatic 30-second certificate renewal

**mTLS Implementation**:
- **Custom DialTLS**: Bypasses hostname validation for SPIFFE certificates
- **SPIFFE ID Validation**: Validates peer identity in certificate callbacks
- **Trust Bundle**: Validates server certificates using SPIRE trust bundle
- **Fallback Mechanisms**: Graceful degradation to HTTP when mTLS fails

### 🏗️ Production Readiness

**Deployment Automation**:
- One-command deployment with `./build-with-trust-bundle.sh`
- Automated trust bundle generation and distribution
- Container orchestration with proper dependencies
- Service readiness checks and health monitoring

**Monitoring & Observability**:
- Comprehensive logging for all services
- Real-time certificate rotation monitoring
- mTLS handshake success/failure tracking
- Service endpoint health checks

**Documentation**:
- Complete usage guides and testing procedures
- Troubleshooting guides with common issues
- Production deployment considerations
- Security best practices

## Real-World Considerations

### 🌩️ AWS ECS Fargate Deployment

In a real AWS ECS Fargate environment:

1. **Replace Mock Components**:
   - Use real ECS Task Metadata Endpoint v4
   - Replace mock metadata with actual ECS metadata
   - Use AWS IAM roles for additional security

2. **Network Configuration**:
   - Configure VPC and security groups
   - Use AWS Load Balancer for external access
   - Set up private subnets for internal communication

3. **Storage and Persistence**:
   - Use Amazon RDS for SPIRE server database
   - Configure EFS for shared storage if needed
   - Set up proper backup and recovery

4. **Monitoring**:
   - Integrate with AWS CloudWatch
   - Set up CloudTrail for audit logging
   - Use AWS X-Ray for distributed tracing

### 🔒 Security Considerations

**Production Security**:
- Implement proper RBAC for SPIRE server access
- Use AWS Secrets Manager for sensitive configuration
- Enable encryption in transit and at rest
- Regular security audits and vulnerability scanning

**Certificate Management**:
- Monitor certificate expiration
- Implement certificate rotation policies
- Set up alerts for attestation failures
- Regular trust bundle updates

## Files and Components

### 📁 Directory Structure

```
fargate-spire-mock/
├── build-with-trust-bundle.sh    # Automated build orchestration
├── generate-trust-bundle.sh       # Trust bundle generation
├── extract-trust-bundle.sh        # Manual trust bundle extraction
├── docker-compose.yml             # Service orchestration
├── trust-bundle/                  # Generated trust bundle files
├── spire-server/                  # SPIRE server configuration
├── app-with-agent/                # Web application with SPIRE agent
├── api-service-with-agent/        # API service with SPIRE agent
├── cli-client-with-agent/         # CLI client with SPIRE agent
├── mock-metadata/                 # ECS metadata endpoint simulation
├── awsecsfargate/                 # Custom ECS Fargate plugins
└── TRUST_BUNDLE_README.md         # Detailed automation documentation
```

### 🔧 Key Files

**Automation Scripts**:
- `build-with-trust-bundle.sh`: Complete automation with options
- `generate-trust-bundle.sh`: Multi-strategy trust bundle generation
- `extract-trust-bundle.sh`: Manual trust bundle extraction

**Configuration Files**:
- `docker-compose.yml`: Service definitions and dependencies
- `*/agent.conf`: SPIRE agent configurations with trust bundle paths
- `spire-server/server.conf`: SPIRE server with custom plugins

**Trust Bundle Files**:
- `trust-bundle/trust-bundle.pem`: Generated trust bundle (826 bytes)
- `*/trust-bundle.pem`: Service-specific trust bundle copies (build-time)

## Contributing

To extend this example:

1. **Add New Services**: Create additional containers with SPIRE agents
2. **Implement New Attestation**: Add custom attestation plugins
3. **Enhance Security**: Add additional security layers and monitoring
4. **Service Mesh Integration**: Integrate with Istio, Linkerd, or Consul Connect
5. **Automated Testing**: Add comprehensive test suites and CI/CD integration

## Support

For issues and questions:
- Check the troubleshooting section above
- Review service logs with `docker compose logs -f`
- Consult the comprehensive `TRUST_BUNDLE_README.md`
- Test with the automated build script: `./build-with-trust-bundle.sh --clean-build`

This example provides a complete foundation for implementing SPIRE-based zero-trust security in containerized environments and can be adapted for various production scenarios.
