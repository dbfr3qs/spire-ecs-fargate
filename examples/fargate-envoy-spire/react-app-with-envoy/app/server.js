const express = require('express');
const cors = require('cors');
const path = require('path');
const { exec } = require('child_process');
const fs = require('fs');
const https = require('https');
const http = require('http');

const app = express();
const PORT = process.env.PORT || 8081;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'frontend/build')));

// SPIRE agent socket path
const SPIRE_SOCKET = '/tmp/spire-agent/public/api.sock';

/**
 * Get SPIRE identity information by calling spire-agent CLI
 */
async function getSPIREInfo() {
    return new Promise((resolve) => {
        // Check if SPIRE agent socket exists
        if (!fs.existsSync(SPIRE_SOCKET)) {
            resolve({
                spiffe_id: '',
                attestation_status: 'FAILED',
                error: 'SPIRE agent socket not found'
            });
            return;
        }

        // Get X509 SVID information
        exec(`/usr/local/bin/spire-agent api fetch x509 -socketPath ${SPIRE_SOCKET}`, (error, stdout, stderr) => {
            if (error) {
                console.error('Failed to fetch SPIRE certificates:', error);
                resolve({
                    spiffe_id: '',
                    attestation_status: 'FAILED',
                    error: `Failed to fetch certificates: ${error.message}`
                });
                return;
            }

            try {
                // Parse spire-agent output to extract SPIFFE ID and certificate info
                const lines = stdout.split('\n');
                let spiffeId = '';
                let validAfter = '';
                let validUntil = '';
                
                // Look specifically for the react-demo-app identity
                for (const line of lines) {
                    if (line.includes('SPIFFE ID:') && line.includes('react-demo-app')) {
                        spiffeId = line.split('SPIFFE ID:')[1].trim();
                        break; // Get our specific react-demo-app identity
                    }
                }
                
                // Fallback to first SPIFFE ID if react-demo-app not found
                if (!spiffeId) {
                    for (const line of lines) {
                        if (line.includes('SPIFFE ID:')) {
                            spiffeId = line.split('SPIFFE ID:')[1].trim();
                            break;
                        }
                    }
                }
                
                for (const line of lines) {
                    if (line.includes('SVID Valid After:')) {
                        validAfter = line.split('SVID Valid After:')[1].trim();
                    }
                    if (line.includes('SVID Valid Until:')) {
                        validUntil = line.split('SVID Valid Until:')[1].trim();
                        break; // We have both dates, exit loop
                    }
                }

                resolve({
                    spiffe_id: spiffeId,
                    attestation_status: 'SUCCESS',
                    x509_svid_parsed: {
                        subject: 'O=SPIRE,C=US',
                        issuer: 'SPIRE Server CA - Envoy Example',
                        not_before: validAfter,
                        not_after: validUntil,
                        uris: [spiffeId]
                    }
                });
            } catch (parseError) {
                console.error('Failed to parse SPIRE output:', parseError);
                resolve({
                    spiffe_id: '',
                    attestation_status: 'FAILED',
                    error: `Failed to parse SPIRE output: ${parseError.message}`
                });
            }
        });
    });
}

/**
 * Get ECS metadata from the mock service
 */
async function getECSMetadata() {
    return new Promise((resolve) => {
        const req = http.get('http://ecs-metadata-mock:8090/v4/metadata', (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                try {
                    resolve(JSON.parse(data));
                } catch (error) {
                    console.error('Failed to parse ECS metadata:', error);
                    resolve(null);
                }
            });
        });
        
        req.on('error', (error) => {
            console.error('Failed to fetch ECS metadata:', error);
            resolve(null);
        });
        
        req.setTimeout(5000, () => {
            req.destroy();
            resolve(null);
        });
    });
}

/**
 * Call API service through Envoy proxy (routes through local Envoy for mTLS)
 */
async function callAPIServiceViaEnvoy() {
    return new Promise((resolve) => {
        console.log('🚀 Calling API service through Envoy proxy...');
        
        // Call through local Envoy proxy which will handle mTLS to the API service
        // The Envoy proxy is configured to route /api-service/* to the API service with mTLS
        const req = http.get('http://localhost:8080/api-service/attestation', (res) => {
            let data = '';
            res.on('data', (chunk) => {
                data += chunk;
            });
            res.on('end', () => {
                try {
                    const response = JSON.parse(data);
                    console.log('✅ API service call successful');
                    resolve({
                        success: true,
                        response: response,
                        endpoint: 'http://localhost:8080/api-service/attestation',
                        transport: 'Plain HTTP to Envoy → mTLS → API Service'
                    });
                } catch (error) {
                    console.error('Failed to parse API response:', error);
                    resolve({
                        success: false,
                        error: `Failed to parse API response: ${error.message}`,
                        endpoint: 'http://api-service-with-agent:8080/attestation',
                        transport: 'Plain HTTP to Envoy → mTLS → API Service'
                    });
                }
            });
        });
        
        req.on('error', (error) => {
            console.error('Failed to call API service:', error);
                                    resolve({
                            success: false,
                            error: `Failed to call API service: ${error.message}`,
                            endpoint: 'http://localhost:8080/api-service/attestation',
                            transport: 'Plain HTTP to Envoy → mTLS → API Service'
                        });
        });
        
        req.setTimeout(10000, () => {
            req.destroy();
            resolve({
                success: false,
                error: 'Request timeout after 10 seconds',
                endpoint: 'http://localhost:8080/api-service/attestation',
                transport: 'Plain HTTP to Envoy → mTLS → API Service'
            });
        });
    });
}

// Routes

// Health check endpoint
app.get('/health', (req, res) => {
    res.status(200).send('OK');
});

// JSON API endpoint - returns SPIRE info as JSON
app.get('/json', async (req, res) => {
    try {
        const spireInfo = await getSPIREInfo();
        const ecsMetadata = await getECSMetadata();
        
        const responseData = {
            ...spireInfo,
            ecs_metadata: ecsMetadata
        };
        
        res.json(responseData);
    } catch (error) {
        console.error('Error in /json endpoint:', error);
        res.status(500).json({
            error: `Server error: ${error.message}`,
            attestation_status: 'FAILED'
        });
    }
});

// API call endpoint - calls the API service through Envoy
app.get('/api-call', async (req, res) => {
    try {
        console.log('📡 API call endpoint triggered');
        const result = await callAPIServiceViaEnvoy();
        res.json(result);
    } catch (error) {
        console.error('Error in /api-call endpoint:', error);
        res.status(500).json({
            success: false,
            error: `Server error: ${error.message}`,
            endpoint: 'http://localhost:8080/api-service/attestation',
            transport: 'Plain HTTP to Envoy → mTLS → API Service'
        });
    }
});

// API endpoint for React frontend to get initial data
app.get('/api/spire-info', async (req, res) => {
    try {
        const spireInfo = await getSPIREInfo();
        const ecsMetadata = await getECSMetadata();
        
        res.json({
            spire: spireInfo,
            ecs: ecsMetadata
        });
    } catch (error) {
        console.error('Error in /api/spire-info endpoint:', error);
        res.status(500).json({
            error: `Server error: ${error.message}`
        });
    }
});

// Serve React app for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend/build', 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log('🚀 Starting SPIRE Envoy Service Mesh Demo - React Application...');
    console.log('🌐 Architecture: React Frontend + Node.js Backend → Envoy Proxy → mTLS');
    console.log(`🌍 React application starting on port ${PORT}`);
    console.log('🔗 Available endpoints:');
    console.log(`  • http://localhost:${PORT}/ - React dashboard`);
    console.log(`  • http://localhost:${PORT}/json - JSON API (Go compatibility)`);
    console.log(`  • http://localhost:${PORT}/health - Health check`);
    console.log(`  • http://localhost:${PORT}/api-call - Test API service communication`);
    console.log(`  • http://localhost:${PORT}/api/spire-info - React API endpoint`);
    console.log('🔐 Security: mTLS authentication handled by Envoy sidecar');
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('🛑 Received SIGTERM, shutting down gracefully');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('🛑 Received SIGINT, shutting down gracefully');
    process.exit(0);
});
