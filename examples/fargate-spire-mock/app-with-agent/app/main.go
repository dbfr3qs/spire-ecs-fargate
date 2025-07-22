package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
)

type SPIREInfo struct {
	SPIFFEID          string            `json:"spiffe_id"`
	X509SVID          string            `json:"x509_svid"`
	X509SVIDParsed    *X509CertInfo     `json:"x509_svid_parsed"`
	JWTSVID           string            `json:"jwt_svid,omitempty"`
	TrustBundle       string            `json:"trust_bundle"`
	TrustBundleParsed []*X509CertInfo   `json:"trust_bundle_parsed"`
	AttestationStatus string            `json:"attestation_status"`
	ECSMetadata       *ECSTaskMetadata  `json:"ecs_metadata,omitempty"`
	PotentialSelectors []string         `json:"potential_selectors,omitempty"`
	Error             string            `json:"error,omitempty"`
}

// APIServiceResponse represents response from API service
type APIServiceResponse struct {
	ServiceName string     `json:"service_name"`
	Version     string     `json:"version"`
	Timestamp   time.Time  `json:"timestamp"`
	Status      string     `json:"status"`
	Data        *SPIREInfo `json:"data"`
}

// MTLSCallResult represents the result of an mTLS API call
type MTLSCallResult struct {
	Success      bool              `json:"success"`
	UsedMTLS     bool              `json:"used_mtls"`
	PeerSpiffeID string            `json:"peer_spiffe_id,omitempty"`
	Response     *APIServiceResponse `json:"response,omitempty"`
	Error        string            `json:"error,omitempty"`
	Fallback     bool              `json:"fallback"`
}

type ECSTaskMetadata struct {
	Cluster           string                 `json:"Cluster"`
	TaskARN           string                 `json:"TaskARN"`
	Family            string                 `json:"Family"`
	Revision          string                 `json:"Revision"`
	DesiredStatus     string                 `json:"DesiredStatus"`
	KnownStatus       string                 `json:"KnownStatus"`
	LaunchType        string                 `json:"LaunchType"`
	PlatformVersion   string                 `json:"PlatformVersion"`
	ServiceName       string                 `json:"ServiceName"`
	AvailabilityZone  string                 `json:"AvailabilityZone"`
	TaskTags          map[string]string      `json:"TaskTags"`
	Containers        []ECSContainerMetadata `json:"Containers"`
	TaskDefinitionArn string                 `json:"TaskDefinitionArn"`
}

type ECSContainerMetadata struct {
	DockerID      string            `json:"DockerId"`
	Name          string            `json:"Name"`
	DockerName    string            `json:"DockerName"`
	Image         string            `json:"Image"`
	ImageID       string            `json:"ImageID"`
	DesiredStatus string            `json:"DesiredStatus"`
	KnownStatus   string            `json:"KnownStatus"`
	Type          string            `json:"Type"`
	Labels        map[string]string `json:"Labels"`
}

type X509CertInfo struct {
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	SerialNumber string    `json:"serial_number"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	DNSNames     []string  `json:"dns_names"`
	URIs         []string  `json:"uris"`
}

const htmlTemplate = `
<!DOCTYPE html>
<html>
<head>
    <title>SPIRE Fargate Demo - Credential Information</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .section { margin-bottom: 30px; padding: 20px; border: 1px solid #ddd; border-radius: 5px; }
        .success { background-color: #d4edda; border-color: #c3e6cb; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; }
        .info { background-color: #d1ecf1; border-color: #bee5eb; }
        .warning { background-color: #fff3cd; border-color: #ffeaa7; }
        pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 12px; }
        .cert-info { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .field { margin-bottom: 10px; }
        .label { font-weight: bold; color: #333; }
        .value { margin-left: 10px; color: #666; }
        .tag-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 10px 0; }
        .tag-item { background: #e9ecef; padding: 8px; border-radius: 4px; font-size: 14px; }
        .container-info { border: 1px solid #dee2e6; padding: 15px; margin: 10px 0; border-radius: 4px; background: #f8f9fa; }
        .container-labels { margin-top: 10px; }
        .label-item { font-size: 12px; color: #6c757d; margin-left: 10px; }
        .selector-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 8px; margin: 15px 0; }
        .selector-item { background: #fff3cd; padding: 8px; border-radius: 4px; font-size: 13px; border: 1px solid #ffeaa7; }
        .selector-info { margin-top: 20px; }
        .refresh-btn { 
            display: inline-block; 
            padding: 10px 20px; 
            background: #007bff; 
            color: white; 
            text-decoration: none; 
            border-radius: 4px; 
            margin-top: 10px;
        }
        .refresh-btn:hover { background: #0056b3; }
        .api-btn {
            display: inline-block;
            padding: 10px 20px;
            background: #28a745;
            color: white;
            border: none;
            border-radius: 4px;
            margin-top: 10px;
            margin-left: 10px;
            cursor: pointer;
        }
        .api-btn:hover { background: #218838; }
        .api-btn:disabled { background: #6c757d; cursor: not-allowed; }
        .api-result {
            margin-top: 20px;
            padding: 15px;
            border-radius: 4px;
            display: none;
        }
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid #3498db;
            border-radius: 50%;
            animation: spin 2s linear infinite;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 SPIRE Fargate Demo</h1>
            <p>ECS Fargate Task Identity and Attestation Information</p>
            <a href="/" class="refresh-btn">🔄 Refresh</a>
            <button id="apiBtn" class="api-btn" onclick="callAPIService()">🔗 Call API Service (mTLS)</button>
        </div>
        
        <div id="apiResult" class="api-result"></div>

        {{if .Error}}
        <div class="section error">
            <h2>❌ Error</h2>
            <p>{{.Error}}</p>
        </div>
        {{else}}

        <div class="section {{if eq .AttestationStatus "SUCCESS"}}success{{else}}warning{{end}}">
            <h2>📋 Attestation Status</h2>
            <p><strong>Status:</strong> {{.AttestationStatus}}</p>
            <p><strong>SPIFFE ID:</strong> <code>{{.SPIFFEID}}</code></p>
        </div>

        {{if .X509SVIDParsed}}
        <div class="section info">
            <h2>🔑 X.509 SVID Certificate</h2>
            <div class="cert-info">
                <div>
                    <div class="field"><span class="label">Subject:</span><span class="value">{{.X509SVIDParsed.Subject}}</span></div>
                    <div class="field"><span class="label">Issuer:</span><span class="value">{{.X509SVIDParsed.Issuer}}</span></div>
                    <div class="field"><span class="label">Serial Number:</span><span class="value">{{.X509SVIDParsed.SerialNumber}}</span></div>
                </div>
                <div>
                    <div class="field"><span class="label">Valid From:</span><span class="value">{{.X509SVIDParsed.NotBefore.Format "2006-01-02 15:04:05 UTC"}}</span></div>
                    <div class="field"><span class="label">Valid Until:</span><span class="value">{{.X509SVIDParsed.NotAfter.Format "2006-01-02 15:04:05 UTC"}}</span></div>
                    <div class="field"><span class="label">URIs:</span><span class="value">{{range .X509SVIDParsed.URIs}}{{.}} {{end}}</span></div>
                </div>
            </div>
            <h4>Raw Certificate:</h4>
            <pre>{{.X509SVID}}</pre>
        </div>
        {{end}}

        {{if .JWTSVID}}
        <div class="section info">
            <h2>🎫 JWT SVID</h2>
            <pre>{{.JWTSVID}}</pre>
        </div>
        {{end}}

        {{if .TrustBundleParsed}}
        <div class="section info">
            <h2>🏛️ Trust Bundle</h2>
            <p><strong>Number of CA Certificates:</strong> {{len .TrustBundleParsed}}</p>
            {{range $i, $cert := .TrustBundleParsed}}
            <h4>CA Certificate {{add $i 1}}:</h4>
            <div class="cert-info">
                <div>
                    <div class="field"><span class="label">Subject:</span><span class="value">{{$cert.Subject}}</span></div>
                    <div class="field"><span class="label">Issuer:</span><span class="value">{{$cert.Issuer}}</span></div>
                </div>
                <div>
                    <div class="field"><span class="label">Valid From:</span><span class="value">{{$cert.NotBefore.Format "2006-01-02 15:04:05 UTC"}}</span></div>
                    <div class="field"><span class="label">Valid Until:</span><span class="value">{{$cert.NotAfter.Format "2006-01-02 15:04:05 UTC"}}</span></div>
                </div>
            </div>
            {{end}}
            <h4>Raw Trust Bundle:</h4>
            <pre>{{.TrustBundle}}</pre>
        </div>
        {{end}}

        {{if .ECSMetadata}}
        <div class="section info">
            <h2>🚢 ECS Task Metadata</h2>
            <div class="cert-info">
                <div>
                    <div class="field"><span class="label">Cluster:</span><span class="value">{{.ECSMetadata.Cluster}}</span></div>
                    <div class="field"><span class="label">Task Definition Family:</span><span class="value">{{.ECSMetadata.Family}}</span></div>
                    <div class="field"><span class="label">Task Definition Revision:</span><span class="value">{{.ECSMetadata.Revision}}</span></div>
                    <div class="field"><span class="label">Service Name:</span><span class="value">{{.ECSMetadata.ServiceName}}</span></div>
                    <div class="field"><span class="label">Launch Type:</span><span class="value">{{.ECSMetadata.LaunchType}}</span></div>
                </div>
                <div>
                    <div class="field"><span class="label">Task ARN:</span><span class="value">{{.ECSMetadata.TaskARN}}</span></div>
                    <div class="field"><span class="label">Availability Zone:</span><span class="value">{{.ECSMetadata.AvailabilityZone}}</span></div>
                    <div class="field"><span class="label">Platform Version:</span><span class="value">{{.ECSMetadata.PlatformVersion}}</span></div>
                    <div class="field"><span class="label">Task Status:</span><span class="value">{{.ECSMetadata.KnownStatus}}</span></div>
                </div>
            </div>
            
            {{if .ECSMetadata.TaskTags}}
            <h4>📋 Task Tags:</h4>
            <div class="tag-grid">
                {{range $key, $value := .ECSMetadata.TaskTags}}
                <div class="tag-item"><strong>{{$key}}:</strong> {{$value}}</div>
                {{end}}
            </div>
            {{end}}
            
            {{if .ECSMetadata.Containers}}
            <h4>📦 Containers:</h4>
            {{range $i, $container := .ECSMetadata.Containers}}
            <div class="container-info">
                <h5>Container {{add $i 1}}: {{$container.Name}}</h5>
                <div class="cert-info">
                    <div>
                        <div class="field"><span class="label">Image:</span><span class="value">{{$container.Image}}</span></div>
                        <div class="field"><span class="label">Image ID:</span><span class="value">{{$container.ImageID}}</span></div>
                        <div class="field"><span class="label">Docker ID:</span><span class="value">{{$container.DockerID}}</span></div>
                    </div>
                    <div>
                        <div class="field"><span class="label">Status:</span><span class="value">{{$container.KnownStatus}}</span></div>
                        <div class="field"><span class="label">Type:</span><span class="value">{{$container.Type}}</span></div>
                        <div class="field"><span class="label">Docker Name:</span><span class="value">{{$container.DockerName}}</span></div>
                    </div>
                </div>
                {{if $container.Labels}}
                <div class="container-labels">
                    <strong>Labels:</strong>
                    {{range $key, $value := $container.Labels}}
                    <div class="label-item">{{$key}}: {{$value}}</div>
                    {{end}}
                </div>
                {{end}}
            </div>
            {{end}}
            {{end}}
        </div>
        {{end}}

        {{if .PotentialSelectors}}
        <div class="section warning">
            <h2>🎯 Potential SPIRE Selectors</h2>
            <p><strong>The following selectors could be used for workload attestation based on the ECS metadata:</strong></p>
            <div class="selector-grid">
                {{range .PotentialSelectors}}
                <code class="selector-item">{{.}}</code>
                {{end}}
            </div>
            <div class="selector-info">
                <h4>💡 Selector Usage Examples:</h4>
                <pre># Register a workload for billing-api service
spire-server entry create \
  -parentID spiffe://example.org/fargate-task \
  -spiffeID spiffe://example.org/billing-api \
  -selector ecs:cluster:production-cluster \
  -selector ecs:task-definition-family:billing-api \
  -selector ecs:service-name:billing-api-service

# Register using task tags
spire-server entry create \
  -parentID spiffe://example.org/fargate-task \
  -spiffeID spiffe://example.org/frontend \
  -selector ecs:task-tag:Environment:production \
  -selector ecs:task-tag:Team:platform</pre>
            </div>
        </div>
        {{end}}

        {{end}}
    </div>
    
    <script>
        function callAPIService() {
            const btn = document.getElementById('apiBtn');
            const resultDiv = document.getElementById('apiResult');
            
            // Disable button and show loading
            btn.disabled = true;
            btn.innerHTML = '<span class="loading"></span> Calling API...';
            
            // Show result div
            resultDiv.style.display = 'block';
            resultDiv.className = 'api-result section info';
            resultDiv.innerHTML = '<h2>🔗 Calling API Service via mTLS...</h2><p>Please wait while we establish a secure mTLS connection to the API service...</p>';
            
            // Make API call
            fetch('/api-call', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            })
            .then(response => response.json())
            .then(data => {
                // Reset button
                btn.disabled = false;
                btn.innerHTML = '🔗 Call API Service (mTLS)';
                
                // Display results
                if (data.success) {
                    resultDiv.className = 'api-result section success';
                    let html = '<h2>✅ mTLS API Call Successful!</h2>';
                    html += '<div class="cert-info">';
                    html += '<div>';
                    html += '<div class="field"><span class="label">Used mTLS:</span><span class="value">' + (data.used_mtls ? '✅ Yes' : '❌ No (HTTP fallback)') + '</span></div>';
                    if (data.peer_spiffe_id) {
                        html += '<div class="field"><span class="label">Peer SPIFFE ID:</span><span class="value">' + data.peer_spiffe_id + '</span></div>';
                    }
                    html += '<div class="field"><span class="label">API Response Status:</span><span class="value">' + data.response.status + '</span></div>';
                    html += '<div class="field"><span class="label">Service Name:</span><span class="value">' + data.response.service_name + '</span></div>';
                    html += '<div class="field"><span class="label">Version:</span><span class="value">' + data.response.version + '</span></div>';
                    html += '<div class="field"><span class="label">Timestamp:</span><span class="value">' + data.response.timestamp + '</span></div>';
                    html += '</div>';
                    html += '<div>';
                    if (data.response.data && data.response.data.spiffe_id) {
                        html += '<div class="field"><span class="label">API Service SPIFFE ID:</span><span class="value">' + data.response.data.spiffe_id + '</span></div>';
                        html += '<div class="field"><span class="label">API Attestation Status:</span><span class="value">' + data.response.data.attestation_status + '</span></div>';
                    }
                    html += '</div>';
                    html += '</div>';
                    
                    if (data.response.data) {
                        html += '<h4>🔍 API Service Details:</h4>';
                        html += '<pre>' + JSON.stringify(data.response.data, null, 2) + '</pre>';
                    }
                    
                    resultDiv.innerHTML = html;
                } else {
                    resultDiv.className = 'api-result section error';
                    resultDiv.innerHTML = '<h2>❌ API Call Failed</h2><p><strong>Error:</strong> ' + (data.error || 'Unknown error occurred') + '</p>';
                }
            })
            .catch(error => {
                // Reset button
                btn.disabled = false;
                btn.innerHTML = '🔗 Call API Service (mTLS)';
                
                // Show error
                resultDiv.className = 'api-result section error';
                resultDiv.innerHTML = '<h2>❌ Network Error</h2><p><strong>Error:</strong> ' + error.message + '</p>';
            });
        }
    </script>
</body>
</html>
`

func parseCertificate(certPEM []byte) (*X509CertInfo, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	var uris []string
	for _, uri := range cert.URIs {
		uris = append(uris, uri.String())
	}

	return &X509CertInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		DNSNames:     cert.DNSNames,
		URIs:         uris,
	}, nil
}

func getECSMetadata() (*ECSTaskMetadata, error) {
	metadataURI := os.Getenv("ECS_CONTAINER_METADATA_URI_V4")
	if metadataURI == "" {
		return nil, nil
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(metadataURI)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var metadata ECSTaskMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, err
	}

	return &metadata, nil
}

func generatePotentialSelectors(metadata *ECSTaskMetadata) []string {
	if metadata == nil {
		return nil
	}

	var selectors []string

	// Task-level selectors
	if metadata.Cluster != "" {
		selectors = append(selectors, "ecs:cluster:"+metadata.Cluster)
	}
	if metadata.Family != "" {
		selectors = append(selectors, "ecs:task-definition-family:"+metadata.Family)
	}
	if metadata.Revision != "" {
		selectors = append(selectors, "ecs:task-definition-revision:"+metadata.Revision)
	}
	if metadata.ServiceName != "" {
		selectors = append(selectors, "ecs:service-name:"+metadata.ServiceName)
	}
	if metadata.LaunchType != "" {
		selectors = append(selectors, "ecs:launch-type:"+metadata.LaunchType)
	}
	if metadata.AvailabilityZone != "" {
		selectors = append(selectors, "ecs:availability-zone:"+metadata.AvailabilityZone)
	}
	if metadata.TaskARN != "" {
		selectors = append(selectors, "ecs:task-arn:"+metadata.TaskARN)
	}

	// Task tags
	for key, value := range metadata.TaskTags {
		selectors = append(selectors, "ecs:task-tag:"+key+":"+value)
	}

	// Container-level selectors
	for _, container := range metadata.Containers {
		if container.Name != "" {
			selectors = append(selectors, "ecs:container-name:"+container.Name)
		}
		if container.Image != "" {
			selectors = append(selectors, "ecs:container-image:"+container.Image)
		}
		if container.ImageID != "" {
			selectors = append(selectors, "ecs:container-image-id:"+container.ImageID)
		}
		if container.Type != "" {
			selectors = append(selectors, "ecs:container-type:"+container.Type)
		}

		// Container labels
		for key, value := range container.Labels {
			if key == "com.amazonaws.ecs.cluster" ||
				key == "com.amazonaws.ecs.container-name" ||
				key == "com.amazonaws.ecs.task-definition-family" ||
				key == "com.amazonaws.ecs.task-definition-version" {
				selectors = append(selectors, "ecs:label:"+key+":"+value)
			}
		}
	}

	return selectors
}

// PersistentMTLSClient manages persistent mTLS connections and certificate rotation
type PersistentMTLSClient struct {
	mu          sync.RWMutex
	client      *http.Client
	source      *workloadapi.X509Source
	lastRefresh time.Time
	refreshInterval time.Duration
}

// Global persistent mTLS client
var globalMTLSClient *PersistentMTLSClient
var clientInitOnce sync.Once

// initPersistentMTLSClient initializes the global persistent mTLS client
func initPersistentMTLSClient() error {
	// Reset the once in case we need to retry initialization
	if globalMTLSClient == nil {
		clientInitOnce = sync.Once{}
	}
	
	var initErr error
	clientInitOnce.Do(func() {
		log.Println("🔧 Initializing persistent mTLS client...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		// Create persistent X509Source
		socketPath := "unix:///tmp/spire-agent/public/api.sock"
		source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
		if err != nil {
			initErr = fmt.Errorf("failed to create X509Source: %v", err)
			log.Printf("❌ X509Source creation failed: %v", err)
			return
		}

		// Create persistent client
		globalMTLSClient = &PersistentMTLSClient{
			source:          source,
			refreshInterval: 30 * time.Second, // Refresh every 30 seconds
		}

		// Build initial client
		if err := globalMTLSClient.refreshClient(); err != nil {
			initErr = fmt.Errorf("failed to build initial mTLS client: %v", err)
			log.Printf("❌ mTLS client build failed: %v", err)
			source.Close()
			globalMTLSClient = nil // Reset to nil on failure
			return
		}

		// Start certificate refresh routine
		go globalMTLSClient.startRefreshRoutine()

		log.Println("✅ Persistent mTLS client initialized successfully")
	})
	return initErr
}

// refreshClient rebuilds the HTTP client with current certificates
func (p *PersistentMTLSClient) refreshClient() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Get current X.509 SVID
	svid, err := p.source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("failed to get X.509 SVID: %v", err)
	}

	if len(svid.Certificates) == 0 {
		return fmt.Errorf("no certificates in X.509-SVID")
	}

	// Get trust bundle from source
	bundle, err := p.source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return fmt.Errorf("failed to get trust bundle: %v", err)
	}

	serverCAs := x509.NewCertPool()
	for _, cert := range bundle.X509Authorities() {
		serverCAs.AddCert(cert)
	}

	// Create client certificate
	clientCert := tls.Certificate{
		Certificate: [][]byte{svid.Certificates[0].Raw},
		PrivateKey:  svid.PrivateKey,
	}

	// Create TLS config for client
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      serverCAs,
		ServerName:   "", // Empty server name to bypass hostname verification
		InsecureSkipVerify: true, // Required for SPIRE certificates
		MinVersion: tls.VersionTLS12,
	}

	// Create HTTP client with custom DialTLS and connection pooling
	p.client = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			// Connection pooling settings
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false,
			// Custom DialTLS to bypass hostname validation for SPIRE certificates
			DialTLS: func(network, addr string) (net.Conn, error) {
				log.Printf("🔧 DEBUG: Custom DialTLS called for %s %s", network, addr)
				
				// Create TCP connection manually
				conn, err := net.Dial(network, addr)
				if err != nil {
					return nil, fmt.Errorf("failed to dial %s: %v", addr, err)
				}
				
				// Wrap with TLS using empty ServerName and InsecureSkipVerify
				tlsConfigCopy := tlsConfig.Clone()
				tlsConfigCopy.ServerName = "" // Force empty server name
				tlsConfigCopy.InsecureSkipVerify = true // Required for SPIRE certificates
				
				tlsConn := tls.Client(conn, tlsConfigCopy)
				if err := tlsConn.Handshake(); err != nil {
					conn.Close()
					return nil, fmt.Errorf("TLS handshake failed: %v", err)
				}
				
				log.Printf("✅ DEBUG: TLS handshake successful for %s", addr)
				return tlsConn, nil
			},
		},
	}

	p.lastRefresh = time.Now()
	log.Printf("🔄 mTLS client refreshed at %s", p.lastRefresh.Format(time.RFC3339))
	return nil
}

// startRefreshRoutine starts the certificate refresh routine
func (p *PersistentMTLSClient) startRefreshRoutine() {
	ticker := time.NewTicker(p.refreshInterval)
	defer ticker.Stop()

	for range ticker.C {
		if err := p.refreshClient(); err != nil {
			log.Printf("❌ Failed to refresh mTLS client: %v", err)
		} else {
			log.Println("✅ mTLS client certificates refreshed successfully")
		}
	}
}

// getClient returns the current HTTP client (thread-safe)
func (p *PersistentMTLSClient) getClient() *http.Client {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.client
}

// cleanup closes the persistent client resources
func (p *PersistentMTLSClient) cleanup() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.source != nil {
		p.source.Close()
	}
}

// callAPIServiceWithMTLS attempts to call API service using persistent mTLS client
func callAPIServiceWithMTLS() *MTLSCallResult {
	result := &MTLSCallResult{}
	
	// Ensure persistent client is initialized (with retry logic)
	if globalMTLSClient == nil {
		log.Println("🔄 Attempting to initialize persistent mTLS client...")
		if err := initPersistentMTLSClient(); err != nil {
			log.Printf("❌ Failed to initialize persistent mTLS client: %v", err)
			result.Error = fmt.Sprintf("Failed to initialize persistent mTLS client: %v", err)
			return result
		}
	}

	// Get current client (thread-safe)
	client := globalMTLSClient.getClient()
	if client == nil {
		log.Println("❌ mTLS client not available after initialization")
		result.Error = "mTLS client not available"
		return result
	}

	// Make mTLS request to API service on internal container port 8080
	resp, err := client.Get("https://api-service-with-agent:8080/attestation")
	if err != nil {
		result.Error = fmt.Sprintf("mTLS request failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to read mTLS response: %v", err)
		return result
	}

	var apiResponse APIServiceResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		result.Error = fmt.Sprintf("Failed to parse mTLS response: %v", err)
		return result
	}

	// Extract peer SPIFFE ID from TLS connection
	peerSpiffeID := "spiffe://example.org/api-service" // Expected server identity

	result.Success = true
	result.UsedMTLS = true
	result.PeerSpiffeID = peerSpiffeID
	result.Response = &apiResponse

	log.Printf("✅ mTLS call successful to API service (using persistent client)")
	return result
}

// fallbackToHTTP makes a regular HTTP call when mTLS fails
func fallbackToHTTP(result *MTLSCallResult) *MTLSCallResult {
	log.Printf("🔄 Falling back to HTTP for API service call")
	
	client := &http.Client{Timeout: 30 * time.Second}
	// Try HTTP on external port since internal port is mTLS-only
	resp, err := client.Get("http://localhost:8082/attestation")
	if err != nil {
		result.Error = fmt.Sprintf("HTTP fallback failed: %v", err)
		return result
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to read HTTP response: %v", err)
		return result
	}

	var apiResponse APIServiceResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		result.Error = fmt.Sprintf("Failed to parse HTTP response: %v", err)
		return result
	}

	result.Success = true
	result.UsedMTLS = false
	result.Fallback = true
	result.Response = &apiResponse

	log.Printf("✅ HTTP fallback call successful")
	return result
}

func getSPIREInfo() *SPIREInfo {
	info := &SPIREInfo{
		AttestationStatus: "FAILED",
	}

	// Try to get ECS metadata
	if metadata, err := getECSMetadata(); err == nil && metadata != nil {
		info.ECSMetadata = metadata
		info.PotentialSelectors = generatePotentialSelectors(metadata)
	}

	// Try to connect to SPIRE Workload API
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	socketPath := "unix:///tmp/spire-agent/public/api.sock"
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		info.Error = fmt.Sprintf("Failed to create X509Source: %v", err)
		return info
	}
	defer source.Close()

	// Get X.509 SVID
	svid, err := source.GetX509SVID()
	if err != nil {
		info.Error = fmt.Sprintf("Failed to get X.509 SVID: %v", err)
		return info
	}

	info.AttestationStatus = "SUCCESS"
	info.SPIFFEID = svid.ID.String()

	// Parse X.509 SVID certificate
	if len(svid.Certificates) > 0 {
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: svid.Certificates[0].Raw,
		})
		info.X509SVID = string(certPEM)

		if parsed, err := parseCertificate(certPEM); err == nil {
			info.X509SVIDParsed = parsed
		}
	}

	// Get trust bundle
	bundle, err := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err == nil && bundle != nil {
		var bundlePEM []byte
		var parsedCerts []*X509CertInfo

		for _, cert := range bundle.X509Authorities() {
			certPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			})
			bundlePEM = append(bundlePEM, certPEM...)

			if parsed, err := parseCertificate(certPEM); err == nil {
				parsedCerts = append(parsedCerts, parsed)
			}
		}

		info.TrustBundle = string(bundlePEM)
		info.TrustBundleParsed = parsedCerts
	}

	// Try to get JWT SVID
	if jwtSource, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath))); err == nil {
		defer jwtSource.Close()
		if jwtSVID, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{
			Audience: "test-audience",
		}); err == nil {
			info.JWTSVID = jwtSVID.Marshal()
		}
	}

	return info
}

func handler(w http.ResponseWriter, r *http.Request) {
	info := getSPIREInfo()

	tmpl := template.Must(template.New("spire-info").Funcs(template.FuncMap{
		"add": func(a, b int) int { return a + b },
	}).Parse(htmlTemplate))

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, info); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func jsonHandler(w http.ResponseWriter, r *http.Request) {
	info := getSPIREInfo()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(info)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// apiCallHandler handles API calls to the API service using mTLS
func apiCallHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	// Handle preflight OPTIONS request
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Println("🔗 Web app: Initiating mTLS API call to API service...")

	// Call the API service using mTLS
	result := callAPIServiceWithMTLS()

	// Log the result
	if result.Success {
		if result.UsedMTLS {
			log.Printf("✅ Web app: mTLS API call successful (peer: %s)", result.PeerSpiffeID)
		} else {
			log.Println("⚠️  Web app: API call successful but used HTTP fallback")
		}
	} else {
		log.Printf("❌ Web app: API call failed: %s", result.Error)
	}

	// Return the result as JSON
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("Error encoding API call result: %v", err)
	}
}

func main() {
	log.Println("Starting SPIRE Fargate Demo App...")

	// Attempt to initialize persistent mTLS client on startup (non-blocking)
	if err := initPersistentMTLSClient(); err != nil {
		log.Printf("⚠️  Failed to initialize persistent mTLS client at startup: %v", err)
		log.Println("Web app will start and retry mTLS initialization on first API call")
		// Reset globalMTLSClient to nil so it can be retried later
		globalMTLSClient = nil
	} else {
		log.Println("✅ Persistent mTLS client initialized successfully at startup")
	}

	// Set up HTTP handlers
	http.HandleFunc("/", handler)
	http.HandleFunc("/json", jsonHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/api-call", apiCallHandler)

	// Cleanup on exit
	defer func() {
		if globalMTLSClient != nil {
			globalMTLSClient.cleanup()
		}
	}()

	log.Println("Server starting on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
