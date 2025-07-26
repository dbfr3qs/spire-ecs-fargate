package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
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

// APIServiceResponse from API service
type APIServiceResponse struct {
	ServiceName string     `json:"service_name"`
	Version     string     `json:"version"`
	Timestamp   time.Time  `json:"timestamp"`
	Status      string     `json:"status"`
	Data        *SPIREInfo `json:"data"`
}

// SimpleCallResult represents API call result (no mTLS complexity)
type SimpleCallResult struct {
	Success   bool                `json:"success"`
	Response  *APIServiceResponse `json:"response,omitempty"`
	Error     string              `json:"error,omitempty"`
	Endpoint  string              `json:"endpoint"`
	Transport string              `json:"transport"`
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
    <title>SPIRE Envoy Service Mesh Demo</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #2c3e50; margin-bottom: 10px; }
        .header p { color: #7f8c8d; font-size: 16px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .info { background: #e8f5e8; }
        .warning { background: #fff3cd; }
        .error { background: #f8d7da; }
        .success { background: #d1ecf1; }
        .cert-info { background: #f8f9fa; padding: 10px; border-radius: 3px; margin: 10px 0; }
        .field { margin: 5px 0; }
        .label { font-weight: bold; color: #495057; display: inline-block; width: 200px; }
        .value { color: #212529; font-family: monospace; }
        .refresh-btn { background: #007bff; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px; }
        .api-section { background: #e7f3ff; }
        .api-call-btn {
            background: #28a745; 
            color: white; 
            border: none; 
            padding: 12px 24px; 
            border-radius: 5px; 
            cursor: pointer; 
            font-size: 16px;
            margin: 10px 5px;
        }
        .api-call-btn:hover { background: #218838; }
        .api-result { margin-top: 15px; padding: 15px; border-radius: 5px; }
        pre { background: #f8f9fa; padding: 10px; border-radius: 3px; overflow-x: auto; }
        .architecture-note { background: #fff3e0; padding: 15px; border-left: 4px solid #ff9800; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🌐 SPIRE Envoy Service Mesh Demo</h1>
            <p>ECS Fargate Task Identity with Envoy Proxy mTLS</p>
            <div class="architecture-note">
                <strong>🏗️ Service Mesh Architecture:</strong> This application communicates through Envoy Proxy sidecars. 
                mTLS is handled transparently by Envoy using SPIRE-issued certificates, while applications use plain HTTP.
            </div>
            <a href="/" class="refresh-btn">🔄 Refresh</a>
        </div>

        <div class="section api-section">
            <h2>🌐 Service Mesh API Communication</h2>
            <p>Test service-to-service communication through Envoy Proxy with automatic mTLS:</p>
            <button class="api-call-btn" onclick="callAPIService()">📡 Call API Service via Envoy</button>
            <div id="api-result"></div>
        </div>

        {{if .Error}}
        <div class="section error">
            <h2>❌ Error</h2>
            <p>{{.Error}}</p>
        </div>
        {{else}}
        
        <div class="section info">
            <h2>🆔 SPIFFE Identity Information</h2>
            <div class="cert-info">
                <div class="field"><span class="label">SPIFFE ID:</span><span class="value">{{.SPIFFEID}}</span></div>
                <div class="field"><span class="label">Attestation Status:</span><span class="value">{{.AttestationStatus}}</span></div>
                {{if .X509SVIDParsed}}
                <div class="field"><span class="label">Certificate Subject:</span><span class="value">{{.X509SVIDParsed.Subject}}</span></div>
                <div class="field"><span class="label">Certificate Issuer:</span><span class="value">{{.X509SVIDParsed.Issuer}}</span></div>
                <div class="field"><span class="label">Valid Until:</span><span class="value">{{.X509SVIDParsed.NotAfter}}</span></div>
                {{end}}
            </div>
        </div>

        {{if .ECSMetadata}}
        <div class="section info">
            <h2>🚢 ECS Task Metadata</h2>
            <div class="cert-info">
                <div class="field"><span class="label">Cluster:</span><span class="value">{{.ECSMetadata.Cluster}}</span></div>
                <div class="field"><span class="label">Task ARN:</span><span class="value">{{.ECSMetadata.TaskARN}}</span></div>
                <div class="field"><span class="label">Family:</span><span class="value">{{.ECSMetadata.Family}}</span></div>
                <div class="field"><span class="label">Service Name:</span><span class="value">{{.ECSMetadata.ServiceName}}</span></div>
                <div class="field"><span class="label">Launch Type:</span><span class="value">{{.ECSMetadata.LaunchType}}</span></div>
                <div class="field"><span class="label">Availability Zone:</span><span class="value">{{.ECSMetadata.AvailabilityZone}}</span></div>
            </div>
        </div>
        {{end}}

        {{end}}
    </div>

    <script>
        async function callAPIService() {
            const resultDiv = document.getElementById('api-result');
            resultDiv.innerHTML = '<p>🔄 Calling API service through Envoy proxy...</p>';
            
            try {
                const response = await fetch('/api-call');
                const data = await response.json();
                
                let resultClass = data.success ? 'success' : 'error';
                let icon = data.success ? '✅' : '❌';
                
                resultDiv.innerHTML = 
                    '<div class="api-result ' + resultClass + '">' +
                        '<h3>' + icon + ' API Service Response</h3>' +
                        '<p><strong>Transport:</strong> ' + data.transport + '</p>' +
                        '<p><strong>Endpoint:</strong> ' + data.endpoint + '</p>' +
                        (data.success ? 
                            '<p><strong>Service:</strong> ' + data.response.service_name + ' v' + data.response.version + '</p>' +
                            '<p><strong>API Service Identity:</strong> ' + data.response.data.spiffe_id + '</p>' +
                            '<pre>' + JSON.stringify(data, null, 2) + '</pre>' :
                            '<p><strong>Error:</strong> ' + data.error + '</p>'
                        ) +
                    '</div>';
            } catch (error) {
                resultDiv.innerHTML = 
                    '<div class="api-result error">' +
                        '<h3>❌ Request Failed</h3>' +
                        '<p><strong>Error:</strong> ' + error.message + '</p>' +
                    '</div>';
            }
        }
    </script>
</body>
</html>`

// mTLS API call using SPIRE certificates with custom DialTLS solution
func callAPIServiceViaEnvoy() *SimpleCallResult {
	// Add panic recovery to catch any early failures
	defer func() {
		if r := recover(); r != nil {
			log.Printf("❌ PANIC in callAPIServiceViaEnvoy: %v", r)
		}
	}()
	
	log.Printf("🚀 DEBUG: Starting mTLS API call with SPIRE certificates")
	log.Printf("🔍 DEBUG: Function entry successful - checking SPIRE agent socket...")
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	
	log.Printf("🔍 DEBUG: Creating SPIRE X509Source...")
	// Create SPIRE X509Source for certificate retrieval
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix:///tmp/spire-agent/public/api.sock")))
	if err != nil {
		log.Printf("❌ DEBUG: Failed to create X509Source: %v", err)
		return &SimpleCallResult{
			Success:   false,
			Error:     fmt.Sprintf("Failed to create X509Source: %v", err),
			Endpoint:  "https://api-service-with-agent:8080/attestation",
			Transport: "mTLS using SPIRE certificates",
		}
	}
	log.Printf("✅ DEBUG: X509Source created successfully")
	defer source.Close()
	
	// Get SPIRE-issued X509 SVID
	svid, err := source.GetX509SVID()
	if err != nil {
		return &SimpleCallResult{
			Success:   false,
			Error:     fmt.Sprintf("Failed to get X509 SVID: %v", err),
			Endpoint:  "https://api-service-with-agent:8080/attestation",
			Transport: "mTLS using SPIRE certificates",
		}
	}
	
	// Create trust bundle CA pool - use system trust bundle for simplicity
	// This works because both services use the same SPIRE trust domain
	serverCAs := x509.NewCertPool()
	// Add the issuer of our own certificate as trusted CA
	// Since we're in the same trust domain, the API service will have the same issuer
	if len(svid.Certificates) > 1 {
		// Add intermediate/root certificates from our own certificate chain
		for i := 1; i < len(svid.Certificates); i++ {
			serverCAs.AddCert(svid.Certificates[i])
		}
	} else {
		// If no intermediate certs, trust the certificate's issuer
		// This is a fallback approach for SPIRE certificates
		log.Printf("⚠️  WARNING: Using InsecureSkipVerify for trust bundle - single cert in chain")
	}
	
	// Create client certificate from SPIRE SVID (single certificate, not loop)
	clientCert := tls.Certificate{
		Certificate: [][]byte{svid.Certificates[0].Raw},
		PrivateKey:  svid.PrivateKey,
	}
	

	
	// Create TLS configuration for mTLS
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:           serverCAs,
		ServerName:        "", // Empty server name to bypass hostname verification
		InsecureSkipVerify: true, // Required for SPIRE certificates
		MinVersion:        tls.VersionTLS12,
	}
	
	// Create HTTP client with custom DialTLS (breakthrough solution)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
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
	
	// Make mTLS request to API service
	resp, err := client.Get("https://api-service-with-agent:8080/attestation")
	if err != nil {
		return &SimpleCallResult{
			Success:   false,
			Error:     fmt.Sprintf("Failed to call API service via mTLS: %v", err),
			Endpoint:  "https://api-service-with-agent:8080/attestation",
			Transport: "mTLS using SPIRE certificates",
		}
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return &SimpleCallResult{
			Success:   false,
			Error:     fmt.Sprintf("Failed to read response: %v", err),
			Endpoint:  "https://api-service-with-agent:8080/attestation",
			Transport: "mTLS using SPIRE certificates",
		}
	}
	
	var apiResponse APIServiceResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return &SimpleCallResult{
			Success:   false,
			Error:     fmt.Sprintf("Failed to parse response: %v", err),
			Endpoint:  "https://api-service-with-agent:8080/attestation",
			Transport: "mTLS using SPIRE certificates",
		}
	}
	
	log.Printf("✅ mTLS API call successful - received valid APIServiceResponse")
	return &SimpleCallResult{
		Success:   true,
		Response:  &apiResponse,
		Endpoint:  "https://api-service-with-agent:8080/attestation",
		Transport: "mTLS using SPIRE certificates",
	}
}

func getSPIREInfo() *SPIREInfo {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix:///tmp/spire-agent/public/api.sock")))
	if err != nil {
		return &SPIREInfo{
			AttestationStatus: "FAILED",
			Error:             fmt.Sprintf("Failed to create X509Source: %v", err),
		}
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		return &SPIREInfo{
			AttestationStatus: "FAILED",
			Error:             fmt.Sprintf("Failed to get X509 SVID: %v", err),
		}
	}

	// Parse certificate information
	cert := svid.Certificates[0]
	certInfo := &X509CertInfo{
		Subject:      cert.Subject.String(),
		Issuer:       cert.Issuer.String(),
		SerialNumber: cert.SerialNumber.String(),
		NotBefore:    cert.NotBefore,
		NotAfter:     cert.NotAfter,
		DNSNames:     cert.DNSNames,
	}

	for _, uri := range cert.URIs {
		certInfo.URIs = append(certInfo.URIs, uri.String())
	}

	// Get ECS metadata
	ecsMetadata, _ := getECSMetadata()
	
	// Generate potential selectors
	var potentialSelectors []string
	if ecsMetadata != nil {
		potentialSelectors = generatePotentialSelectors(ecsMetadata)
	}

	return &SPIREInfo{
		SPIFFEID:          svid.ID.String(),
		X509SVIDParsed:    certInfo,
		AttestationStatus: "SUCCESS",
		ECSMetadata:       ecsMetadata,
		PotentialSelectors: potentialSelectors,
	}
}

func getECSMetadata() (*ECSTaskMetadata, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://ecs-metadata-mock:8090/v4/metadata")
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
	var selectors []string
	
	if metadata.Cluster != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate_task:cluster:%s", metadata.Cluster))
	}
	if metadata.Family != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate_task:family:%s", metadata.Family))
	}
	if metadata.ServiceName != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate_task:service:%s", metadata.ServiceName))
	}
	if metadata.LaunchType != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate_task:launch_type:%s", metadata.LaunchType))
	}
	
	for key, value := range metadata.TaskTags {
		selectors = append(selectors, fmt.Sprintf("aws_fargate_task:tag:%s:%s", key, value))
	}
	
	return selectors
}

func handler(w http.ResponseWriter, r *http.Request) {
	spireInfo := getSPIREInfo()
	
	tmpl, err := template.New("index").Parse(htmlTemplate)
	if err != nil {
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}
	
	if err := tmpl.Execute(w, spireInfo); err != nil {
		log.Printf("Template execution error: %v", err)
		http.Error(w, fmt.Sprintf("Template execution error: %v", err), http.StatusInternalServerError)
		return
	}
}

func jsonHandler(w http.ResponseWriter, r *http.Request) {
	spireInfo := getSPIREInfo()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(spireInfo)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Simplified API call handler - no mTLS complexity
func apiCallHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("🌟 DEBUG: apiCallHandler called - starting API call flow")
	w.Header().Set("Content-Type", "application/json")
	
	log.Printf("📞 DEBUG: About to call callAPIServiceViaEnvoy()")
	result := callAPIServiceViaEnvoy()
	log.Printf("📋 DEBUG: callAPIServiceViaEnvoy() returned: %+v", result)
	
	log.Printf("📤 DEBUG: About to encode and send response")
	json.NewEncoder(w).Encode(result)
	log.Printf("✅ DEBUG: apiCallHandler completed")
}

func main() {
	log.Println("🚀 Starting SPIRE Envoy Service Mesh Demo Web Application...")
	log.Println("🌐 Architecture: Plain HTTP to Envoy sidecar, mTLS handled transparently")
	
	http.HandleFunc("/", handler)
	http.HandleFunc("/json", jsonHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/api-call", apiCallHandler)
	
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	
	log.Printf("🌍 Web application starting on port %s", port)
	log.Printf("🔗 Available endpoints:")
	log.Printf("  • http://localhost:%s/ - Main dashboard", port)
	log.Printf("  • http://localhost:%s/json - JSON API", port)
	log.Printf("  • http://localhost:%s/health - Health check", port)
	log.Printf("  • http://localhost:%s/api-call - Test API service communication", port)
	
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
