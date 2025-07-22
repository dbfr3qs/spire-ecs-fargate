package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
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

type APIResponse struct {
	ServiceName string     `json:"service_name"`
	Version     string     `json:"version"`
	Timestamp   time.Time  `json:"timestamp"`
	Status      string     `json:"status"`
	Data        *SPIREInfo `json:"data"`
}

func parseCertificate(certPEM []byte) (*X509CertInfo, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
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
	metadataURIV4 := os.Getenv("ECS_CONTAINER_METADATA_URI_V4")
	if metadataURIV4 == "" {
		return nil, fmt.Errorf("ECS_CONTAINER_METADATA_URI_V4 not set")
	}

	taskURL := metadataURIV4 + "/task"
	resp, err := http.Get(taskURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get ECS metadata: %v", err)
	}
	defer resp.Body.Close()

	var metadata ECSTaskMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode ECS metadata: %v", err)
	}

	return &metadata, nil
}

func generatePotentialSelectors(metadata *ECSTaskMetadata) []string {
	var selectors []string

	if metadata == nil {
		return selectors
	}

	// Basic ECS selectors
	if metadata.Cluster != "" {
		selectors = append(selectors, fmt.Sprintf("ecs:cluster:%s", metadata.Cluster))
	}
	if metadata.Family != "" {
		selectors = append(selectors, fmt.Sprintf("ecs:task-definition-family:%s", metadata.Family))
	}
	if metadata.Revision != "" {
		selectors = append(selectors, fmt.Sprintf("ecs:task-definition-revision:%s", metadata.Revision))
	}
	if metadata.LaunchType != "" {
		selectors = append(selectors, fmt.Sprintf("ecs:launch-type:%s", metadata.LaunchType))
	}
	if metadata.ServiceName != "" {
		selectors = append(selectors, fmt.Sprintf("ecs:service-name:%s", metadata.ServiceName))
	}
	if metadata.AvailabilityZone != "" {
		selectors = append(selectors, fmt.Sprintf("ecs:availability-zone:%s", metadata.AvailabilityZone))
	}

	// Task tags
	for key, value := range metadata.TaskTags {
		selectors = append(selectors, fmt.Sprintf("ecs:task-tag:%s:%s", key, value))
	}

	// Container-based selectors
	for _, container := range metadata.Containers {
		if container.Name != "" {
			selectors = append(selectors, fmt.Sprintf("ecs:container-name:%s", container.Name))
		}
		if container.Image != "" {
			selectors = append(selectors, fmt.Sprintf("ecs:container-image:%s", container.Image))
		}
		for key, value := range container.Labels {
			selectors = append(selectors, fmt.Sprintf("ecs:container-label:%s:%s", key, value))
		}
	}

	// Unix-based selectors (common in containers)
	selectors = append(selectors, "unix:uid:0")
	selectors = append(selectors, "unix:gid:0")

	return selectors
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

func attestationHandler(w http.ResponseWriter, r *http.Request) {
	info := getSPIREInfo()
	
	response := APIResponse{
		ServiceName: "spire-attestation-api",
		Version:     "1.0.0",
		Timestamp:   time.Now(),
		Status:      info.AttestationStatus,
		Data:        info,
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	json.NewEncoder(w).Encode(response)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"service": "spire-attestation-api",
		"timestamp": time.Now().Format(time.RFC3339),
	})
}

// mTLSConfig holds the current TLS configuration with certificate rotation
type mTLSConfig struct {
	mu          sync.RWMutex
	tlsConfig   *tls.Config
	certExpiry  time.Time
}

var globalMTLSConfig = &mTLSConfig{}

// setupMTLS configures mTLS using SPIRE certificates
func setupMTLS() (*tls.Config, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create X509Source using the same pattern as existing code
	socketPath := "unix:///tmp/spire-agent/public/api.sock"
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return nil, fmt.Errorf("failed to create X509Source: %v", err)
	}
	defer source.Close()

	// Get X.509 SVID
	svid, err := source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("failed to get X.509 SVID: %v", err)
	}

	if len(svid.Certificates) == 0 {
		return nil, fmt.Errorf("no certificates in X.509-SVID")
	}

	// Get trust bundle from source
	bundle, err := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return nil, fmt.Errorf("failed to get trust bundle: %v", err)
	}

	clientCAs := x509.NewCertPool()
	for _, cert := range bundle.X509Authorities() {
		clientCAs.AddCert(cert)
	}

	// Convert X.509 certificates to tls.Certificate
	tlsCerts := make([]tls.Certificate, len(svid.Certificates))
	for i, cert := range svid.Certificates {
		tlsCerts[i] = tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  svid.PrivateKey,
		}
	}

	// Create TLS config with client certificate validation
	tlsConfig := &tls.Config{
		Certificates: tlsCerts,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return validateClientCertificate(rawCerts, verifiedChains)
		},
		MinVersion: tls.VersionTLS12,
	}

	log.Printf("✅ mTLS configured with SPIRE certificates")
	log.Printf("   Server SPIFFE ID: %s", svid.ID)
	log.Printf("   Certificate expires: %s", svid.Certificates[0].NotAfter)
	log.Printf("   Trust bundle contains %d certificates", len(bundle.X509Authorities()))

	// Store certificate expiry for refresh tracking
	globalMTLSConfig.mu.Lock()
	globalMTLSConfig.certExpiry = svid.Certificates[0].NotAfter
	globalMTLSConfig.mu.Unlock()

	return tlsConfig, nil
}

// validateClientCertificate validates client certificates and SPIFFE IDs
func validateClientCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		log.Printf("❌ mTLS validation failed: no client certificate provided")
		return fmt.Errorf("no client certificate provided")
	}

	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		log.Printf("❌ mTLS validation failed: failed to parse client certificate: %v", err)
		return fmt.Errorf("failed to parse client certificate: %v", err)
	}

	// Extract SPIFFE ID from certificate
	var spiffeID string
	for _, uri := range cert.URIs {
		if strings.HasPrefix(uri.String(), "spiffe://") {
			spiffeID = uri.String()
			break
		}
	}

	if spiffeID == "" {
		log.Printf("❌ mTLS validation failed: no SPIFFE ID found in client certificate")
		return fmt.Errorf("no SPIFFE ID found in client certificate")
	}

	// Validate trust domain
	if !strings.HasPrefix(spiffeID, "spiffe://example.org/") {
		log.Printf("❌ mTLS validation failed: invalid trust domain in SPIFFE ID: %s", spiffeID)
		return fmt.Errorf("invalid trust domain in SPIFFE ID: %s", spiffeID)
	}

	log.Printf("✅ Client certificate validated: SPIFFE ID = %s", spiffeID)
	return nil
}

// refreshCertificates periodically refreshes SPIRE certificates
func refreshCertificates() {
	for {
		time.Sleep(30 * time.Second) // Check every 30 seconds
		
		globalMTLSConfig.mu.RLock()
		expiry := globalMTLSConfig.certExpiry
		globalMTLSConfig.mu.RUnlock()
		
		// Refresh if certificate expires within 5 minutes
		if time.Until(expiry) < 5*time.Minute {
			log.Printf("🔄 Refreshing SPIRE certificates (expires in %v)", time.Until(expiry))
			
			newTLSConfig, err := setupMTLS()
			if err != nil {
				log.Printf("❌ Failed to refresh certificates: %v", err)
				continue
			}
			
			globalMTLSConfig.mu.Lock()
			globalMTLSConfig.tlsConfig = newTLSConfig
			// Certificate expiry already updated inside setupMTLS
			globalMTLSConfig.mu.Unlock()
			
			log.Printf("✅ Certificates refreshed successfully")
		}
	}
}

// getTLSConfig returns the current TLS configuration
func getTLSConfig() *tls.Config {
	globalMTLSConfig.mu.RLock()
	defer globalMTLSConfig.mu.RUnlock()
	return globalMTLSConfig.tlsConfig
}

func main() {
	// Setup mTLS configuration
	tlsConfig, err := setupMTLS()
	if err != nil {
		log.Printf("❌ Failed to setup mTLS: %v", err)
		log.Printf("🔄 Falling back to HTTP mode")
		// Fallback to HTTP
		startHTTPServer()
		return
	}

	// Store initial TLS config
	globalMTLSConfig.mu.Lock()
	globalMTLSConfig.tlsConfig = tlsConfig
	// Certificate expiry already updated inside setupMTLS
	globalMTLSConfig.mu.Unlock()

	// Start certificate refresh goroutine
	go refreshCertificates()

	// Setup HTTP handlers
	http.HandleFunc("/attestation", attestationHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/", attestationHandler) // Default route

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// Create HTTPS server with mTLS
	server := &http.Server{
		Addr:      ":" + port,
		TLSConfig: tlsConfig,
	}

	log.Printf("🔐 Starting SPIRE mTLS API Server on port %s", port)
	log.Printf("   Server SPIFFE ID: spiffe://example.org/api-service")
	log.Printf("   mTLS enabled with client certificate validation")
	log.Printf("   Endpoints:")
	log.Printf("     GET /attestation - Get SPIRE attestation information")
	log.Printf("     GET /health - Health check")
	
	log.Fatal(server.ListenAndServeTLS("", ""))
}

// startHTTPServer starts a fallback HTTP server
func startHTTPServer() {
	http.HandleFunc("/attestation", attestationHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/", attestationHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("🌐 Starting HTTP API Server on port %s (mTLS disabled)", port)
	log.Printf("   Endpoints:")
	log.Printf("     GET /attestation - Get SPIRE attestation information")
	log.Printf("     GET /health - Health check")
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
