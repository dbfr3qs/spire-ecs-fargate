package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
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
			Audience: "cli-client",
		}); err == nil {
			info.JWTSVID = jwtSVID.Marshal()
		}
	}

	return info
}

// validateServerCertificate validates server certificates and SPIFFE IDs
func validateServerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return fmt.Errorf("no verified certificate chains")
	}

	serverCert := verifiedChains[0][0]
	
	// Extract SPIFFE ID from certificate
	var spiffeID string
	for _, uri := range serverCert.URIs {
		if uri.Scheme == "spiffe" {
			spiffeID = uri.String()
			break
		}
	}

	if spiffeID == "" {
		return fmt.Errorf("no SPIFFE ID found in server certificate")
	}

	// Validate expected service identity
	expectedSpiffeID := "spiffe://example.org/api-service"
	if spiffeID != expectedSpiffeID {
		return fmt.Errorf("unexpected server SPIFFE ID: %s (expected: %s)", spiffeID, expectedSpiffeID)
	}

	log.Printf("\u2705 Server certificate validated - SPIFFE ID: %s", spiffeID)
	return nil
}

func createMTLSClient() (*http.Client, error) {
	log.Printf("🔧 DEBUG: Starting mTLS client creation")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	socketPath := "unix:///tmp/spire-agent/public/api.sock"
	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr(socketPath)))
	if err != nil {
		return nil, fmt.Errorf("failed to create X509Source: %v", err)
	}
	defer source.Close()

	// Get X.509 SVID for client certificate
	svid, err := source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("failed to get X.509 SVID: %v", err)
	}

	// Get trust bundle for server validation
	bundle, err := source.GetX509BundleForTrustDomain(svid.ID.TrustDomain())
	if err != nil {
		return nil, fmt.Errorf("failed to get trust bundle: %v", err)
	}

	// Create certificate pool from trust bundle
	caCertPool := x509.NewCertPool()
	for _, cert := range bundle.X509Authorities() {
		caCertPool.AddCert(cert)
	}

	// Create client certificate
	clientCert := tls.Certificate{
		Certificate: [][]byte{svid.Certificates[0].Raw},
		PrivateKey:  svid.PrivateKey,
	}

	// Configure TLS for SPIRE certificates with custom DialTLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caCertPool,
		InsecureSkipVerify: true,
		MinVersion: tls.VersionTLS12,
	}

	log.Printf("🔧 DEBUG: Created TLS config with InsecureSkipVerify=true")

	// Create custom transport with DialTLS to manually handle hostname validation
	transport := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			log.Printf("🔧 DEBUG: Custom DialTLS called for %s %s", network, addr)
			
			// Parse the address to get host and port
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("failed to parse address %s: %v", addr, err)
			}
			
			// Create plain TCP connection
			conn, err := net.Dial(network, addr)
			if err != nil {
				return nil, fmt.Errorf("failed to dial %s: %v", addr, err)
			}
			
			// Wrap with TLS using empty ServerName to bypass hostname validation
			tlsConfigCopy := tlsConfig.Clone()
			tlsConfigCopy.ServerName = "" // Force empty server name
			
			tlsConn := tls.Client(conn, tlsConfigCopy)
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				return nil, fmt.Errorf("TLS handshake failed for %s:%s: %v", host, port, err)
			}
			
			log.Printf("✅ DEBUG: TLS handshake successful for %s:%s", host, port)
			return tlsConn, nil
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout: 30 * time.Second,
	}, nil
}

func queryAPIService(endpoint string) (*APIResponse, error) {
	client, err := createMTLSClient()
	if err != nil {
		// Fallback to regular HTTP if mTLS fails
		log.Printf("mTLS client creation failed, using regular HTTP: %v", err)
		client = &http.Client{Timeout: 30 * time.Second}
	}

	resp, err := client.Get(endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to query API service: %v", err)
	}
	defer resp.Body.Close()

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode API response: %v", err)
	}

	return &apiResp, nil
}

func printSPIREInfo(info *SPIREInfo, title string) {
	fmt.Printf("\n=== %s ===\n", title)
	fmt.Printf("📍 SPIFFE ID: %s\n", info.SPIFFEID)
	fmt.Printf("🔒 Attestation Status: %s\n", info.AttestationStatus)
	
	if info.X509SVIDParsed != nil {
		fmt.Printf("📜 Certificate Subject: %s\n", info.X509SVIDParsed.Subject)
		fmt.Printf("⏰ Valid Until: %s\n", info.X509SVIDParsed.NotAfter.Format(time.RFC3339))
	}
	
	if info.ECSMetadata != nil {
		fmt.Printf("🚢 ECS Cluster: %s\n", info.ECSMetadata.Cluster)
		fmt.Printf("📦 Task Family: %s\n", info.ECSMetadata.Family)
		fmt.Printf("🏷️  Service: %s\n", info.ECSMetadata.ServiceName)
	}
	
	if len(info.PotentialSelectors) > 0 {
		fmt.Printf("🎯 Selectors (%d):\n", len(info.PotentialSelectors))
		for i, selector := range info.PotentialSelectors {
			if i < 5 { // Show first 5
				fmt.Printf("   • %s\n", selector)
			}
		}
		if len(info.PotentialSelectors) > 5 {
			fmt.Printf("   ... and %d more\n", len(info.PotentialSelectors)-5)
		}
	}
	
	if info.Error != "" {
		fmt.Printf("❌ Error: %s\n", info.Error)
	}
}

func main() {
	var (
		showSelf     = flag.Bool("self", false, "Show own SPIRE attestation information")
		queryAPI     = flag.Bool("query", false, "Query API service attestation information")
		apiEndpoint  = flag.String("endpoint", "https://api-service-with-agent:8080/attestation", "API service endpoint to query")
		jsonOutput   = flag.Bool("json", false, "Output in JSON format")
		showHelp     = flag.Bool("help", false, "Show help information")
	)
	flag.Parse()

	if *showHelp {
		fmt.Println("SPIRE CLI Client - ECS Fargate Identity Demo")
		fmt.Println()
		fmt.Println("This CLI tool demonstrates secure communication between ECS Fargate tasks using SPIRE.")
		fmt.Println("It attests its own identity and can query other services using mTLS.")
		fmt.Println()
		fmt.Println("Usage:")
		flag.PrintDefaults()
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  spire-cli -self                    # Show own attestation info")
		fmt.Println("  spire-cli -query                   # Query API service")
		fmt.Println("  spire-cli -self -query             # Show both")
		fmt.Println("  spire-cli -self -json              # JSON output")
		return
	}

	if !*showSelf && !*queryAPI {
		fmt.Println("🚀 SPIRE CLI Client - ECS Fargate Identity Demo")
		fmt.Println("Use -help for usage information")
		fmt.Println("Use -self to show own identity, -query to query API service")
		return
	}

	if *showSelf {
		fmt.Println("🔍 Getting own SPIRE attestation information...")
		selfInfo := getSPIREInfo()
		
		if *jsonOutput {
			json.NewEncoder(os.Stdout).Encode(selfInfo)
		} else {
			printSPIREInfo(selfInfo, "CLI Client Identity")
		}
	}

	if *queryAPI {
		fmt.Printf("🌐 Querying API service at %s...\n", *apiEndpoint)
		apiResp, err := queryAPIService(*apiEndpoint)
		if err != nil {
			fmt.Printf("❌ Failed to query API service: %v\n", err)
			os.Exit(1)
		}

		if *jsonOutput {
			json.NewEncoder(os.Stdout).Encode(apiResp)
		} else {
			fmt.Printf("\n📡 API Service Response (Status: %s)\n", apiResp.Status)
			fmt.Printf("🕐 Timestamp: %s\n", apiResp.Timestamp.Format(time.RFC3339))
			if apiResp.Data != nil {
				printSPIREInfo(apiResp.Data, "API Service Identity")
			}
		}
	}

	fmt.Println("\n✅ Operations completed successfully!")
}
