package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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

type APIServiceResponse struct {
	ServiceName string     `json:"service_name"`
	Version     string     `json:"version"`
	Timestamp   time.Time  `json:"timestamp"`
	Status      string     `json:"status"`
	Data        *SPIREInfo `json:"data"`
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

func getSelfIdentity() (*SPIREInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	source, err := workloadapi.NewX509Source(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix:///tmp/spire-agent/public/api.sock")))
	if err != nil {
		return nil, fmt.Errorf("failed to create X509Source: %v", err)
	}
	defer source.Close()

	svid, err := source.GetX509SVID()
	if err != nil {
		return nil, fmt.Errorf("failed to get X509 SVID: %v", err)
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

	return &SPIREInfo{
		SPIFFEID:          svid.ID.String(),
		X509SVIDParsed:    certInfo,
		AttestationStatus: "SUCCESS",
	}, nil
}

// Simplified API query - plain HTTP to Envoy sidecar
func queryAPIService() (*APIServiceResponse, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	
	// Call through local Envoy sidecar - Envoy handles mTLS transparently
	resp, err := client.Get("http://127.0.0.1:8080/attestation")
	if err != nil {
		return nil, fmt.Errorf("failed to call API service: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API service returned status %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %v", err)
	}

	var apiResponse APIServiceResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	return &apiResponse, nil
}

func printSelfIdentity(jsonOutput bool) {
	fmt.Println("🔍 Retrieving CLI client identity...")
	
	identity, err := getSelfIdentity()
	if err != nil {
		fmt.Printf("❌ Error retrieving identity: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		output, _ := json.MarshalIndent(identity, "", "  ")
		fmt.Println(string(output))
	} else {
		fmt.Println("\n📍 CLI Client Identity Information:")
		fmt.Printf("  SPIFFE ID: %s\n", identity.SPIFFEID)
		fmt.Printf("  Attestation Status: %s\n", identity.AttestationStatus)
		if identity.X509SVIDParsed != nil {
			fmt.Printf("  Certificate Subject: %s\n", identity.X509SVIDParsed.Subject)
			fmt.Printf("  Certificate Issuer: %s\n", identity.X509SVIDParsed.Issuer)
			fmt.Printf("  Valid Until: %s\n", identity.X509SVIDParsed.NotAfter.Format(time.RFC3339))
		}
	}
}

func queryAPIServiceData(jsonOutput bool) {
	fmt.Println("📡 Querying API service through Envoy proxy...")
	
	response, err := queryAPIService()
	if err != nil {
		fmt.Printf("❌ Error querying API service: %v\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		output, _ := json.MarshalIndent(response, "", "  ")
		fmt.Println(string(output))
	} else {
		fmt.Println("\n🌐 API Service Response:")
		fmt.Printf("  Service: %s v%s\n", response.ServiceName, response.Version)
		fmt.Printf("  Status: %s\n", response.Status)
		fmt.Printf("  Timestamp: %s\n", response.Timestamp.Format(time.RFC3339))
		
		if response.Data != nil {
			fmt.Printf("  API Service SPIFFE ID: %s\n", response.Data.SPIFFEID)
			fmt.Printf("  API Attestation Status: %s\n", response.Data.AttestationStatus)
			
			if response.Data.ECSMetadata != nil {
				fmt.Printf("  ECS Cluster: %s\n", response.Data.ECSMetadata.Cluster)
				fmt.Printf("  ECS Service: %s\n", response.Data.ECSMetadata.ServiceName)
				fmt.Printf("  ECS Family: %s\n", response.Data.ECSMetadata.Family)
			}
		}
		
		fmt.Println("\n🔐 Transport: Plain HTTP → Envoy Proxy → mTLS → API Service")
	}
}

func showHelp() {
	fmt.Println("🌐 SPIRE Envoy Service Mesh CLI Client")
	fmt.Println("=====================================")
	fmt.Println()
	fmt.Println("This CLI demonstrates service-to-service communication through Envoy Proxy")
	fmt.Println("sidecars with SPIRE-issued certificates for transparent mTLS.")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  spire-cli [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -self         Show this CLI client's SPIFFE identity")
	fmt.Println("  -query        Query API service through Envoy proxy")
	fmt.Println("  -json         Output results in JSON format")
	fmt.Println("  -help         Show this help message")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  spire-cli -self                    # Show CLI identity")
	fmt.Println("  spire-cli -query                   # Query API service")
	fmt.Println("  spire-cli -self -query -json       # Both operations with JSON output")
	fmt.Println()
	fmt.Println("Architecture:")
	fmt.Println("  CLI App → Plain HTTP → Envoy Sidecar → mTLS → API Service Envoy → Plain HTTP → API App")
	fmt.Println()
	fmt.Println("Security:")
	fmt.Println("  • mTLS authentication handled transparently by Envoy sidecars")
	fmt.Println("  • SPIRE-issued certificates with automatic rotation")
	fmt.Println("  • Zero-trust networking at the proxy layer")
}

func main() {
	var (
		showSelf  = flag.Bool("self", false, "Show CLI client's SPIFFE identity")
		queryAPI  = flag.Bool("query", false, "Query API service through Envoy proxy")
		jsonOut   = flag.Bool("json", false, "Output in JSON format")
		help      = flag.Bool("help", false, "Show help message")
	)
	
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	// If no flags specified, show help
	if !*showSelf && !*queryAPI {
		showHelp()
		return
	}

	fmt.Println("🚀 SPIRE Envoy Service Mesh CLI Client")
	fmt.Println("======================================")
	fmt.Println("🌐 Architecture: Plain HTTP to Envoy sidecar, mTLS handled transparently")
	fmt.Println()

	if *showSelf {
		printSelfIdentity(*jsonOut)
		if *queryAPI {
			fmt.Println()
		}
	}

	if *queryAPI {
		queryAPIServiceData(*jsonOut)
	}

	fmt.Println()
	fmt.Println("✅ CLI operations completed successfully")
}
