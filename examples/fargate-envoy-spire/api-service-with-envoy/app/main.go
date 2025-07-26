package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
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

type APIServiceResponse struct {
	ServiceName string     `json:"service_name"`
	Version     string     `json:"version"`
	Timestamp   time.Time  `json:"timestamp"`
	Status      string     `json:"status"`
	Data        *SPIREInfo `json:"data"`
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

	// Get JWT SVID
	jwtSource, err := workloadapi.NewJWTSource(ctx, workloadapi.WithClientOptions(workloadapi.WithAddr("unix:///tmp/spire-agent/public/api.sock")))
	if err == nil {
		defer jwtSource.Close()
		jwtSVID, err := jwtSource.FetchJWTSVID(ctx, jwtsvid.Params{Audience: "api-service"})
		if err == nil {
			certInfo := &SPIREInfo{
				SPIFFEID:          svid.ID.String(),
				X509SVIDParsed:    certInfo,
				JWTSVID:           jwtSVID.Marshal(),
				AttestationStatus: "SUCCESS",
			}
			
			// Get ECS metadata
			if ecsMetadata, err := getECSMetadata(); err == nil {
				certInfo.ECSMetadata = ecsMetadata
				certInfo.PotentialSelectors = generatePotentialSelectors(ecsMetadata)
			}
			
			return certInfo
		}
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

// Simplified attestation handler - no mTLS complexity, receives plain HTTP from Envoy
func attestationHandler(w http.ResponseWriter, r *http.Request) {
	// Enable CORS for cross-origin requests
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Content-Type", "application/json")

	// Handle preflight requests
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	log.Printf("📡 Received attestation request from %s", r.RemoteAddr)
	log.Printf("🔍 Headers: %v", r.Header)
	
	// Note: mTLS authentication is handled by Envoy sidecar
	// The request reaches here only if Envoy successfully validated the client certificate
	
	spireInfo := getSPIREInfo()
	
	response := APIServiceResponse{
		ServiceName: "api-service-with-envoy",
		Version:     "2.0.0-envoy",
		Timestamp:   time.Now(),
		Status:      "success",
		Data:        spireInfo,
	}

	log.Printf("✅ Sending attestation response for SPIFFE ID: %s", spireInfo.SPIFFEID)
	
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("❌ Failed to encode response: %v", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	health := map[string]interface{}{
		"status":    "healthy",
		"service":   "api-service-with-envoy",
		"version":   "2.0.0-envoy",
		"timestamp": time.Now(),
		"transport": "Plain HTTP (mTLS handled by Envoy sidecar)",
	}
	
	json.NewEncoder(w).Encode(health)
}

func main() {
	log.Println("🚀 Starting SPIRE Envoy API Service...")
	log.Println("🌐 Architecture: Plain HTTP from Envoy sidecar, mTLS handled transparently")
	
	http.HandleFunc("/attestation", attestationHandler)
	http.HandleFunc("/health", healthHandler)
	
	// Default handler for debugging
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		info := map[string]interface{}{
			"service":     "api-service-with-envoy",
			"version":     "2.0.0-envoy",
			"timestamp":   time.Now(),
			"description": "SPIRE Envoy Service Mesh API Service",
			"transport":   "Plain HTTP (mTLS handled by Envoy sidecar)",
			"endpoints": []string{
				"/attestation - Get SPIRE attestation data",
				"/health - Health check",
			},
		}
		
		json.NewEncoder(w).Encode(info)
	})
	
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}
	
	log.Printf("🌍 API service starting on port %s", port)
	log.Printf("🔗 Available endpoints:")
	log.Printf("  • http://localhost:%s/attestation - SPIRE attestation data", port)
	log.Printf("  • http://localhost:%s/health - Health check", port)
	log.Printf("  • http://localhost:%s/ - Service information", port)
	log.Printf("🔐 Security: mTLS authentication handled by Envoy sidecar")
	
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
