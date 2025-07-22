package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName             = "aws_fargate_task"
	defaultMetadataTimeout = 30 * time.Second
)

// FargateAttestorConfig configures the FargateAttestorPlugin.
type FargateAttestorConfig struct {
	MetadataEndpoint string        `hcl:"metadata_endpoint"`
	Timeout          time.Duration `hcl:"-"` // Set programmatically after parsing
}

// FargateAttestorHCLConfig represents the HCL configuration structure
type FargateAttestorHCLConfig struct {
	MetadataEndpoint string `hcl:"metadata_endpoint"`
	Timeout          string `hcl:"timeout"`
}

// Plugin implements the NodeAttestor plugin for AWS Fargate
type Plugin struct {
	// UnimplementedNodeAttestorServer is embedded to satisfy gRPC
	nodeattestorv1.UnimplementedNodeAttestorServer

	// UnimplementedConfigServer is embedded to satisfy gRPC
	configv1.UnimplementedConfigServer

	// Configuration should be set atomically
	configMtx sync.RWMutex
	config    *FargateAttestorConfig

	// The logger received from the framework via the SetLogger method
	logger hclog.Logger
}

// FargateTaskMetadata represents the ECS Task Metadata v4 structure
type FargateTaskMetadata struct {
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
	Containers        []FargateContainerInfo `json:"Containers"`
	TaskDefinitionArn string                 `json:"TaskDefinitionArn"`
}

// FargateContainerInfo represents container information from ECS Task Metadata
type FargateContainerInfo struct {
	DockerID      string            `json:"DockerId"`
	Name          string            `json:"Name"`
	DockerName    string            `json:"DockerName"`
	Image         string            `json:"Image"`
	ImageID       string            `json:"ImageID"`
	Labels        map[string]string `json:"Labels"`
	DesiredStatus string            `json:"DesiredStatus"`
	KnownStatus   string            `json:"KnownStatus"`
	Type          string            `json:"Type"`
}

// FargateAttestationData represents the data sent to the server for attestation
type FargateAttestationData struct {
	TaskMetadata string   `json:"task_metadata"`
	Selectors    []string `json:"selectors"`
}

// AidAttestation implements the NodeAttestor AidAttestation RPC. AidAttestation facilitates attestation by returning
// the attestation payload and participating in attestation challenge/response.
func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	p.logger.Debug("Starting Fargate attestation")

	// Fetch task metadata from ECS metadata endpoint
	taskMetadata, err := p.fetchTaskMetadata(stream.Context(), config)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to fetch task metadata: %v", err)
	}

	p.logger.Debug("Successfully fetched task metadata", "cluster", taskMetadata.Cluster, "taskArn", taskMetadata.TaskARN)

	// Marshal the task metadata as JSON
	taskMetadataJSON, err := json.Marshal(taskMetadata)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal task metadata: %v", err)
	}

	// Extract selectors from task metadata for workload identity
	selectors := p.extractSelectors(taskMetadata)
	p.logger.Debug("Extracted selectors from task metadata", "count", len(selectors), "selectors", selectors)

	// Create attestation data with both raw metadata and extracted selectors
	attestationData := &FargateAttestationData{
		TaskMetadata: string(taskMetadataJSON),
		Selectors:    selectors,
	}

	attestationDataJSON, err := json.Marshal(attestationData)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal attestation data: %v", err)
	}

	// Send the attestation data to the server
	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: attestationDataJSON,
		},
	}); err != nil {
		return status.Errorf(codes.Internal, "failed to send attestation data: %v", err)
	}

	p.logger.Debug("Sent attestation data to server")

	// The server may send challenges, but for Fargate attestation we don't expect any
	for {
		req, err := stream.Recv()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return status.Errorf(codes.Internal, "failed to receive from stream: %v", err)
		}

		if challenge := req.GetChallenge(); challenge != nil {
			return status.Error(codes.Internal, "unexpected challenge from server during Fargate attestation")
		}
	}
}

// fetchTaskMetadata retrieves the ECS Task Metadata from the v4 endpoint
func (p *Plugin) fetchTaskMetadata(ctx context.Context, config *FargateAttestorConfig) (*FargateTaskMetadata, error) {
	// Use the configured endpoint or fall back to the environment variable
	metadataEndpoint := config.MetadataEndpoint
	if metadataEndpoint == "" {
		metadataEndpoint = os.Getenv("ECS_CONTAINER_METADATA_URI_V4")
		if metadataEndpoint == "" {
			return nil, fmt.Errorf("no metadata endpoint configured and ECS_CONTAINER_METADATA_URI_V4 not set")
		}
	}

	// Use the metadata endpoint directly - it should already be the full URL
	metadataURL := metadataEndpoint

	p.logger.Debug("Fetching task metadata", "endpoint", metadataURL)

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: config.Timeout,
	}

	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Make the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata endpoint returned status %d", resp.StatusCode)
	}

	// Read and parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	var taskMetadata FargateTaskMetadata
	if err := json.Unmarshal(body, &taskMetadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal task metadata: %v", err)
	}

	return &taskMetadata, nil
}

// Configure configures the plugin. This is invoked by SPIRE when the plugin is
// first loaded. In the future, it may be invoked to reconfigure the plugin.
func (p *Plugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config, err := p.buildConfig(req)
	if err != nil {
		return nil, err
	}

	p.setConfig(config)
	return &configv1.ConfigureResponse{}, nil
}

// buildConfig parses the HCL configuration
func (p *Plugin) buildConfig(req *configv1.ConfigureRequest) (*FargateAttestorConfig, error) {
	// First parse the HCL into the intermediate structure
	hclConfig := &FargateAttestorHCLConfig{}
	if err := hcl.Decode(hclConfig, req.HclConfiguration); err != nil {
		return nil, fmt.Errorf("unable to decode configuration: %v", err)
	}

	// Convert to the final configuration structure
	newConfig := &FargateAttestorConfig{
		MetadataEndpoint: hclConfig.MetadataEndpoint,
		Timeout:          defaultMetadataTimeout, // Default
	}

	// Parse timeout if provided
	if hclConfig.Timeout != "" {
		timeout, err := time.ParseDuration(hclConfig.Timeout)
		if err != nil {
			return nil, fmt.Errorf("unable to parse timeout duration: %v", err)
		}
		newConfig.Timeout = timeout
	}

	return newConfig, nil
}

// extractSelectors extracts meaningful selectors from ECS task metadata for workload identity
func (p *Plugin) extractSelectors(metadata *FargateTaskMetadata) []string {
	var selectors []string

	// High-value selectors for strong identity guarantees
	if metadata.Cluster != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate:cluster:%s", metadata.Cluster))
	}

	if metadata.ServiceName != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate:service:%s", metadata.ServiceName))
	}

	if metadata.Family != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate:task_definition:%s", metadata.Family))
	}

	if metadata.Revision != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate:task_definition_revision:%s", metadata.Revision))
	}

	if metadata.AvailabilityZone != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate:availability_zone:%s", metadata.AvailabilityZone))
	}

	if metadata.LaunchType != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate:launch_type:%s", metadata.LaunchType))
	}

	// Extract account ID and region from TaskARN
	if metadata.TaskARN != "" {
		// TaskARN format: arn:aws:ecs:region:account-id:task/cluster-name/task-id
		if parts := strings.Split(metadata.TaskARN, ":"); len(parts) >= 5 {
			if region := parts[3]; region != "" {
				selectors = append(selectors, fmt.Sprintf("aws_fargate:region:%s", region))
			}
			if accountID := parts[4]; accountID != "" {
				selectors = append(selectors, fmt.Sprintf("aws_fargate:account:%s", accountID))
			}
		}
		selectors = append(selectors, fmt.Sprintf("aws_fargate:task_arn:%s", metadata.TaskARN))
	}

	// Extract task tags for custom business logic
	for key, value := range metadata.TaskTags {
		if key != "" && value != "" {
			selectors = append(selectors, fmt.Sprintf("aws_fargate:tag:%s:%s", key, value))
		}
	}

	// Extract container information
	for _, container := range metadata.Containers {
		if container.Name != "" {
			selectors = append(selectors, fmt.Sprintf("aws_fargate:container:%s", container.Name))
		}
		if container.Image != "" {
			selectors = append(selectors, fmt.Sprintf("aws_fargate:image:%s", container.Image))
		}
		// Extract container labels
		for key, value := range container.Labels {
			if key != "" && value != "" {
				selectors = append(selectors, fmt.Sprintf("aws_fargate:container_label:%s:%s", key, value))
			}
		}
	}

	return selectors
}

// SetLogger is called by the framework when the plugin is loaded and provides
// the plugin with a logger wired up to SPIRE's logging facilities.
func (p *Plugin) SetLogger(logger hclog.Logger) {
	p.logger = logger
}

// setConfig replaces the configuration atomically under a write lock.
func (p *Plugin) setConfig(config *FargateAttestorConfig) {
	p.configMtx.Lock()
	defer p.configMtx.Unlock()
	p.config = config
}

// getConfig gets the configuration under a read lock.
func (p *Plugin) getConfig() (*FargateAttestorConfig, error) {
	p.configMtx.RLock()
	defer p.configMtx.RUnlock()

	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "plugin not configured")
	}
	return p.config, nil
}

func main() {
	plugin := new(Plugin)
	// Serve the plugin. This function call will not return. If there is a
	// failure to serve, the process will exit with a non-zero exit code.
	pluginmain.Serve(
		nodeattestorv1.NodeAttestorPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)
}
