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

// FargateAttestorConfig holds plugin configuration.
type FargateAttestorConfig struct {
	MetadataEndpoint string        `hcl:"metadata_endpoint"`
	Timeout          time.Duration `hcl:"-"`
}

// FargateAttestorHCLConfig represents HCL configuration for parsing.
type FargateAttestorHCLConfig struct {
	MetadataEndpoint string `hcl:"metadata_endpoint"`
	Timeout          string `hcl:"timeout"`
}

// Plugin implements NodeAttestor for AWS Fargate tasks.
type Plugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	configMtx sync.RWMutex
	config    *FargateAttestorConfig
	logger    hclog.Logger
}

// FargateTaskMetadata represents ECS Task Metadata v4 structure.
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

// FargateContainerInfo represents container information from ECS Task Metadata.
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

// FargateAttestationData represents attestation data sent to server.
type FargateAttestationData struct {
	TaskMetadata string   `json:"task_metadata"`
	Selectors    []string `json:"selectors"`
}

// AidAttestation facilitates attestation by returning the attestation payload.
func (p *Plugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	p.logger.Debug("Starting Fargate attestation")

	taskMetadata, err := p.fetchTaskMetadata(stream.Context(), config)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to fetch task metadata: %v", err)
	}

	p.logger.Debug("Successfully fetched task metadata", "cluster", taskMetadata.Cluster, "taskArn", taskMetadata.TaskARN)

	attestationData, err := p.buildAttestationData(taskMetadata)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to build attestation data: %v", err)
	}

	if err := p.sendAttestationData(stream, attestationData); err != nil {
		return err
	}

	return p.handleChallenges(stream)
}

func (p *Plugin) buildAttestationData(taskMetadata *FargateTaskMetadata) (*FargateAttestationData, error) {
	taskMetadataJSON, err := json.Marshal(taskMetadata)
	if err != nil {
		return nil, err
	}

	selectors := p.extractSelectors(taskMetadata)

	return &FargateAttestationData{
		TaskMetadata: string(taskMetadataJSON),
		Selectors:    selectors,
	}, nil
}

func (p *Plugin) sendAttestationData(stream nodeattestorv1.NodeAttestor_AidAttestationServer, attestationData *FargateAttestationData) error {
	attestationDataJSON, err := json.Marshal(attestationData)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to marshal attestation data: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: attestationDataJSON,
		},
	}); err != nil {
		return status.Errorf(codes.Internal, "failed to send attestation data: %v", err)
	}

	p.logger.Debug("Sent attestation data to server")

	return nil
}

func (p *Plugin) handleChallenges(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
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

// fetchTaskMetadata retrieves ECS Task Metadata from the v4 endpoint.
func (p *Plugin) fetchTaskMetadata(ctx context.Context, config *FargateAttestorConfig) (*FargateTaskMetadata, error) {
	endpoint := config.MetadataEndpoint
	if endpoint == "" {
		endpoint = os.Getenv("ECS_CONTAINER_METADATA_URI_V4")
		if endpoint == "" {
			return nil, fmt.Errorf("no metadata endpoint configured and ECS_CONTAINER_METADATA_URI_V4 not set")
		}
	}

	p.logger.Debug("Fetching task metadata", "endpoint", endpoint)

	client := &http.Client{Timeout: config.Timeout}
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch metadata: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("metadata endpoint returned status %d", resp.StatusCode)
	}

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

// extractSelectors extracts selectors from ECS task metadata for workload identity.
func (p *Plugin) extractSelectors(metadata *FargateTaskMetadata) []string {
	var selectors []string

	selectors = append(selectors, p.extractTaskSelectors(metadata)...)
	selectors = append(selectors, p.extractARNSelectors(metadata.TaskARN)...)
	selectors = append(selectors, p.extractTagSelectors(metadata.TaskTags)...)
	selectors = append(selectors, p.extractContainerSelectors(metadata.Containers)...)

	return selectors
}

func (p *Plugin) extractTaskSelectors(metadata *FargateTaskMetadata) []string {
	var selectors []string

	fields := map[string]string{
		"cluster":                    metadata.Cluster,
		"service":                    metadata.ServiceName,
		"task_definition":            metadata.Family,
		"task_definition_revision":   metadata.Revision,
		"availability_zone":          metadata.AvailabilityZone,
		"launch_type":               metadata.LaunchType,
	}

	for key, value := range fields {
		if value != "" {
			selectors = append(selectors, fmt.Sprintf("aws_fargate:%s:%s", key, value))
		}
	}

	return selectors
}

func (p *Plugin) extractARNSelectors(taskARN string) []string {
	var selectors []string

	if taskARN == "" {
		return selectors
	}

	selectors = append(selectors, fmt.Sprintf("aws_fargate:task_arn:%s", taskARN))

	if parts := strings.Split(taskARN, ":"); len(parts) >= 5 {
		if region := parts[3]; region != "" {
			selectors = append(selectors, fmt.Sprintf("aws_fargate:region:%s", region))
		}
		if accountID := parts[4]; accountID != "" {
			selectors = append(selectors, fmt.Sprintf("aws_fargate:account:%s", accountID))
		}
	}

	return selectors
}

func (p *Plugin) extractTagSelectors(tags map[string]string) []string {
	var selectors []string

	for key, value := range tags {
		if key != "" && value != "" {
			selectors = append(selectors, fmt.Sprintf("aws_fargate:tag:%s:%s", key, value))
		}
	}

	return selectors
}

func (p *Plugin) extractContainerSelectors(containers []FargateContainerInfo) []string {
	var selectors []string

	for _, container := range containers {
		if container.Name != "" {
			selectors = append(selectors, fmt.Sprintf("aws_fargate:container:%s", container.Name))
		}
		if container.Image != "" {
			selectors = append(selectors, fmt.Sprintf("aws_fargate:image:%s", container.Image))
		}

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
