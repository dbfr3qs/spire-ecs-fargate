package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/hcl"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/spire-plugin-sdk/pluginmain"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	pluginName = "aws_fargate_task"
)

// FargateAttestorConfig holds configuration for the Fargate attestor plugin
type FargateAttestorConfig struct {
	TrustDomain     string   `hcl:"trust_domain"`
	AllowedAccounts []string `hcl:"allowed_accounts"`
	AllowedClusters []string `hcl:"allowed_clusters"`
	AgentPathTemplate string `hcl:"agent_path_template"`
}

// FargateTaskMetadata represents the ECS Task Metadata v4 structure we care about
type FargateTaskMetadata struct {
	Cluster           string            `json:"Cluster"`
	TaskARN           string            `json:"TaskARN"`
	Family            string            `json:"Family"`
	Revision          string            `json:"Revision"`
	ServiceName       string            `json:"ServiceName"`
	LaunchType        string            `json:"LaunchType"`
	AvailabilityZone  string            `json:"AvailabilityZone"`
	TaskTags          map[string]string `json:"TaskTags"`
	TaskDefinitionArn string            `json:"TaskDefinitionArn"`
}

// FargateAttestationData represents the data sent by the agent for attestation
type FargateAttestationData struct {
	TaskMetadata string   `json:"task_metadata"`
	Selectors    []string `json:"selectors"`
}

// Plugin implements the NodeAttestor plugin for AWS Fargate (server side)
type Plugin struct {
	// UnimplementedNodeAttestorServer is embedded to satisfy gRPC
	nodeattestorv1.UnimplementedNodeAttestorServer

	// UnimplementedConfigServer is embedded to satisfy gRPC
	configv1.UnimplementedConfigServer

	log    hclog.Logger
	config *FargateAttestorConfig
	mtx    sync.RWMutex
}

// Attest implements the server side logic for the AWS Fargate task node attestation plugin.
func (p *Plugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	config, err := p.getConfig()
	if err != nil {
		return err
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	// Parse attestation data from agent
	payload := req.GetPayload()
	if payload == nil {
		return status.Error(codes.InvalidArgument, "missing attestation payload")
	}

	var attestationData FargateAttestationData
	if err := json.Unmarshal(payload, &attestationData); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal attestation data: %v", err)
	}

	// Parse task metadata
	var metadata FargateTaskMetadata
	if err := json.Unmarshal([]byte(attestationData.TaskMetadata), &metadata); err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to unmarshal task metadata: %v", err)
	}

	// Extract account ID from Task ARN
	accountID, err := p.extractAccountIDFromTaskARN(metadata.TaskARN)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "failed to extract account ID from Task ARN: %v", err)
	}

	// Validate account is allowed
	if !p.isAccountIDAllowed(config, accountID) {
		return status.Errorf(codes.PermissionDenied, "account ID %s is not allowed", accountID)
	}

	// Validate cluster is allowed
	if !p.isClusterAllowed(config, metadata.Cluster) {
		return status.Errorf(codes.PermissionDenied, "cluster %s is not allowed", metadata.Cluster)
	}

	// Generate SPIFFE ID
	spiffeID, err := p.generateSpiffeID(config, accountID, &metadata)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to generate SPIFFE ID: %v", err)
	}

	// Validate and filter selectors
	selectors := p.validateAndFilterSelectors(attestationData.Selectors, accountID, &metadata)

	// Generate additional selectors
	additionalSelectors := p.generateSelectors(accountID, &metadata)
	selectors = append(selectors, additionalSelectors...)

	// DEBUG: Log that we're setting CanReattest to true
	if p.log != nil {
		p.log.Info("[DEBUG] Setting CanReattest=true for agent", "spiffe_id", spiffeID.String())
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				CanReattest: true,
				SpiffeId:    spiffeID.String(),
				SelectorValues: selectors,
			},
		},
	})
}

// Configure configures the FargateAttestorPlugin.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config, err := p.buildConfig(req)
	if err != nil {
		return nil, err
	}

	p.mtx.Lock()
	defer p.mtx.Unlock()

	p.config = config
	return &configv1.ConfigureResponse{}, nil
}

// Validate validates the configuration
func (p *Plugin) Validate(_ context.Context, req *configv1.ValidateRequest) (*configv1.ValidateResponse, error) {
	_, err := p.buildValidateConfig(req.HclConfiguration)
	if err != nil {
		return &configv1.ValidateResponse{
			Valid: false,
		}, nil
	}
	return &configv1.ValidateResponse{Valid: true}, nil
}

// SetLogger sets this plugin's logger
func (p *Plugin) SetLogger(log hclog.Logger) {
	p.log = log
}

func (p *Plugin) buildConfig(req *configv1.ConfigureRequest) (*FargateAttestorConfig, error) {
	config := new(FargateAttestorConfig)
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "trust_domain is required")
	}

	if config.AgentPathTemplate == "" {
		config.AgentPathTemplate = "/aws_fargate_task/{{ .accountID }}/{{ .cluster }}"
	}

	return config, nil
}

func (p *Plugin) getConfig() (*FargateAttestorConfig, error) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()

	if p.config == nil {
		return nil, status.Error(codes.FailedPrecondition, "not configured")
	}
	return p.config, nil
}

func (p *Plugin) buildValidateConfig(hclConfiguration string) (*FargateAttestorConfig, error) {
	config := new(FargateAttestorConfig)
	if err := hcl.Decode(config, hclConfiguration); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unable to decode configuration: %v", err)
	}

	if config.TrustDomain == "" {
		return nil, status.Error(codes.InvalidArgument, "trust_domain is required")
	}

	if config.AgentPathTemplate == "" {
		config.AgentPathTemplate = "/aws_fargate_task/{{ .accountID }}/{{ .cluster }}"
	}

	return config, nil
}

func (p *Plugin) extractAccountIDFromTaskARN(taskARN string) (string, error) {
	// Task ARN format: arn:aws:ecs:region:account-id:task/cluster-name/task-id
	parts := strings.Split(taskARN, ":")
	if len(parts) < 5 {
		return "", fmt.Errorf("invalid Task ARN format: %s", taskARN)
	}
	return parts[4], nil
}

func (p *Plugin) isAccountIDAllowed(config *FargateAttestorConfig, accountID string) bool {
	if len(config.AllowedAccounts) == 0 {
		return true // Allow all if not configured
	}

	for _, allowed := range config.AllowedAccounts {
		if allowed == accountID {
			return true
		}
	}
	return false
}

func (p *Plugin) isClusterAllowed(config *FargateAttestorConfig, cluster string) bool {
	if len(config.AllowedClusters) == 0 {
		return true // Allow all if not configured
	}

	for _, allowed := range config.AllowedClusters {
		if allowed == cluster {
			return true
		}
	}
	return false
}

func (p *Plugin) generateSpiffeID(config *FargateAttestorConfig, accountID string, metadata *FargateTaskMetadata) (spiffeid.ID, error) {
	// Simple template replacement for agent path
	agentPath := strings.ReplaceAll(config.AgentPathTemplate, "{{ .accountID }}", accountID)
	agentPath = strings.ReplaceAll(agentPath, "{{ .cluster }}", metadata.Cluster)

	td, err := spiffeid.TrustDomainFromString(config.TrustDomain)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("invalid trust domain: %v", err)
	}

	return spiffeid.FromPath(td, agentPath)
}

func (p *Plugin) validateAndFilterSelectors(agentSelectors []string, accountID string, metadata *FargateTaskMetadata) []string {
	var validSelectors []string

	for _, selector := range agentSelectors {
		// Agent sends selectors with aws_fargate: prefix
		if strings.HasPrefix(selector, "aws_fargate:") {
			// Accept all aws_fargate selectors from the agent
			validSelectors = append(validSelectors, selector)
			continue
		}

		// Handle other selector formats if needed
		parts := strings.SplitN(selector, ":", 2)
		if len(parts) != 2 {
			p.log.Warn("Invalid selector format, skipping", "selector", selector)
			continue
		}

		selectorType := parts[0]
		selectorValue := parts[1]

		switch selectorType {
		case "aws_fargate_task":
			// Validate aws_fargate_task selectors
			subParts := strings.SplitN(selectorValue, ":", 2)
			if len(subParts) == 2 {
				validSelectors = append(validSelectors, selector)
			}
		case "unix":
			// Accept standard unix selectors
			validSelectors = append(validSelectors, selector)
		default:
			p.log.Debug("Unknown selector type, skipping", "selector_type", selectorType, "selector", selector)
		}
	}

	return validSelectors
}

func (p *Plugin) generateSelectors(accountID string, metadata *FargateTaskMetadata) []string {
	var selectors []string

	// Add account selector
	selectors = append(selectors, fmt.Sprintf("aws_fargate_task:account:%s", accountID))

	// Add cluster selector
	if metadata.Cluster != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate_task:cluster:%s", metadata.Cluster))
	}

	// Add family selector
	if metadata.Family != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate_task:family:%s", metadata.Family))
	}

	// Add revision selector
	if metadata.Revision != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate_task:revision:%s", metadata.Revision))
	}

	// Add service selector
	if metadata.ServiceName != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate_task:service:%s", metadata.ServiceName))
	}

	// Add availability zone selector
	if metadata.AvailabilityZone != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate_task:az:%s", metadata.AvailabilityZone))
	}

	// Add launch type selector
	if metadata.LaunchType != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate_task:launch_type:%s", metadata.LaunchType))
	}

	// Add task definition ARN selector
	if metadata.TaskDefinitionArn != "" {
		selectors = append(selectors, fmt.Sprintf("aws_fargate_task:task_definition_arn:%s", metadata.TaskDefinitionArn))
	}

	// Add task tags as selectors
	for key, value := range metadata.TaskTags {
		selectors = append(selectors, fmt.Sprintf("aws_fargate_task:tag:%s:%s", key, value))
	}

	return selectors
}

func init() {
	// Emergency debug: Try to write from init() function
	if f, err := os.Create("/tmp/spire-plugin-init.log"); err == nil {
		f.WriteString(fmt.Sprintf("[INIT %s] Plugin init() function called\n", time.Now().Format("15:04:05")))
		f.Close()
	}
}

func main() {
	// Emergency debug: Force file creation with multiple attempts
	for i := 0; i < 3; i++ {
		if f, err := os.Create(fmt.Sprintf("/tmp/spire-plugin-main-%d.log", i)); err == nil {
			f.WriteString(fmt.Sprintf("[MAIN-%d %s] AWS Fargate server plugin main() executing - attempt %d\n", i, time.Now().Format("15:04:05"), i))
			f.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	// Try explicit plugin creation and serving
	plugin := &Plugin{}
	
	// Write final debug before serving
	if f, err := os.Create("/tmp/spire-plugin-serving.log"); err == nil {
		f.WriteString(fmt.Sprintf("[SERVING %s] About to call pluginmain.Serve\n", time.Now().Format("15:04:05")))
		f.Close()
	}

	// Serve the plugin with explicit error handling
	pluginmain.Serve(
		nodeattestorv1.NodeAttestorPluginServer(plugin),
		configv1.ConfigServiceServer(plugin),
	)

	// This should never be reached, but add debug just in case
	if f, err := os.Create("/tmp/spire-plugin-after-serve.log"); err == nil {
		f.WriteString(fmt.Sprintf("[AFTER %s] pluginmain.Serve returned (unexpected!)\n", time.Now().Format("15:04:05")))
		f.Close()
	}
}
