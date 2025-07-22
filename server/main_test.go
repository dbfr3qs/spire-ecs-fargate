package main

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/go-hclog"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestPlugin(t *testing.T) {
	t.Run("TestConfigure", testConfigure)
	t.Run("TestConfigureDefaults", testConfigureDefaults)
	t.Run("TestConfigureInvalidConfig", testConfigureInvalidConfig)
	t.Run("TestValidate", testValidate)
	t.Run("TestValidateInvalidConfig", testValidateInvalidConfig)
	t.Run("TestAttest", testAttest)
	t.Run("TestAttestInvalidData", testAttestInvalidData)
	t.Run("TestAttestNotConfigured", testAttestNotConfigured)
	t.Run("TestExtractAccountIDFromTaskARN", testExtractAccountIDFromTaskARN)
	t.Run("TestIsAccountIDAllowed", testIsAccountIDAllowed)
	t.Run("TestIsClusterAllowed", testIsClusterAllowed)
	t.Run("TestGenerateSpiffeID", testGenerateSpiffeID)
	t.Run("TestValidateAndFilterSelectors", testValidateAndFilterSelectors)
	t.Run("TestGenerateSelectors", testGenerateSelectors)
}

func testConfigure(t *testing.T) {
	tests := []struct {
		name           string
		hclConfig      string
		expectError    bool
		expectedConfig *FargateAttestorConfig
	}{
		{
			name: "valid configuration",
			hclConfig: `
				trust_domain = "example.org"
				allowed_accounts = ["123456789012", "987654321098"]
				allowed_clusters = ["test-cluster", "prod-cluster"]
				agent_path_template = "/aws_fargate_task/{{ .accountID }}/{{ .cluster }}"
			`,
			expectError: false,
			expectedConfig: &FargateAttestorConfig{
				TrustDomain:       "example.org",
				AllowedAccounts:   []string{"123456789012", "987654321098"},
				AllowedClusters:   []string{"test-cluster", "prod-cluster"},
				AgentPathTemplate: "/aws_fargate_task/{{ .accountID }}/{{ .cluster }}",
			},
		},
		{
			name: "minimal configuration",
			hclConfig: `
				trust_domain = "example.org"
			`,
			expectError: false,
			expectedConfig: &FargateAttestorConfig{
				TrustDomain:        "example.org",
				AllowedAccounts:    nil, // HCL decoding results in nil for empty slices
				AllowedClusters:    nil, // HCL decoding results in nil for empty slices
				AgentPathTemplate:  "/aws_fargate_task/{{ .accountID }}/{{ .cluster }}", // Default value
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &Plugin{}
			plugin.SetLogger(hclog.NewNullLogger())

			req := &configv1.ConfigureRequest{
				HclConfiguration: tt.hclConfig,
			}

			resp, err := plugin.Configure(context.Background(), req)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)

				config, err := plugin.getConfig()
				require.NoError(t, err)
				assert.Equal(t, tt.expectedConfig.TrustDomain, config.TrustDomain)
				assert.ElementsMatch(t, tt.expectedConfig.AllowedAccounts, config.AllowedAccounts)
				assert.ElementsMatch(t, tt.expectedConfig.AllowedClusters, config.AllowedClusters)
				assert.Equal(t, tt.expectedConfig.AgentPathTemplate, config.AgentPathTemplate)
			}
		})
	}
}

func testConfigureDefaults(t *testing.T) {
	plugin := &Plugin{}
	plugin.SetLogger(hclog.NewNullLogger())

	req := &configv1.ConfigureRequest{
		HclConfiguration: `trust_domain = "example.org"`,
	}

	resp, err := plugin.Configure(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	config, err := plugin.getConfig()
	require.NoError(t, err)
	assert.Equal(t, "example.org", config.TrustDomain)
	assert.Nil(t, config.AllowedAccounts) // HCL decoding results in nil for empty slices
	assert.Nil(t, config.AllowedClusters) // HCL decoding results in nil for empty slices
	assert.Equal(t, "/aws_fargate_task/{{ .accountID }}/{{ .cluster }}", config.AgentPathTemplate) // Default value
}

func testConfigureInvalidConfig(t *testing.T) {
	plugin := &Plugin{}
	plugin.SetLogger(hclog.NewNullLogger())

	req := &configv1.ConfigureRequest{
		HclConfiguration: `invalid_hcl_syntax`,
	}

	resp, err := plugin.Configure(context.Background(), req)
	assert.Error(t, err)
	assert.Nil(t, resp)
}

func testValidate(t *testing.T) {
	plugin := &Plugin{}
	plugin.SetLogger(hclog.NewNullLogger())

	req := &configv1.ValidateRequest{
		HclConfiguration: `
			trust_domain = "example.org"
			allowed_accounts = ["123456789012"]
			allowed_clusters = ["test-cluster"]
		`,
	}

	resp, err := plugin.Validate(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Valid)
}

func testValidateInvalidConfig(t *testing.T) {
	plugin := &Plugin{}
	plugin.SetLogger(hclog.NewNullLogger())

	req := &configv1.ValidateRequest{
		HclConfiguration: `invalid_hcl_syntax`,
	}

	resp, err := plugin.Validate(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.Valid)
}

func testAttest(t *testing.T) {
	plugin := &Plugin{}
	plugin.SetLogger(hclog.NewNullLogger())

	// Configure the plugin first
	configReq := &configv1.ConfigureRequest{
		HclConfiguration: `
			trust_domain = "example.org"
			allowed_accounts = ["123456789012"]
			allowed_clusters = ["test-cluster"]
			agent_path_template = "/aws_fargate_task/{{ .accountID }}/{{ .cluster }}"
		`,
	}
	_, err := plugin.Configure(context.Background(), configReq)
	require.NoError(t, err)

	// Create test attestation data
	metadata := createValidTaskMetadata()
	attestationData := FargateAttestationData{
		TaskMetadata: metadata,
		Selectors:    []string{"aws:cluster:test-cluster", "aws:account_id:123456789012"},
	}
	attestationPayload, err := json.Marshal(attestationData)
	require.NoError(t, err)

	// Create mock stream
	stream := &mockAttestStream{
		ctx: context.Background(),
		payload: attestationPayload,
	}

	// Test attestation
	err = plugin.Attest(stream)
	assert.NoError(t, err)
	assert.Len(t, stream.responses, 1)

	resp := stream.responses[0]
	assert.NotNil(t, resp.GetAgentAttributes())
	assert.True(t, resp.GetAgentAttributes().CanReattest)
	assert.NotEmpty(t, resp.GetAgentAttributes().SpiffeId)
	assert.NotEmpty(t, resp.GetAgentAttributes().SelectorValues)
}

func testAttestInvalidData(t *testing.T) {
	plugin := &Plugin{}
	plugin.SetLogger(hclog.NewNullLogger())

	// Configure the plugin first
	configReq := &configv1.ConfigureRequest{
		HclConfiguration: `trust_domain = "example.org"`,
	}
	_, err := plugin.Configure(context.Background(), configReq)
	require.NoError(t, err)

	// Create invalid attestation data
	invalidPayload := []byte(`{"invalid": "json"}`)

	stream := &mockAttestStream{
		ctx: context.Background(),
		payload: invalidPayload,
	}

	err = plugin.Attest(stream)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal task metadata")
}

func testAttestNotConfigured(t *testing.T) {
	plugin := &Plugin{}
	plugin.SetLogger(hclog.NewNullLogger())

	stream := &mockAttestStream{
		ctx: context.Background(),
		payload: []byte(`{}`),
	}

	err := plugin.Attest(stream)
	assert.Error(t, err)
	st := status.Convert(err)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
}

func testExtractAccountIDFromTaskARN(t *testing.T) {
	plugin := &Plugin{}

	tests := []struct {
		name        string
		taskARN     string
		expectedID  string
		expectError bool
	}{
		{
			name:        "valid task ARN",
			taskARN:     "arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123def456",
			expectedID:  "123456789012",
			expectError: false,
		},
		{
			name:        "invalid task ARN format",
			taskARN:     "invalid-arn",
			expectedID:  "",
			expectError: true,
		},
		{
			name:        "empty task ARN",
			taskARN:     "",
			expectedID:  "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accountID, err := plugin.extractAccountIDFromTaskARN(tt.taskARN)

			if tt.expectError {
				assert.Error(t, err)
				assert.Empty(t, accountID)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedID, accountID)
			}
		})
	}
}

func testIsAccountIDAllowed(t *testing.T) {
	plugin := &Plugin{}

	tests := []struct {
		name            string
		config          *FargateAttestorConfig
		accountID       string
		expectedAllowed bool
	}{
		{
			name: "account in allowed list",
			config: &FargateAttestorConfig{
				AllowedAccounts: []string{"123456789012", "987654321098"},
			},
			accountID:       "123456789012",
			expectedAllowed: true,
		},
		{
			name: "account not in allowed list",
			config: &FargateAttestorConfig{
				AllowedAccounts: []string{"123456789012", "987654321098"},
			},
			accountID:       "111111111111",
			expectedAllowed: false,
		},
		{
			name: "empty allowed list allows all",
			config: &FargateAttestorConfig{
				AllowedAccounts: []string{},
			},
			accountID:       "123456789012",
			expectedAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := plugin.isAccountIDAllowed(tt.config, tt.accountID)
			assert.Equal(t, tt.expectedAllowed, allowed)
		})
	}
}

func testIsClusterAllowed(t *testing.T) {
	plugin := &Plugin{}

	tests := []struct {
		name            string
		config          *FargateAttestorConfig
		cluster         string
		expectedAllowed bool
	}{
		{
			name: "cluster in allowed list",
			config: &FargateAttestorConfig{
				AllowedClusters: []string{"test-cluster", "prod-cluster"},
			},
			cluster:         "test-cluster",
			expectedAllowed: true,
		},
		{
			name: "cluster not in allowed list",
			config: &FargateAttestorConfig{
				AllowedClusters: []string{"test-cluster", "prod-cluster"},
			},
			cluster:         "dev-cluster",
			expectedAllowed: false,
		},
		{
			name: "empty allowed list allows all",
			config: &FargateAttestorConfig{
				AllowedClusters: []string{},
			},
			cluster:         "any-cluster",
			expectedAllowed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allowed := plugin.isClusterAllowed(tt.config, tt.cluster)
			assert.Equal(t, tt.expectedAllowed, allowed)
		})
	}
}

func testGenerateSpiffeID(t *testing.T) {
	plugin := &Plugin{}

	config := &FargateAttestorConfig{
		TrustDomain:       "example.org",
		AgentPathTemplate: "/aws_fargate_task/{{ .accountID }}/{{ .cluster }}",
	}

	metadata := &FargateTaskMetadata{
		Cluster: "test-cluster",
		TaskARN: "arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123def456",
	}

	spiffeID, err := plugin.generateSpiffeID(config, "123456789012", metadata)
	assert.NoError(t, err)
	assert.Equal(t, "spiffe://example.org/aws_fargate_task/123456789012/test-cluster", spiffeID.String())
}

func testValidateAndFilterSelectors(t *testing.T) {
	plugin := &Plugin{}
	plugin.SetLogger(hclog.NewNullLogger()) // Set logger to prevent nil pointer dereference

	metadata := &FargateTaskMetadata{
		Cluster:     "test-cluster",
		TaskARN:     "arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123def456",
		Family:      "test-family",
		ServiceName: "test-service",
	}

	tests := []struct {
		name              string
		agentSelectors    []string
		expectedSelectors []string
	}{
		{
			name: "valid selectors",
			agentSelectors: []string{
				"aws_fargate:cluster:test-cluster",
				"aws_fargate:account_id:123456789012",
				"unix:uid:0",
			},
			expectedSelectors: []string{
				"aws_fargate:cluster:test-cluster",
				"aws_fargate:account_id:123456789012",
				"unix:uid:0",
			},
		},
		{
			name: "invalid selectors filtered out",
			agentSelectors: []string{
				"aws_fargate:cluster:test-cluster",
				"invalid:format",
				"unknown:selector:value",
			},
			expectedSelectors: []string{
				"aws_fargate:cluster:test-cluster",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := plugin.validateAndFilterSelectors(tt.agentSelectors, "123456789012", metadata)
			assert.Equal(t, tt.expectedSelectors, filtered)
		})
	}
}

func testGenerateSelectors(t *testing.T) {
	plugin := &Plugin{}

	metadata := &FargateTaskMetadata{
		Cluster:           "test-cluster",
		TaskARN:           "arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123def456",
		Family:            "test-family",
		Revision:          "1",
		ServiceName:       "test-service",
		LaunchType:        "FARGATE",
		AvailabilityZone:  "us-east-1a",
		TaskDefinitionArn: "arn:aws:ecs:us-east-1:123456789012:task-definition/test-family:1",
		TaskTags: map[string]string{
			"Environment": "test",
			"Team":        "backend",
		},
	}

	selectors := plugin.generateSelectors("123456789012", metadata)

	expectedSelectors := []string{
		"aws_fargate_task:account:123456789012",
		"aws_fargate_task:cluster:test-cluster",
		"aws_fargate_task:family:test-family",
		"aws_fargate_task:revision:1",
		"aws_fargate_task:service:test-service",
		"aws_fargate_task:az:us-east-1a",
		"aws_fargate_task:launch_type:FARGATE",
		"aws_fargate_task:task_definition_arn:arn:aws:ecs:us-east-1:123456789012:task-definition/test-family:1",
		"aws_fargate_task:tag:Environment:test",
		"aws_fargate_task:tag:Team:backend",
	}

	assert.ElementsMatch(t, expectedSelectors, selectors)
}

// Test helpers

func createValidTaskMetadata() string {
	metadata := FargateTaskMetadata{
		Cluster:           "test-cluster",
		TaskARN:           "arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123def456",
		Family:            "test-family",
		Revision:          "1",
		ServiceName:       "test-service",
		LaunchType:        "FARGATE",
		AvailabilityZone:  "us-east-1a",
		TaskDefinitionArn: "arn:aws:ecs:us-east-1:123456789012:task-definition/test-family:1",
		TaskTags: map[string]string{
			"Environment": "test",
			"Team":        "backend",
		},
	}

	data, _ := json.Marshal(metadata)
	return string(data)
}

// Mock implementation of nodeattestorv1.NodeAttestor_AttestServer
type mockAttestStream struct {
	ctx       context.Context
	payload   []byte
	responses []*nodeattestorv1.AttestResponse
}

func (m *mockAttestStream) Send(response *nodeattestorv1.AttestResponse) error {
	m.responses = append(m.responses, response)
	return nil
}

func (m *mockAttestStream) Recv() (*nodeattestorv1.AttestRequest, error) {
	return &nodeattestorv1.AttestRequest{
		Request: &nodeattestorv1.AttestRequest_Payload{
			Payload: m.payload,
		},
	}, nil
}

func (m *mockAttestStream) Context() context.Context {
	return m.ctx
}

// Additional methods required by grpc.ServerStream interface
func (m *mockAttestStream) SetHeader(md metadata.MD) error {
	return nil
}

func (m *mockAttestStream) SendHeader(md metadata.MD) error {
	return nil
}

func (m *mockAttestStream) SetTrailer(md metadata.MD) {}

func (m *mockAttestStream) SendMsg(msg interface{}) error {
	return nil
}

func (m *mockAttestStream) RecvMsg(msg interface{}) error {
	return nil
}
