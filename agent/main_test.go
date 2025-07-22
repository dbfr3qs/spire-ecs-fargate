package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
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
	t.Run("TestConfigureInvalidTimeout", testConfigureInvalidTimeout)
	t.Run("TestAidAttestationSuccess", testAidAttestationSuccess)
	t.Run("TestAidAttestationMetadataTimeout", testAidAttestationMetadataTimeout)
	t.Run("TestAidAttestationMetadata404", testAidAttestationMetadata404)
	t.Run("TestAidAttestationMetadata500", testAidAttestationMetadata500)
	t.Run("TestAidAttestationInvalidJSON", testAidAttestationInvalidJSON)
	t.Run("TestAidAttestationNotConfigured", testAidAttestationNotConfigured)
	t.Run("TestFetchTaskMetadata", testFetchTaskMetadata)
	t.Run("TestSetAndGetConfig", testSetAndGetConfig)
	t.Run("TestExtractSelectors", testExtractSelectors)
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
				metadata_endpoint = "http://test-endpoint:8080"
				timeout = "45s"
			`,
			expectError: false,
			expectedConfig: &FargateAttestorConfig{
				MetadataEndpoint: "http://test-endpoint:8080",
				Timeout:          45 * time.Second,
			},
		},
		{
			name: "minimal configuration",
			hclConfig: `
				timeout = "15s"
			`,
			expectError: false,
			expectedConfig: &FargateAttestorConfig{
				MetadataEndpoint: "",
				Timeout:          15 * time.Second,
			},
		},
		{
			name: "invalid HCL",
			hclConfig: `
				metadata_endpoint = [invalid
			`,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &Plugin{logger: hclog.NewNullLogger()}
			
			req := &configv1.ConfigureRequest{
				HclConfiguration: tt.hclConfig,
			}

			resp, err := plugin.Configure(context.Background(), req)

			if tt.expectError {
				require.Error(t, err)
				require.Nil(t, resp)
			} else {
				require.NoError(t, err)
				require.NotNil(t, resp)

				config, err := plugin.getConfig()
				require.NoError(t, err)
				assert.Equal(t, tt.expectedConfig.MetadataEndpoint, config.MetadataEndpoint)
				assert.Equal(t, tt.expectedConfig.Timeout, config.Timeout)
			}
		})
	}
}

func testConfigureDefaults(t *testing.T) {
	plugin := &Plugin{logger: hclog.NewNullLogger()}
	
	req := &configv1.ConfigureRequest{
		HclConfiguration: "", // Empty configuration
	}

	resp, err := plugin.Configure(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	config, err := plugin.getConfig()
	require.NoError(t, err)
	assert.Equal(t, "", config.MetadataEndpoint)
	assert.Equal(t, defaultMetadataTimeout, config.Timeout)
}

func testConfigureInvalidTimeout(t *testing.T) {
	plugin := &Plugin{logger: hclog.NewNullLogger()}
	
	req := &configv1.ConfigureRequest{
		HclConfiguration: `timeout = "invalid"`,
	}

	resp, err := plugin.Configure(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, resp)
	assert.Contains(t, err.Error(), "unable to parse timeout duration")
}

func testAidAttestationSuccess(t *testing.T) {
	// Create mock metadata server
	server := createMockMetadataServer(t, http.StatusOK, createValidTaskMetadata())
	defer server.Close()

	plugin := &Plugin{logger: hclog.NewNullLogger()}
	configurePlugin(t, plugin, server.URL)

	// Create mock stream
	stream := &mockAttestationStream{
		ctx: context.Background(),
	}

	err := plugin.AidAttestation(stream)
	require.NoError(t, err)

	// Verify attestation data was sent
	require.Len(t, stream.responses, 1)
	
	payload := stream.responses[0].GetPayload()
	require.NotNil(t, payload)

	var attestationData FargateAttestationData
	err = json.Unmarshal(payload, &attestationData)
	require.NoError(t, err)
	
	var taskMetadata FargateTaskMetadata
	err = json.Unmarshal([]byte(attestationData.TaskMetadata), &taskMetadata)
	require.NoError(t, err)
	
	assert.Equal(t, "test-cluster", taskMetadata.Cluster)
	assert.Equal(t, "arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123def456", taskMetadata.TaskARN)
	assert.Equal(t, "demo-service", taskMetadata.ServiceName)
}

func testAidAttestationMetadataTimeout(t *testing.T) {
	// Create server that delays response beyond timeout
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // Delay longer than our short timeout
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(createValidTaskMetadata())
	}))
	defer server.Close()

	plugin := &Plugin{logger: hclog.NewNullLogger()}
	
	// Configure with very short timeout
	req := &configv1.ConfigureRequest{
		HclConfiguration: fmt.Sprintf(`
			metadata_endpoint = "%s"
			timeout = "10ms"
		`, server.URL),
	}
	_, err := plugin.Configure(context.Background(), req)
	require.NoError(t, err)

	stream := &mockAttestationStream{
		ctx: context.Background(),
	}

	err = plugin.AidAttestation(stream)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to fetch task metadata")
}

func testAidAttestationMetadata404(t *testing.T) {
	server := createMockMetadataServer(t, http.StatusNotFound, "")
	defer server.Close()

	plugin := &Plugin{logger: hclog.NewNullLogger()}
	configurePlugin(t, plugin, server.URL)

	stream := &mockAttestationStream{
		ctx: context.Background(),
	}

	err := plugin.AidAttestation(stream)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata endpoint returned status 404")
}

func testAidAttestationMetadata500(t *testing.T) {
	server := createMockMetadataServer(t, http.StatusInternalServerError, "")
	defer server.Close()

	plugin := &Plugin{logger: hclog.NewNullLogger()}
	configurePlugin(t, plugin, server.URL)

	stream := &mockAttestationStream{
		ctx: context.Background(),
	}

	err := plugin.AidAttestation(stream)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "metadata endpoint returned status 500")
}

func testAidAttestationInvalidJSON(t *testing.T) {
	server := createMockMetadataServer(t, http.StatusOK, "invalid json{}")
	defer server.Close()

	plugin := &Plugin{logger: hclog.NewNullLogger()}
	configurePlugin(t, plugin, server.URL)

	stream := &mockAttestationStream{
		ctx: context.Background(),
	}

	err := plugin.AidAttestation(stream)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to unmarshal task metadata")
}

func testAidAttestationNotConfigured(t *testing.T) {
	plugin := &Plugin{logger: hclog.NewNullLogger()}
	
	stream := &mockAttestationStream{
		ctx: context.Background(),
	}

	err := plugin.AidAttestation(stream)
	require.Error(t, err)
	
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "plugin not configured")
}

func testFetchTaskMetadata(t *testing.T) {
	tests := []struct {
		name           string
		httpStatus     int
		responseBody   string
		expectError    bool
		expectedCluster string
	}{
		{
			name:           "successful fetch",
			httpStatus:     http.StatusOK,
			responseBody:   createValidTaskMetadata(),
			expectError:    false,
			expectedCluster: "test-cluster",
		},
		{
			name:        "404 not found",
			httpStatus:  http.StatusNotFound,
			responseBody: "",
			expectError: true,
		},
		{
			name:        "invalid JSON response",
			httpStatus:  http.StatusOK,
			responseBody: "invalid json",
			expectError: true,
		},
		{
			name:           "minimal valid response",
			httpStatus:     http.StatusOK,
			responseBody:   `{"Cluster":"minimal-cluster","TaskARN":"arn:aws:ecs:us-east-1:123456789012:task/minimal-cluster/test123"}`,
			expectError:    false,
			expectedCluster: "minimal-cluster",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := createMockMetadataServer(t, tt.httpStatus, tt.responseBody)
			defer server.Close()

			plugin := &Plugin{logger: hclog.NewNullLogger()}
			config := &FargateAttestorConfig{
				MetadataEndpoint: server.URL,
				Timeout:          5 * time.Second,
			}

			metadata, err := plugin.fetchTaskMetadata(context.Background(), config)

			if tt.expectError {
				require.Error(t, err)
				require.Nil(t, metadata)
			} else {
				require.NoError(t, err)
				require.NotNil(t, metadata)
				assert.Equal(t, tt.expectedCluster, metadata.Cluster)
			}
		})
	}
}

func testSetAndGetConfig(t *testing.T) {
	plugin := &Plugin{logger: hclog.NewNullLogger()}
	
	// Test getting config when not set
	config, err := plugin.getConfig()
	require.Error(t, err)
	require.Nil(t, config)
	
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())

	// Test setting and getting config
	expectedConfig := &FargateAttestorConfig{
		MetadataEndpoint: "http://test:8080",
		Timeout:          30 * time.Second,
	}
	
	plugin.setConfig(expectedConfig)
	
	config, err = plugin.getConfig()
	require.NoError(t, err)
	require.NotNil(t, config)
	assert.Equal(t, expectedConfig.MetadataEndpoint, config.MetadataEndpoint)
	assert.Equal(t, expectedConfig.Timeout, config.Timeout)
}

func testExtractSelectors(t *testing.T) {
	tests := []struct {
		name              string
		metadata          *FargateTaskMetadata
		expectedSelectors []string
	}{
		{
			name: "comprehensive metadata",
			metadata: &FargateTaskMetadata{
				Cluster:           "test-cluster",
				TaskARN:           "arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123def456",
				Family:            "fargate-spire-demo",
				Revision:          "1",
				ServiceName:       "demo-service",
				AvailabilityZone:  "us-east-1a",
				LaunchType:        "FARGATE",
				TaskTags: map[string]string{
					"Environment": "production",
					"Team":        "platform",
				},
				Containers: []FargateContainerInfo{
					{
						Name:  "spire-agent",
						Image: "spire-agent:latest",
						Labels: map[string]string{
							"version": "1.0.0",
							"env":     "prod",
						},
					},
				},
			},
			expectedSelectors: []string{
				"aws_fargate:cluster:test-cluster",
				"aws_fargate:service:demo-service",
				"aws_fargate:task_definition:fargate-spire-demo",
				"aws_fargate:task_definition_revision:1",
				"aws_fargate:availability_zone:us-east-1a",
				"aws_fargate:launch_type:FARGATE",
				"aws_fargate:region:us-east-1",
				"aws_fargate:account:123456789012",
				"aws_fargate:task_arn:arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123def456",
				"aws_fargate:tag:Environment:production",
				"aws_fargate:tag:Team:platform",
				"aws_fargate:container:spire-agent",
				"aws_fargate:image:spire-agent:latest",
				"aws_fargate:container_label:version:1.0.0",
				"aws_fargate:container_label:env:prod",
			},
		},
		{
			name: "minimal metadata",
			metadata: &FargateTaskMetadata{
				Cluster: "minimal-cluster",
				TaskARN: "arn:aws:ecs:us-west-2:987654321098:task/minimal-cluster/xyz789",
			},
			expectedSelectors: []string{
				"aws_fargate:cluster:minimal-cluster",
				"aws_fargate:region:us-west-2",
				"aws_fargate:account:987654321098",
				"aws_fargate:task_arn:arn:aws:ecs:us-west-2:987654321098:task/minimal-cluster/xyz789",
			},
		},
		{
			name: "empty metadata",
			metadata: &FargateTaskMetadata{},
			expectedSelectors: []string{},
		},
		{
			name: "invalid task ARN",
			metadata: &FargateTaskMetadata{
				Cluster: "test-cluster",
				TaskARN: "invalid-arn",
			},
			expectedSelectors: []string{
				"aws_fargate:cluster:test-cluster",
				"aws_fargate:task_arn:invalid-arn",
			},
		},
		{
			name: "empty tag values filtered out",
			metadata: &FargateTaskMetadata{
				Cluster: "test-cluster",
				TaskTags: map[string]string{
					"ValidTag":   "value",
					"EmptyValue": "",
					"":           "EmptyKey",
				},
			},
			expectedSelectors: []string{
				"aws_fargate:cluster:test-cluster",
				"aws_fargate:tag:ValidTag:value",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plugin := &Plugin{logger: hclog.NewNullLogger()}
			
			actualSelectors := plugin.extractSelectors(tt.metadata)
			
			// Sort both slices for comparison since order may vary
			assert.ElementsMatch(t, tt.expectedSelectors, actualSelectors)
		})
	}
}

// Test helpers

func createMockMetadataServer(t *testing.T, statusCode int, responseBody string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		if responseBody != "" {
			w.Write([]byte(responseBody))
		}
	}))
}

func createValidTaskMetadata() string {
	metadata := FargateTaskMetadata{
		Cluster:           "test-cluster",
		TaskARN:           "arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123def456",
		Family:            "fargate-spire-demo",
		Revision:          "1",
		DesiredStatus:     "RUNNING",
		KnownStatus:       "RUNNING",
		AvailabilityZone:  "us-east-1a",
		LaunchType:        "FARGATE",
		PlatformVersion:   "1.4.0",
		TaskDefinitionArn: "arn:aws:ecs:us-east-1:123456789012:task-definition/fargate-spire-demo:1",
		ServiceName:       "demo-service",
		TaskTags: map[string]string{
			"Environment": "production",
			"Team":        "platform",
		},
		Containers: []FargateContainerInfo{
			{
				DockerID:      "abc123def456",
				Name:          "spire-agent",
				DockerName:    "fargate-app-spire-agent",
				Image:         "spire-agent:latest",
				ImageID:       "sha256:abc123",
				Labels: map[string]string{
					"version": "1.0.0",
					"env":     "prod",
				},
				DesiredStatus: "RUNNING",
				KnownStatus:   "RUNNING",
				Type:          "NORMAL",
			},
		},
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		panic(err)
	}
	return string(data)
}

func configurePlugin(t *testing.T, plugin *Plugin, metadataEndpoint string) {
	req := &configv1.ConfigureRequest{
		HclConfiguration: fmt.Sprintf(`
			metadata_endpoint = "%s"
			timeout = "5s"
		`, metadataEndpoint),
	}
	
	_, err := plugin.Configure(context.Background(), req)
	require.NoError(t, err)
}

// Mock implementation of nodeattestorv1.NodeAttestor_AidAttestationServer
type mockAttestationStream struct {
	ctx       context.Context
	responses []*nodeattestorv1.PayloadOrChallengeResponse
}

func (m *mockAttestationStream) Send(response *nodeattestorv1.PayloadOrChallengeResponse) error {
	m.responses = append(m.responses, response)
	return nil
}

func (m *mockAttestationStream) Recv() (*nodeattestorv1.Challenge, error) {
	// For this simple test, we don't expect any challenges
	// Return EOF to indicate end of stream
	return nil, io.EOF
}

func (m *mockAttestationStream) Context() context.Context {
	return m.ctx
}

// Additional methods required by grpc.ServerStream interface
func (m *mockAttestationStream) SetHeader(md metadata.MD) error {
	return nil
}

func (m *mockAttestationStream) SendHeader(md metadata.MD) error {
	return nil
}

func (m *mockAttestationStream) SetTrailer(md metadata.MD) {
}

func (m *mockAttestationStream) SendMsg(msg interface{}) error {
	return nil
}

func (m *mockAttestationStream) RecvMsg(msg interface{}) error {
	return nil
}
