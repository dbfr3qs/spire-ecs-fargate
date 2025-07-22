# SPIRE ECS Fargate Plugin Suite

A comprehensive external plugin solution for [SPIRE](https://spiffe.io/docs/latest/spire-about/) that enables secure workload identity attestation in AWS ECS Fargate environments.

## Overview

This plugin suite provides two complementary SPIRE plugins that work together to enable secure workload identity and certificate-based authentication for containerized applications running on AWS ECS Fargate:

- **Server Plugin (`server/`)**: Server-side node attestor that validates ECS Fargate task identities
- **Agent Plugin (`agent/`)**: Agent-side node attestor that retrieves ECS task metadata for attestation

Both plugins are implemented as external SPIRE plugins using the official SPIRE Plugin SDK and can be deployed independently of each other.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SPIRE Server                             │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │            aws-fargate-server-nodeattestor              │    │
│  │  • Validates ECS task metadata                          │    │
│  │  • Enforces account/cluster filtering                   │    │
│  │  • Generates SPIFFE IDs and selectors                   │    │
│  │  • Enables re-attestation (CanReattest: true)           │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                                │
                                │ Attestation Flow
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      ECS Fargate Task                           │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │               SPIRE Agent                               │    │
│  │  ┌─────────────────────────────────────────────────┐    │    │
│  │  │        aws-fargate-nodeattestor                 │    │    │
│  │  │  • Fetches ECS Task Metadata v4                 │    │    │
│  │  │  • Extracts task selectors                      │    │    │
│  │  │  • Provides attestation payload                 │    │    │
│  │  └─────────────────────────────────────────────────┘    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                               │                                 │
│                               ▼                                 │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │           ECS Task Metadata v4 Endpoint                 │    │
│  │  • Task ARN, Cluster, Family, Service                   │    │
│  │  • Task Tags, Launch Type, Availability Zone            │    │
│  │  • Task Definition ARN and Revision                     │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
```

## Server Plugin (`server/`)

The server plugin runs as part of the SPIRE Server and validates attestation requests from ECS Fargate agents.

### Features

- **ECS Task Identity Validation**: Validates ECS task metadata from agents
- **Account Filtering**: Configurable allow-list of AWS account IDs
- **Cluster Filtering**: Configurable allow-list of ECS cluster names
- **SPIFFE ID Generation**: Generates standardized SPIFFE IDs for attested tasks
- **Selector Generation**: Creates comprehensive selectors from ECS metadata
- **Re-attestation Support**: Enables continuous certificate rotation with `CanReattest: true`

### Configuration

```hcl
NodeAttestor "aws_fargate_task" {
    plugin_cmd = "/opt/spire/bin/aws-fargate-server-nodeattestor"
    plugin_data {
        trust_domain = "example.org"
        allowed_accounts = ["123456789012", "210987654321"]
        allowed_clusters = ["production", "staging"]
        agent_path_template = "/aws_fargate_task/{{ .accountID }}/{{ .cluster }}"
    }
}
```

#### Configuration Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `trust_domain` | string | ✅ | - | SPIFFE trust domain |
| `allowed_accounts` | []string | ❌ | `[]` (all allowed) | List of allowed AWS account IDs |
| `allowed_clusters` | []string | ❌ | `[]` (all allowed) | List of allowed ECS cluster names |
| `agent_path_template` | string | ❌ | `/aws_fargate_task/{{ .accountID }}/{{ .cluster }}` | Template for agent SPIFFE ID path |

### Generated SPIFFE IDs

- **Agent Identity**: `spiffe://example.org/aws_fargate_task/123456789012/my-cluster`
- **Workload Identity**: Determined by SPIRE Server registration entries

### Generated Selectors

The server plugin generates the following selectors from ECS task metadata:

```
aws_fargate_task:account:123456789012
aws_fargate_task:cluster:my-cluster
aws_fargate_task:family:my-task-family
aws_fargate_task:revision:1
aws_fargate_task:service:my-service
aws_fargate_task:az:us-east-1a
aws_fargate_task:launch_type:FARGATE
aws_fargate_task:task_definition_arn:arn:aws:ecs:us-east-1:123456789012:task-definition/my-task-family:1
aws_fargate_task:tag:Environment:production
aws_fargate_task:tag:Team:backend
```

## Agent Plugin (`agent/`)

The agent plugin runs as part of the SPIRE Agent in ECS Fargate tasks and provides attestation data.

### Features

- **ECS Metadata Retrieval**: Fetches task metadata from ECS Task Metadata v4 endpoint
- **Automatic Discovery**: Uses `ECS_CONTAINER_METADATA_URI_V4` environment variable
- **Selector Extraction**: Extracts meaningful selectors from task metadata
- **Configurable Timeout**: Adjustable HTTP timeout for metadata requests
- **Error Handling**: Robust error handling with detailed logging

### Configuration

```hcl
NodeAttestor "aws_fargate_task" {
    plugin_cmd = "/opt/spire/bin/aws-fargate-nodeattestor"
    plugin_data {
        metadata_endpoint = "http://169.254.170.2/v4/metadata"
        timeout = "30s"
    }
}
```

#### Configuration Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `metadata_endpoint` | string | ❌ | Auto-detected from `ECS_CONTAINER_METADATA_URI_V4` | ECS Task Metadata v4 endpoint URL |
| `timeout` | string | ❌ | `30s` | HTTP timeout for metadata requests |

### Environment Variables

The agent plugin automatically detects the ECS metadata endpoint using:

- `ECS_CONTAINER_METADATA_URI_V4`: AWS-provided environment variable in Fargate tasks

## Building and Deployment

### Prerequisites

- Go 1.21+
- SPIRE Plugin SDK v1.12.4+

### Building

#### Server Plugin
```bash
cd server/
GOOS=linux GOARCH=amd64 go build -o aws-fargate-server-nodeattestor-linux
```

#### Agent Plugin
```bash
cd agent/
GOOS=linux GOARCH=amd64 go build -o aws-fargate-nodeattestor-linux
```

### Deployment

#### SPIRE Server
1. Copy the server plugin binary to your SPIRE Server container/host
2. Update SPIRE Server configuration to include the plugin
3. Restart SPIRE Server

#### SPIRE Agent (ECS Fargate)
1. Copy the agent plugin binary to your Fargate task container
2. Update SPIRE Agent configuration to include the plugin
3. Ensure the ECS task has access to the Task Metadata v4 endpoint

### Docker Example

```dockerfile
# Agent container
FROM spire-agent-base:latest
COPY aws-fargate-nodeattestor-linux /opt/spire/bin/aws-fargate-nodeattestor
RUN chmod +x /opt/spire/bin/aws-fargate-nodeattestor

# Server container  
FROM spire-server-base:latest
COPY aws-fargate-server-nodeattestor-linux /opt/spire/bin/aws-fargate-server-nodeattestor
RUN chmod +x /opt/spire/bin/aws-fargate-server-nodeattestor
```

## Testing

Both plugins include comprehensive test suites:

### Server Plugin Tests
```bash
cd server/
go test -v .
```

**Coverage**: 18 test cases covering configuration, validation, attestation, account/cluster filtering, SPIFFE ID generation, and selector validation.

### Agent Plugin Tests
```bash
cd agent/
go test -v .
```

**Coverage**: 24 test cases covering configuration, metadata retrieval, timeout handling, error scenarios, and selector extraction.

## Integration Examples

### Registration Entries

Create workload registration entries using the server-generated agent identity:

```bash
# Register a workload with ECS-attested parent
spire-server entry create \
  -parentID spiffe://example.org/aws_fargate_task/123456789012/my-cluster \
  -spiffeID spiffe://example.org/my-workload \
  -selector unix:uid:1001
```

### Example Applications

See the [`examples/fargate-spire-mock/`](../examples/fargate-spire-mock/) directory for complete Docker Compose examples including:

- Web application with SPIRE agent integration
- API service with mTLS using SPIRE certificates  
- CLI client for identity verification
- Mock ECS metadata server for development/testing

## Security Considerations

- **Account Isolation**: Use `allowed_accounts` to restrict which AWS accounts can attest
- **Cluster Isolation**: Use `allowed_clusters` to restrict which ECS clusters can attest
- **Network Security**: Ensure ECS tasks can reach SPIRE Server on the configured port
- **Certificate Rotation**: The plugins support automatic certificate rotation via re-attestation

## Troubleshooting

### Common Issues

1. **Agent fails to fetch metadata**
   - Verify `ECS_CONTAINER_METADATA_URI_V4` environment variable is set
   - Check network connectivity to metadata endpoint
   - Increase timeout if needed

2. **Server rejects attestation**
   - Verify account ID is in `allowed_accounts` (if configured)
   - Verify cluster name is in `allowed_clusters` (if configured)
   - Check SPIRE Server logs for detailed error messages

3. **Re-attestation failures**
   - Ensure server plugin is properly configured with `CanReattest: true`
   - Verify SPIRE Server version compatibility (1.12.4+)

### Debugging

Enable debug logging in both plugins:

```hcl
# Agent configuration
log_level = "DEBUG"

# Server configuration  
log_level = "DEBUG"
```

## Contributing

1. **Code Structure**: Each plugin is a separate Go module with independent dependencies
2. **Testing**: All new features must include comprehensive test coverage
3. **Documentation**: Update this README for any configuration or usage changes
4. **Compatibility**: Maintain compatibility with SPIRE Plugin SDK v1.12.4+

## License

This project follows the same license as the SPIRE project.

---

For more information about SPIRE and the Plugin SDK, visit:
- [SPIRE Documentation](https://spiffe.io/docs/latest/spire-about/)
- [SPIRE Plugin SDK](https://github.com/spiffe/spire-plugin-sdk)
