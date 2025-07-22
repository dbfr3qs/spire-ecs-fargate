package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// ECS Task Metadata v4 response structure
type TaskMetadata struct {
	Cluster              string                 `json:"Cluster"`
	TaskARN              string                 `json:"TaskARN"`
	Family               string                 `json:"Family"`
	Revision             string                 `json:"Revision"`
	DesiredStatus        string                 `json:"DesiredStatus"`
	KnownStatus          string                 `json:"KnownStatus"`
	PullStartedAt        time.Time              `json:"PullStartedAt"`
	PullStoppedAt        time.Time              `json:"PullStoppedAt"`
	AvailabilityZone     string                 `json:"AvailabilityZone"`
	Containers           []ContainerMetadata    `json:"Containers"`
	Limits               map[string]interface{} `json:"Limits"`
	TaskTags             map[string]string      `json:"TaskTags"`
	ServiceName          string                 `json:"ServiceName"`
	LaunchType           string                 `json:"LaunchType"`
	PlatformVersion      string                 `json:"PlatformVersion"`
	TaskDefinitionArn    string                 `json:"TaskDefinitionArn"`
	ExecutionStoppedAt   *time.Time             `json:"ExecutionStoppedAt,omitempty"`
}

type ContainerMetadata struct {
	DockerID      string            `json:"DockerId"`
	Name          string            `json:"Name"`
	DockerName    string            `json:"DockerName"`
	Image         string            `json:"Image"`
	ImageID       string            `json:"ImageID"`
	Labels        map[string]string `json:"Labels"`
	DesiredStatus string            `json:"DesiredStatus"`
	KnownStatus   string            `json:"KnownStatus"`
	Limits        map[string]int    `json:"Limits"`
	CreatedAt     time.Time         `json:"CreatedAt"`
	StartedAt     time.Time         `json:"StartedAt"`
	Type          string            `json:"Type"`
	Networks      []NetworkInfo     `json:"Networks"`
	Ports         []PortMapping     `json:"Ports"`
}

type NetworkInfo struct {
	NetworkMode   string   `json:"NetworkMode"`
	IPv4Addresses []string `json:"IPv4Addresses"`
	IPv6Addresses []string `json:"IPv6Addresses"`
}

type PortMapping struct {
	ContainerPort int    `json:"ContainerPort"`
	Protocol      string `json:"Protocol"`
	HostPort      int    `json:"HostPort"`
}

func mockTaskMetadata(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request for task metadata: %s", r.URL.Path)

	now := time.Now()
	pullTime := now.Add(-5 * time.Minute)

	metadata := TaskMetadata{
		Cluster:           "test-cluster",
		TaskARN:           "arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123def456",
		Family:            "fargate-spire-demo",
		Revision:          "1",
		DesiredStatus:     "RUNNING",
		KnownStatus:       "RUNNING",
		PullStartedAt:     pullTime,
		PullStoppedAt:     pullTime.Add(2 * time.Minute),
		AvailabilityZone:  "us-east-1a",
		LaunchType:        "FARGATE",
		PlatformVersion:   "1.4.0",
		TaskDefinitionArn: "arn:aws:ecs:us-east-1:123456789012:task-definition/fargate-spire-demo:1",
		ServiceName:       "demo-service",
		TaskTags: map[string]string{
			"Environment": "development",
			"Service":     "spire-demo",
			"Team":        "platform",
		},
		Limits: map[string]interface{}{
			"CPU":    0.5,
			"Memory": 1024,
		},
		Containers: []ContainerMetadata{
			{
				DockerID:      "abc123def456",
				Name:          "spire-agent",
				DockerName:    "fargate-app-spire-agent",
				Image:         "spire-agent:latest",
				ImageID:       "sha256:spire123456789abcdef",
				DesiredStatus: "RUNNING",
				KnownStatus:   "RUNNING",
				Type:          "NORMAL",
				CreatedAt:     pullTime.Add(2 * time.Minute),
				StartedAt:     pullTime.Add(3 * time.Minute),
				Labels: map[string]string{
					"com.amazonaws.ecs.cluster":                 "test-cluster",
					"com.amazonaws.ecs.container-name":          "spire-agent",
					"com.amazonaws.ecs.task-arn":                "arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123def456",
					"com.amazonaws.ecs.task-definition-family":  "fargate-spire-demo",
					"com.amazonaws.ecs.task-definition-version": "1",
				},
				Limits: map[string]int{
					"CPU":    256,
					"Memory": 512,
				},
				Networks: []NetworkInfo{
					{
						NetworkMode:   "awsvpc",
						IPv4Addresses: []string{"10.0.1.100"},
					},
				},
			},
			{
				DockerID:      "def456ghi789",
				Name:          "demo-app",
				DockerName:    "fargate-app-demo-app",
				Image:         "demo-app:latest",
				ImageID:       "sha256:demo123456789abcdef",
				DesiredStatus: "RUNNING",
				KnownStatus:   "RUNNING",
				Type:          "NORMAL",
				CreatedAt:     pullTime.Add(2 * time.Minute),
				StartedAt:     pullTime.Add(3 * time.Minute),
				Labels: map[string]string{
					"com.amazonaws.ecs.cluster":                 "test-cluster",
					"com.amazonaws.ecs.container-name":          "demo-app",
					"com.amazonaws.ecs.task-arn":                "arn:aws:ecs:us-east-1:123456789012:task/test-cluster/abc123def456",
					"com.amazonaws.ecs.task-definition-family":  "fargate-spire-demo",
					"com.amazonaws.ecs.task-definition-version": "1",
				},
				Limits: map[string]int{
					"CPU":    256,
					"Memory": 512,
				},
				Networks: []NetworkInfo{
					{
						NetworkMode:   "awsvpc",
						IPv4Addresses: []string{"10.0.1.100"},
					},
				},
				Ports: []PortMapping{
					{
						ContainerPort: 8080,
						Protocol:      "tcp",
						HostPort:      8080,
					},
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(metadata); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	r := mux.NewRouter()
	
	// ECS Task Metadata Endpoint v4
	r.HandleFunc("/v4/metadata", mockTaskMetadata).Methods("GET")
	r.HandleFunc("/health", healthCheck).Methods("GET")
	
	log.Println("Starting ECS Metadata Mock Server on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
