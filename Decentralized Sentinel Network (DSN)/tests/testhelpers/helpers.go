package testhelpers

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dsn/decentralized-sentinel-network/pkg/config"
	"github.com/dsn/decentralized-sentinel-network/pkg/logger"
	"github.com/stretchr/testify/require"
)

// TestConfig creates a test configuration with safe defaults
func TestConfig(t *testing.T) *config.Config {
	cfg := config.NewDefaultConfig()
	cfg.SentinelID = fmt.Sprintf("test-sentinel-%d", time.Now().Unix())
	cfg.Region = "test-region"
	cfg.Zone = "test-zone"
	
	// Use random available ports for testing
	cfg.Server.GRPCPort = GetFreePort(t)
	cfg.Server.HTTPPort = GetFreePort(t)
	cfg.Server.MetricsPort = GetFreePort(t)
	
	// Set test-friendly logging
	cfg.Logging.Level = "debug"
	cfg.Logging.Format = "json"
	cfg.Logging.Output = "stdout"
	
	// Disable external services for unit tests
	cfg.Services.Consensus.Enabled = false
	cfg.Services.AIEngine.Enabled = false
	cfg.Services.Healing.Enabled = false
	cfg.Services.Prometheus.Enabled = false
	
	// Use in-memory storage for tests
	cfg.Storage.Type = "memory"
	
	return cfg
}

// TestLogger creates a test logger
func TestLogger(t *testing.T) logger.Logger {
	cfg := &config.LoggingConfig{
		Level:  "debug",
		Format: "json",
		Output: "stdout",
	}
	
	log, err := logger.New(*cfg)
	require.NoError(t, err)
	
	return log
}

// GetFreePort finds an available port for testing
func GetFreePort(t *testing.T) int {
	listener, err := net.Listen("tcp", ":0")
	require.NoError(t, err)
	defer listener.Close()
	
	return listener.Addr().(*net.TCPAddr).Port
}

// WaitForPort waits for a port to become available
func WaitForPort(t *testing.T, port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	
	return false
}

// CreateTempDir creates a temporary directory for testing
func CreateTempDir(t *testing.T) string {
	dir, err := os.MkdirTemp("", "dsn-test-*")
	require.NoError(t, err)
	
	t.Cleanup(func() {
		os.RemoveAll(dir)
	})
	
	return dir
}

// CreateTempFile creates a temporary file with content
func CreateTempFile(t *testing.T, content string) string {
	dir := CreateTempDir(t)
	file := filepath.Join(dir, "test-file")
	
	err := os.WriteFile(file, []byte(content), 0644)
	require.NoError(t, err)
	
	return file
}

// CreateTestConfigFile creates a temporary config file for testing
func CreateTestConfigFile(t *testing.T, cfg *config.Config) string {
	content := `
sentinel_id: "` + cfg.SentinelID + `"
region: "` + cfg.Region + `"
zone: "` + cfg.Zone + `"

server:
  grpc_port: ` + fmt.Sprintf("%d", cfg.Server.GRPCPort) + `
  http_port: ` + fmt.Sprintf("%d", cfg.Server.HTTPPort) + `
  metrics_port: ` + fmt.Sprintf("%d", cfg.Server.MetricsPort) + `

logging:
  level: "` + cfg.Logging.Level + `"
  format: "` + cfg.Logging.Format + `"
  output: "` + cfg.Logging.Output + `"

metrics:
  enabled: ` + fmt.Sprintf("%t", cfg.Metrics.Enabled) + `
  namespace: "` + cfg.Metrics.Namespace + `"
  subsystem: "` + cfg.Metrics.Subsystem + `"

storage:
  type: "` + cfg.Storage.Type + `"
`
	
	return CreateTempFile(t, content)
}

// ContextWithTimeout creates a context with timeout for testing
func ContextWithTimeout(t *testing.T, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	
	t.Cleanup(func() {
		cancel()
	})
	
	return ctx, cancel
}

// AssertEventually asserts that a condition becomes true within a timeout
func AssertEventually(t *testing.T, condition func() bool, timeout time.Duration, message string) {
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	
	t.Fatalf("Condition not met within timeout: %s", message)
}

// MockMetricsCollector provides a mock metrics collector for testing
type MockMetricsCollector struct {
	metrics map[string]float64
}

// NewMockMetricsCollector creates a new mock metrics collector
func NewMockMetricsCollector() *MockMetricsCollector {
	return &MockMetricsCollector{
		metrics: make(map[string]float64),
	}
}

// Record records a metric value
func (m *MockMetricsCollector) Record(name string, value float64) {
	m.metrics[name] = value
}

// Get retrieves a metric value
func (m *MockMetricsCollector) Get(name string) (float64, bool) {
	value, exists := m.metrics[name]
	return value, exists
}

// GetAll returns all recorded metrics
func (m *MockMetricsCollector) GetAll() map[string]float64 {
	result := make(map[string]float64)
	for k, v := range m.metrics {
		result[k] = v
	}
	return result
}

// Reset clears all recorded metrics
func (m *MockMetricsCollector) Reset() {
	m.metrics = make(map[string]float64)
}

// TestEnvironment provides a complete test environment
type TestEnvironment struct {
	Config    *config.Config
	Logger    logger.Logger
	TempDir   string
	ConfigFile string
	t         *testing.T
}

// NewTestEnvironment creates a new test environment
func NewTestEnvironment(t *testing.T) *TestEnvironment {
	cfg := TestConfig(t)
	log := TestLogger(t)
	tempDir := CreateTempDir(t)
	configFile := CreateTestConfigFile(t, cfg)
	
	return &TestEnvironment{
		Config:     cfg,
		Logger:     log,
		TempDir:    tempDir,
		ConfigFile: configFile,
		t:          t,
	}
}

// Cleanup cleans up the test environment
func (te *TestEnvironment) Cleanup() {
	// Cleanup is handled by t.Cleanup() in helper functions
}

// SetEnvVar sets an environment variable for the test
func (te *TestEnvironment) SetEnvVar(key, value string) {
	oldValue := os.Getenv(key)
	os.Setenv(key, value)
	
	te.t.Cleanup(func() {
		if oldValue == "" {
			os.Unsetenv(key)
		} else {
			os.Setenv(key, oldValue)
		}
	})
}