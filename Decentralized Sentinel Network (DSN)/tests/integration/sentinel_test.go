//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/dsn/decentralized-sentinel-network/internal/sentinel"
	"github.com/dsn/decentralized-sentinel-network/pkg/config"
	"github.com/dsn/decentralized-sentinel-network/pkg/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type SentinelIntegrationTestSuite struct {
	suite.Suite
	sentinel *sentinel.Sentinel
	config   *config.Config
	logger   logger.Logger
}

func (suite *SentinelIntegrationTestSuite) SetupSuite() {
	// Load test configuration
	cfg := config.NewDefaultConfig()
	cfg.SentinelID = "integration-test-sentinel"
	cfg.Region = "test-region"
	cfg.Zone = "test-zone"
	cfg.Server.GRPCPort = 19090
	cfg.Server.HTTPPort = 18080
	cfg.Server.MetricsPort = 18081
	cfg.Logging.Level = "debug"

	suite.config = cfg

	// Initialize logger
	log, err := logger.New(cfg.Logging)
	require.NoError(suite.T(), err)
	suite.logger = log

	// Initialize sentinel
	s, err := sentinel.New(cfg, log)
	require.NoError(suite.T(), err)
	suite.sentinel = s
}

func (suite *SentinelIntegrationTestSuite) TearDownSuite() {
	if suite.sentinel != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		suite.sentinel.Shutdown(ctx)
	}
}

func (suite *SentinelIntegrationTestSuite) TestSentinelStartStop() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start sentinel in a goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- suite.sentinel.Start(ctx)
	}()

	// Wait a bit for startup
	time.Sleep(2 * time.Second)

	// Check if sentinel is running
	assert.True(suite.T(), suite.sentinel.IsHealthy())

	// Stop sentinel
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	
	err := suite.sentinel.Shutdown(shutdownCtx)
	assert.NoError(suite.T(), err)

	// Check for any startup errors
	select {
	case err := <-errChan:
		if err != nil && err != context.Canceled {
			suite.T().Errorf("Sentinel startup error: %v", err)
		}
	case <-time.After(1 * time.Second):
		// No error received, which is expected for clean shutdown
	}
}

func (suite *SentinelIntegrationTestSuite) TestSentinelHealthCheck() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start sentinel
	go func() {
		suite.sentinel.Start(ctx)
	}()

	// Wait for startup
	time.Sleep(2 * time.Second)

	// Test health check
	healthy := suite.sentinel.IsHealthy()
	assert.True(suite.T(), healthy)

	// Test health check endpoint
	status := suite.sentinel.GetStatus()
	assert.NotNil(suite.T(), status)
	assert.Equal(suite.T(), "running", status.State)
	assert.Equal(suite.T(), suite.config.SentinelID, status.SentinelID)
}

func (suite *SentinelIntegrationTestSuite) TestSentinelMetrics() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start sentinel
	go func() {
		suite.sentinel.Start(ctx)
	}()

	// Wait for startup
	time.Sleep(2 * time.Second)

	// Test metrics collection
	metrics := suite.sentinel.GetMetrics()
	assert.NotNil(suite.T(), metrics)
	
	// Check for basic metrics
	assert.Contains(suite.T(), metrics, "sentinel_uptime_seconds")
	assert.Contains(suite.T(), metrics, "sentinel_health_status")
}

func (suite *SentinelIntegrationTestSuite) TestSentinelConfiguration() {
	// Test configuration loading and validation
	cfg := suite.sentinel.GetConfig()
	assert.NotNil(suite.T(), cfg)
	assert.Equal(suite.T(), "integration-test-sentinel", cfg.SentinelID)
	assert.Equal(suite.T(), "test-region", cfg.Region)
	assert.Equal(suite.T(), "test-zone", cfg.Zone)
}

func TestSentinelIntegrationSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	suite.Run(t, new(SentinelIntegrationTestSuite))
}

// Test database integration
func TestDatabaseIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// This test would require actual database connection
	// Implementation depends on database package being created
	t.Skip("Database integration tests not yet implemented")
}

// Test gRPC server integration
func TestGRPCServerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// This test would require gRPC server implementation
	// Implementation depends on gRPC server package being created
	t.Skip("gRPC server integration tests not yet implemented")
}

// Test metrics integration
func TestMetricsIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	cfg := config.NewDefaultConfig()
	cfg.Metrics.Enabled = true
	cfg.Metrics.Namespace = "dsn_test"
	cfg.Metrics.Subsystem = "sentinel_test"

	log, err := logger.New(cfg.Logging)
	require.NoError(t, err)

	s, err := sentinel.New(cfg, log)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start sentinel
	go func() {
		s.Start(ctx)
	}()

	// Wait for startup
	time.Sleep(1 * time.Second)

	// Test metrics endpoint
	metrics := s.GetMetrics()
	assert.NotNil(t, metrics)
	assert.NotEmpty(t, metrics)

	// Cleanup
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	s.Shutdown(shutdownCtx)
}