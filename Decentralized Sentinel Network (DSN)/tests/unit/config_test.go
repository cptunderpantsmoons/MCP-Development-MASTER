package unit

import (
	"os"
	"testing"

	"github.com/dsn/decentralized-sentinel-network/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigLoad(t *testing.T) {
	tests := []struct {
		name        string
		configFile  string
		expectError bool
	}{
		{
			name:        "valid config file",
			configFile:  "../../configs/sentinel.yaml",
			expectError: false,
		},
		{
			name:        "non-existent config file",
			configFile:  "non-existent.yaml",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.Load(tt.configFile)
			
			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, cfg)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, cfg)
				assert.NotEmpty(t, cfg.SentinelID)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := &config.Config{
		SentinelID: "test-sentinel",
		Region:     "us-west-2",
		Zone:       "us-west-2a",
		Server: config.ServerConfig{
			GRPCPort: 9090,
			HTTPPort: 8080,
		},
		Logging: config.LoggingConfig{
			Level:  "info",
			Format: "json",
		},
	}

	err := cfg.Validate()
	assert.NoError(t, err)
}

func TestConfigValidationErrors(t *testing.T) {
	tests := []struct {
		name   string
		config *config.Config
	}{
		{
			name: "empty sentinel ID",
			config: &config.Config{
				SentinelID: "",
				Region:     "us-west-2",
				Zone:       "us-west-2a",
			},
		},
		{
			name: "invalid port",
			config: &config.Config{
				SentinelID: "test-sentinel",
				Region:     "us-west-2",
				Zone:       "us-west-2a",
				Server: config.ServerConfig{
					GRPCPort: 0,
					HTTPPort: 8080,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			assert.Error(t, err)
		})
	}
}

func TestConfigFromEnv(t *testing.T) {
	// Set environment variables
	os.Setenv("DSN_SENTINEL_ID", "env-sentinel")
	os.Setenv("DSN_REGION", "env-region")
	os.Setenv("DSN_LOG_LEVEL", "debug")
	defer func() {
		os.Unsetenv("DSN_SENTINEL_ID")
		os.Unsetenv("DSN_REGION")
		os.Unsetenv("DSN_LOG_LEVEL")
	}()

	cfg := &config.Config{}
	cfg.LoadFromEnv()

	assert.Equal(t, "env-sentinel", cfg.SentinelID)
	assert.Equal(t, "env-region", cfg.Region)
	assert.Equal(t, "debug", cfg.Logging.Level)
}

func TestConfigDefaults(t *testing.T) {
	cfg := config.NewDefaultConfig()
	
	require.NotNil(t, cfg)
	assert.NotEmpty(t, cfg.SentinelID)
	assert.Equal(t, 9090, cfg.Server.GRPCPort)
	assert.Equal(t, 8080, cfg.Server.HTTPPort)
	assert.Equal(t, "info", cfg.Logging.Level)
	assert.Equal(t, "json", cfg.Logging.Format)
}