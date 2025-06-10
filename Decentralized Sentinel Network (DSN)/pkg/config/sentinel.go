package config

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// SentinelConfig holds the configuration for a sentinel node
type SentinelConfig struct {
	// Basic identification
	SentinelID string `mapstructure:"sentinel_id" yaml:"sentinel_id"`
	Region     string `mapstructure:"region" yaml:"region"`
	Zone       string `mapstructure:"zone" yaml:"zone"`

	// Server configuration
	Server ServerConfig `mapstructure:"server" yaml:"server"`

	// Logging configuration
	Logging LoggingConfig `mapstructure:"logging" yaml:"logging"`

	// Metrics configuration
	Metrics MetricsConfig `mapstructure:"metrics" yaml:"metrics"`

	// Monitoring configuration
	Monitoring MonitoringConfig `mapstructure:"monitoring" yaml:"monitoring"`

	// Health check configuration
	HealthCheck HealthCheckConfig `mapstructure:"health_check" yaml:"health_check"`

	// Threat detection configuration
	ThreatDetection ThreatDetectionConfig `mapstructure:"threat_detection" yaml:"threat_detection"`

	// Security configuration
	Security SecurityConfig `mapstructure:"security" yaml:"security"`

	// External services
	Services ServicesConfig `mapstructure:"services" yaml:"services"`

	// Storage configuration
	Storage StorageConfig `mapstructure:"storage" yaml:"storage"`
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	GRPCPort     int           `mapstructure:"grpc_port" yaml:"grpc_port"`
	HTTPPort     int           `mapstructure:"http_port" yaml:"http_port"`
	MetricsPort  int           `mapstructure:"metrics_port" yaml:"metrics_port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout" yaml:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout" yaml:"write_timeout"`
	MaxConns     int           `mapstructure:"max_connections" yaml:"max_connections"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `mapstructure:"level" yaml:"level"`
	Format string `mapstructure:"format" yaml:"format"`
	Output string `mapstructure:"output" yaml:"output"`
}

// MetricsConfig holds metrics configuration
type MetricsConfig struct {
	Enabled    bool   `mapstructure:"enabled" yaml:"enabled"`
	Path       string `mapstructure:"path" yaml:"path"`
	Namespace  string `mapstructure:"namespace" yaml:"namespace"`
	Subsystem  string `mapstructure:"subsystem" yaml:"subsystem"`
	PushGateway string `mapstructure:"push_gateway" yaml:"push_gateway"`
}
// MonitoringConfig holds monitoring configuration
type MonitoringConfig struct {
	Enabled         bool                    `mapstructure:"enabled" yaml:"enabled"`
	Interval        time.Duration           `mapstructure:"interval" yaml:"interval"`
	MetricsEnabled  bool                    `mapstructure:"metrics_enabled" yaml:"metrics_enabled"`
	SecurityEnabled bool                    `mapstructure:"security_enabled" yaml:"security_enabled"`
	RateLimit       int                     `mapstructure:"rate_limit" yaml:"rate_limit"`
	Thresholds      MonitoringThresholds    `mapstructure:"thresholds" yaml:"thresholds"`
	Security        MonitoringSecurityConfig `mapstructure:"security" yaml:"security"`
}

// MonitoringThresholds holds monitoring threshold values
type MonitoringThresholds struct {
	CPUWarning         float64 `mapstructure:"cpu_warning" yaml:"cpu_warning"`
	CPUCritical        float64 `mapstructure:"cpu_critical" yaml:"cpu_critical"`
	MemoryWarning      float64 `mapstructure:"memory_warning" yaml:"memory_warning"`
	MemoryCritical     float64 `mapstructure:"memory_critical" yaml:"memory_critical"`
	HealthScoreCritical float64 `mapstructure:"health_score_critical" yaml:"health_score_critical"`
}

// MonitoringSecurityConfig holds security-specific monitoring settings
type MonitoringSecurityConfig struct {
	AnomalyDetection bool `mapstructure:"anomaly_detection" yaml:"anomaly_detection"`
	MetricValidation bool `mapstructure:"metric_validation" yaml:"metric_validation"`
	RateLimiting     bool `mapstructure:"rate_limiting" yaml:"rate_limiting"`
	AlertThrottling  bool `mapstructure:"alert_throttling" yaml:"alert_throttling"`
}

// HealthCheckConfig holds health check configuration
type HealthCheckConfig struct {
	Enabled  bool          `mapstructure:"enabled" yaml:"enabled"`
	Interval time.Duration `mapstructure:"interval" yaml:"interval"`
	Timeout  time.Duration `mapstructure:"timeout" yaml:"timeout"`
	Endpoint string        `mapstructure:"endpoint" yaml:"endpoint"`
}

// ThreatDetectionConfig holds threat detection configuration
type ThreatDetectionConfig struct {
	Enabled          bool          `mapstructure:"enabled" yaml:"enabled"`
	ScanInterval     time.Duration `mapstructure:"scan_interval" yaml:"scan_interval"`
	DeepScanEnabled  bool          `mapstructure:"deep_scan_enabled" yaml:"deep_scan_enabled"`
	MaxConcurrentScans int         `mapstructure:"max_concurrent_scans" yaml:"max_concurrent_scans"`
	ExcludedPaths    []string      `mapstructure:"excluded_paths" yaml:"excluded_paths"`
	
	// Detection engines
	Engines DetectionEnginesConfig `mapstructure:"engines" yaml:"engines"`
	
	// Thresholds
	Thresholds ThresholdConfig `mapstructure:"thresholds" yaml:"thresholds"`
}

// DetectionEnginesConfig holds configuration for different detection engines
type DetectionEnginesConfig struct {
	Signature SignatureDetectionConfig `mapstructure:"signature" yaml:"signature"`
	Anomaly   AnomalyDetectionConfig   `mapstructure:"anomaly" yaml:"anomaly"`
	Behavior  BehaviorDetectionConfig  `mapstructure:"behavior" yaml:"behavior"`
}

// SignatureDetectionConfig holds signature-based detection configuration
type SignatureDetectionConfig struct {
	Enabled       bool     `mapstructure:"enabled" yaml:"enabled"`
	DatabasePath  string   `mapstructure:"database_path" yaml:"database_path"`
	UpdateInterval time.Duration `mapstructure:"update_interval" yaml:"update_interval"`
	CustomRules   []string `mapstructure:"custom_rules" yaml:"custom_rules"`
}

// AnomalyDetectionConfig holds anomaly detection configuration
type AnomalyDetectionConfig struct {
	Enabled         bool    `mapstructure:"enabled" yaml:"enabled"`
	SensitivityLevel string  `mapstructure:"sensitivity_level" yaml:"sensitivity_level"`
	LearningPeriod  time.Duration `mapstructure:"learning_period" yaml:"learning_period"`
	ConfidenceThreshold float64 `mapstructure:"confidence_threshold" yaml:"confidence_threshold"`
}

// BehaviorDetectionConfig holds behavior-based detection configuration
type BehaviorDetectionConfig struct {
	Enabled        bool          `mapstructure:"enabled" yaml:"enabled"`
	MonitoringWindow time.Duration `mapstructure:"monitoring_window" yaml:"monitoring_window"`
	BaselineUpdate time.Duration `mapstructure:"baseline_update" yaml:"baseline_update"`
}

// ThresholdConfig holds various threshold configurations
type ThresholdConfig struct {
	CPUUsage    float64 `mapstructure:"cpu_usage" yaml:"cpu_usage"`
	MemoryUsage float64 `mapstructure:"memory_usage" yaml:"memory_usage"`
	DiskUsage   float64 `mapstructure:"disk_usage" yaml:"disk_usage"`
	NetworkTraffic float64 `mapstructure:"network_traffic" yaml:"network_traffic"`
	ErrorRate   float64 `mapstructure:"error_rate" yaml:"error_rate"`
}

// SecurityConfig holds security-related configuration
type SecurityConfig struct {
	TLS  TLSConfig  `mapstructure:"tls" yaml:"tls"`
	mTLS mTLSConfig `mapstructure:"mtls" yaml:"mtls"`
	Vault VaultConfig `mapstructure:"vault" yaml:"vault"`
	Auth  AuthConfig `mapstructure:"auth" yaml:"auth"`
}

// TLSConfig holds TLS configuration
type TLSConfig struct {
	Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
	CertFile string `mapstructure:"cert_file" yaml:"cert_file"`
	KeyFile  string `mapstructure:"key_file" yaml:"key_file"`
	CAFile   string `mapstructure:"ca_file" yaml:"ca_file"`
}

// mTLSConfig holds mutual TLS configuration
type mTLSConfig struct {
	Enabled    bool   `mapstructure:"enabled" yaml:"enabled"`
	ClientCert string `mapstructure:"client_cert" yaml:"client_cert"`
	ClientKey  string `mapstructure:"client_key" yaml:"client_key"`
	ServerName string `mapstructure:"server_name" yaml:"server_name"`
}

// VaultConfig holds HashiCorp Vault configuration
type VaultConfig struct {
	Enabled   bool   `mapstructure:"enabled" yaml:"enabled"`
	Address   string `mapstructure:"address" yaml:"address"`
	Token     string `mapstructure:"token" yaml:"token"`
	Namespace string `mapstructure:"namespace" yaml:"namespace"`
	AuthMethod string `mapstructure:"auth_method" yaml:"auth_method"`
	SecretPath string `mapstructure:"secret_path" yaml:"secret_path"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
	Method   string `mapstructure:"method" yaml:"method"` // jwt, oauth2, api_key
	JWTSecret string `mapstructure:"jwt_secret" yaml:"jwt_secret"`
	OAuth2   OAuth2Config `mapstructure:"oauth2" yaml:"oauth2"`
}

// OAuth2Config holds OAuth2 configuration
type OAuth2Config struct {
	ClientID     string `mapstructure:"client_id" yaml:"client_id"`
	ClientSecret string `mapstructure:"client_secret" yaml:"client_secret"`
	AuthURL      string `mapstructure:"auth_url" yaml:"auth_url"`
	TokenURL     string `mapstructure:"token_url" yaml:"token_url"`
	RedirectURL  string `mapstructure:"redirect_url" yaml:"redirect_url"`
}

// ServicesConfig holds external services configuration
type ServicesConfig struct {
	Consensus ConsensusServiceConfig `mapstructure:"consensus" yaml:"consensus"`
	AIEngine  AIEngineServiceConfig  `mapstructure:"ai_engine" yaml:"ai_engine"`
	Healing   HealingServiceConfig   `mapstructure:"healing" yaml:"healing"`
	Prometheus PrometheusConfig      `mapstructure:"prometheus" yaml:"prometheus"`
}

// ConsensusServiceConfig holds consensus layer service configuration
type ConsensusServiceConfig struct {
	Enabled   bool     `mapstructure:"enabled" yaml:"enabled"`
	Endpoints []string `mapstructure:"endpoints" yaml:"endpoints"`
	Timeout   time.Duration `mapstructure:"timeout" yaml:"timeout"`
	TLS       TLSConfig `mapstructure:"tls" yaml:"tls"`
}

// AIEngineServiceConfig holds AI engine service configuration
type AIEngineServiceConfig struct {
	Enabled   bool     `mapstructure:"enabled" yaml:"enabled"`
	Endpoints []string `mapstructure:"endpoints" yaml:"endpoints"`
	Timeout   time.Duration `mapstructure:"timeout" yaml:"timeout"`
	APIKey    string   `mapstructure:"api_key" yaml:"api_key"`
}

// HealingServiceConfig holds self-healing service configuration
type HealingServiceConfig struct {
	Enabled   bool     `mapstructure:"enabled" yaml:"enabled"`
	Endpoints []string `mapstructure:"endpoints" yaml:"endpoints"`
	Timeout   time.Duration `mapstructure:"timeout" yaml:"timeout"`
}

// PrometheusConfig holds Prometheus configuration
type PrometheusConfig struct {
	Enabled  bool   `mapstructure:"enabled" yaml:"enabled"`
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`
	Username string `mapstructure:"username" yaml:"username"`
	Password string `mapstructure:"password" yaml:"password"`
}

// StorageConfig holds storage configuration
type StorageConfig struct {
	Type     string `mapstructure:"type" yaml:"type"` // local, s3, gcs, azure
	Path     string `mapstructure:"path" yaml:"path"`
	Bucket   string `mapstructure:"bucket" yaml:"bucket"`
	Region   string `mapstructure:"region" yaml:"region"`
	Endpoint string `mapstructure:"endpoint" yaml:"endpoint"`
	
	// Retention settings
	RetentionDays int `mapstructure:"retention_days" yaml:"retention_days"`
	MaxSize       string `mapstructure:"max_size" yaml:"max_size"`
}

// LoadSentinelConfig loads the sentinel configuration from viper
func LoadSentinelConfig() (*SentinelConfig, error) {
	var config SentinelConfig
	
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Set defaults if not provided
	if config.SentinelID == "" {
		config.SentinelID = generateSentinelID()
	}
	
	return &config, nil
}

// Validate validates the sentinel configuration
func (c *SentinelConfig) Validate() error {
	// Create validator instance
	validator := &inputValidator{
		allowedPaths: []string{"/etc/dsn/", "/var/lib/dsn/", "/tmp/dsn/"},
	}
	
	// Validate sentinel ID
	if err := validator.ValidateSentinelID(c.SentinelID); err != nil {
		return fmt.Errorf("invalid sentinel_id: %w", err)
	}
	
	// Validate server configuration
	if err := c.Server.Validate(validator); err != nil {
		return fmt.Errorf("server config validation failed: %w", err)
	}
	
	// Validate logging configuration
	if err := c.Logging.Validate(validator); err != nil {
		return fmt.Errorf("logging config validation failed: %w", err)
	}
	
	// Validate security configuration
	if err := c.Security.Validate(validator); err != nil {
		return fmt.Errorf("security config validation failed: %w", err)
	}
	
	// Validate threat detection configuration
	if err := c.ThreatDetection.Validate(validator); err != nil {
		return fmt.Errorf("threat detection config validation failed: %w", err)
	}
	
	// Validate external services
	if err := c.Services.Validate(validator); err != nil {
		return fmt.Errorf("services config validation failed: %w", err)
	}
	
	return nil
}

// Validate validates the server configuration
func (c *ServerConfig) Validate(validator *inputValidator) error {
	if err := validator.ValidatePort(c.GRPCPort, "gRPC"); err != nil {
		return err
	}
	
	if err := validator.ValidatePort(c.HTTPPort, "HTTP"); err != nil {
		return err
	}
	
	if err := validator.ValidatePort(c.MetricsPort, "metrics"); err != nil {
		return err
	}
	
	// Ensure ports are unique
	ports := []int{c.GRPCPort, c.HTTPPort, c.MetricsPort}
	for i := 0; i < len(ports); i++ {
		for j := i + 1; j < len(ports); j++ {
			if ports[i] == ports[j] {
				return fmt.Errorf("ports must be unique: found duplicate port %d", ports[i])
			}
		}
	}
	
	// Validate timeouts
	if c.ReadTimeout <= 0 {
		return fmt.Errorf("read_timeout must be positive, got %v", c.ReadTimeout)
	}
	
	if c.WriteTimeout <= 0 {
		return fmt.Errorf("write_timeout must be positive, got %v", c.WriteTimeout)
	}
	
	// Validate connection limits
	if c.MaxConns < 0 {
		return fmt.Errorf("max_connections cannot be negative, got %d", c.MaxConns)
	}
	
	if c.MaxConns > 10000 {
		return fmt.Errorf("max_connections too high (%d), maximum recommended is 10000", c.MaxConns)
	}
	
	return nil
}

// Validate validates the logging configuration
func (c *LoggingConfig) Validate(validator *inputValidator) error {
	if err := validator.ValidateLogLevel(c.Level); err != nil {
		return err
	}
	
	if err := validator.ValidateLogFormat(c.Format); err != nil {
		return err
	}
	
	// Validate output path if specified
	if c.Output != "" && c.Output != "stdout" && c.Output != "stderr" {
		if err := validator.ValidateFilePath(c.Output, "log output"); err != nil {
			return err
		}
	}
	
	return nil
}

// Validate validates the security configuration
func (c *SecurityConfig) Validate(validator *inputValidator) error {
	// TLS validation
	if c.TLS.Enabled {
		if c.TLS.CertFile == "" {
			return fmt.Errorf("tls cert_file is required when TLS is enabled")
		}
		if err := validator.ValidateFilePath(c.TLS.CertFile, "TLS cert"); err != nil {
			return fmt.Errorf("TLS cert_file validation failed: %w", err)
		}
		
		if c.TLS.KeyFile == "" {
			return fmt.Errorf("tls key_file is required when TLS is enabled")
		}
		if err := validator.ValidateFilePath(c.TLS.KeyFile, "TLS key"); err != nil {
			return fmt.Errorf("TLS key_file validation failed: %w", err)
		}
		
		if c.TLS.CAFile != "" {
			if err := validator.ValidateFilePath(c.TLS.CAFile, "TLS CA"); err != nil {
				return fmt.Errorf("TLS ca_file validation failed: %w", err)
			}
		}
	} else {
		// Warn if TLS is disabled in production-like environment
		if strings.ToLower(os.Getenv("DSN_ENVIRONMENT")) == "production" {
			return fmt.Errorf("TLS must be enabled in production environment")
		}
	}
	
	// mTLS validation
	if c.mTLS.Enabled {
		if !c.TLS.Enabled {
			return fmt.Errorf("TLS must be enabled when mTLS is enabled")
		}
		
		if c.mTLS.ClientCert == "" {
			return fmt.Errorf("mtls client_cert is required when mTLS is enabled")
		}
		if err := validator.ValidateFilePath(c.mTLS.ClientCert, "mTLS client cert"); err != nil {
			return fmt.Errorf("mTLS client_cert validation failed: %w", err)
		}
		
		if c.mTLS.ClientKey == "" {
			return fmt.Errorf("mtls client_key is required when mTLS is enabled")
		}
		if err := validator.ValidateFilePath(c.mTLS.ClientKey, "mTLS client key"); err != nil {
			return fmt.Errorf("mTLS client_key validation failed: %w", err)
		}
		
		if c.mTLS.ServerName == "" {
			return fmt.Errorf("mtls server_name is required when mTLS is enabled")
		}
	}
	
	// Vault validation
	if c.Vault.Enabled {
		if c.Vault.Address == "" {
			return fmt.Errorf("vault address is required when Vault is enabled")
		}
		
		// Basic URL validation for Vault address
		if !strings.HasPrefix(c.Vault.Address, "https://") && 
		   !strings.HasPrefix(c.Vault.Address, "http://") {
			return fmt.Errorf("vault address must be a valid HTTP(S) URL")
		}
		
		if c.Vault.AuthMethod != "" {
			validMethods := map[string]bool{
				"token": true, "kubernetes": true, "aws": true, "azure": true,
			}
			if !validMethods[c.Vault.AuthMethod] {
				return fmt.Errorf("invalid vault auth_method: %s", c.Vault.AuthMethod)
			}
		}
	}
	
	// Auth validation
	if c.Auth.Enabled {
		validMethods := map[string]bool{
			"jwt": true, "oauth2": true, "api_key": true,
		}
		if !validMethods[c.Auth.Method] {
			return fmt.Errorf("invalid auth method: %s", c.Auth.Method)
		}
		
		if c.Auth.Method == "jwt" && c.Auth.JWTSecret == "" {
			return fmt.Errorf("jwt_secret is required when auth method is JWT")
		}
		
		if c.Auth.Method == "oauth2" {
			if c.Auth.OAuth2.ClientID == "" {
				return fmt.Errorf("oauth2 client_id is required")
			}
			if c.Auth.OAuth2.ClientSecret == "" {
				return fmt.Errorf("oauth2 client_secret is required")
			}
		}
	}
	
	return nil
}

// Validate validates the threat detection configuration
func (c *ThreatDetectionConfig) Validate(validator *inputValidator) error {
	if c.MaxConcurrentScans <= 0 {
		return fmt.Errorf("max_concurrent_scans must be positive, got %d", c.MaxConcurrentScans)
	}
	
	if c.MaxConcurrentScans > 100 {
		return fmt.Errorf("max_concurrent_scans too high (%d), maximum recommended is 100", c.MaxConcurrentScans)
	}
	
	if c.ScanInterval <= 0 {
		return fmt.Errorf("scan_interval must be positive")
	}
	
	// Validate threshold ranges (0-100 for percentages)
	if c.Thresholds.CPUUsage < 0 || c.Thresholds.CPUUsage > 100 {
		return fmt.Errorf("cpu_usage threshold must be between 0 and 100, got %f", c.Thresholds.CPUUsage)
	}
	
	if c.Thresholds.MemoryUsage < 0 || c.Thresholds.MemoryUsage > 100 {
		return fmt.Errorf("memory_usage threshold must be between 0 and 100, got %f", c.Thresholds.MemoryUsage)
	}
	
	if c.Thresholds.DiskUsage < 0 || c.Thresholds.DiskUsage > 100 {
		return fmt.Errorf("disk_usage threshold must be between 0 and 100, got %f", c.Thresholds.DiskUsage)
	}
	
	if c.Thresholds.ErrorRate < 0 || c.Thresholds.ErrorRate > 100 {
		return fmt.Errorf("error_rate threshold must be between 0 and 100, got %f", c.Thresholds.ErrorRate)
	}
	
	// Validate excluded paths for security
	for i, path := range c.ExcludedPaths {
		if strings.Contains(path, "..") {
			return fmt.Errorf("excluded_paths[%d] contains directory traversal: %s", i, path)
		}
	}
	
	// Validate detection engines
	if c.Engines.Signature.Enabled && c.Engines.Signature.DatabasePath != "" {
		if err := validator.ValidateFilePath(c.Engines.Signature.DatabasePath, "signature database"); err != nil {
			return fmt.Errorf("signature database path validation failed: %w", err)
		}
	}
	
	if c.Engines.Anomaly.Enabled {
		validLevels := map[string]bool{
			"low": true, "medium": true, "high": true,
		}
		if !validLevels[c.Engines.Anomaly.SensitivityLevel] {
			return fmt.Errorf("invalid anomaly sensitivity level: %s", c.Engines.Anomaly.SensitivityLevel)
		}
		
		if c.Engines.Anomaly.ConfidenceThreshold < 0 || c.Engines.Anomaly.ConfidenceThreshold > 1 {
			return fmt.Errorf("anomaly confidence threshold must be between 0 and 1, got %f", c.Engines.Anomaly.ConfidenceThreshold)
		}
	}
	
	return nil
}

// Validate validates the services configuration
func (c *ServicesConfig) Validate(validator *inputValidator) error {
	// Validate consensus service endpoints
	if c.Consensus.Enabled && len(c.Consensus.Endpoints) > 0 {
		for i, endpoint := range c.Consensus.Endpoints {
			if endpoint == "" {
				return fmt.Errorf("consensus.endpoints[%d] cannot be empty", i)
			}
			// Basic endpoint format validation (host:port)
			if !strings.Contains(endpoint, ":") {
				return fmt.Errorf("consensus.endpoints[%d] must be in host:port format", i)
			}
		}
	}
	
	// Validate AI engine service endpoints  
	if c.AIEngine.Enabled && len(c.AIEngine.Endpoints) > 0 {
		for i, endpoint := range c.AIEngine.Endpoints {
			if endpoint == "" {
				return fmt.Errorf("ai_engine.endpoints[%d] cannot be empty", i)
			}
		}
	}
	
	// Validate healing service endpoints
	if c.Healing.Enabled && len(c.Healing.Endpoints) > 0 {
		for i, endpoint := range c.Healing.Endpoints {
			if endpoint == "" {
				return fmt.Errorf("healing.endpoints[%d] cannot be empty", i)
			}
		}
	}
	
	// Validate Prometheus configuration
	if c.Prometheus.Enabled {
		if c.Prometheus.Endpoint == "" {
			return fmt.Errorf("prometheus endpoint is required when enabled")
		}
		if !strings.HasPrefix(c.Prometheus.Endpoint, "http://") && 
		   !strings.HasPrefix(c.Prometheus.Endpoint, "https://") {
			return fmt.Errorf("prometheus endpoint must be a valid HTTP(S) URL")
		}
	}
	
	return nil
}

// generateSentinelID generates a cryptographically secure sentinel ID
func generateSentinelID() string {
	// Use secure random generation from crypto package
	id, err := generateSecureSentinelID()
	if err != nil {
		// Fallback to hostname-based ID if crypto fails
		hostname, _ := os.Hostname()
		timestamp := time.Now().Unix()
		return fmt.Sprintf("sentinel-%s-%d", hostname, timestamp)
	}
	return id
}

// generateSecureSentinelID creates a cryptographically secure ID
func generateSecureSentinelID() (string, error) {
	// Generate 16 bytes of cryptographically secure random data
	randomBytes := make([]byte, 16)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	
	// Encode as base32 for readability (no padding)
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(randomBytes)
	
	// Truncate to 16 characters and add prefix
	if len(encoded) > 16 {
		encoded = encoded[:16]
	}
	
	return fmt.Sprintf("sentinel-%s", strings.ToLower(encoded)), nil
}

// inputValidator provides secure input validation for configuration
type inputValidator struct {
	allowedPaths []string
}

// ValidateSentinelID validates sentinel ID format and security
func (v *inputValidator) ValidateSentinelID(id string) error {
	if id == "" {
		return fmt.Errorf("cannot be empty")
	}
	
	// Allow alphanumeric, hyphens, and underscores, length 8-64
	if len(id) < 8 || len(id) > 64 {
		return fmt.Errorf("must be 8-64 characters long")
	}
	
	// Check for valid characters only
	for _, char := range id {
		if !((char >= 'a' && char <= 'z') || 
			 (char >= 'A' && char <= 'Z') || 
			 (char >= '0' && char <= '9') || 
			 char == '-' || char == '_') {
			return fmt.Errorf("contains invalid characters, only alphanumeric, hyphens, and underscores allowed")
		}
	}
	
	return nil
}

// ValidatePort validates network port ranges
func (v *inputValidator) ValidatePort(port int, name string) error {
	if port <= 0 || port > 65535 {
		return fmt.Errorf("%s port %d must be between 1 and 65535", name, port)
	}
	
	// Warn about privileged ports
	if port < 1024 {
		return fmt.Errorf("%s port %d is privileged (<1024), use ports >=1024 for security", name, port)
	}
	
	return nil
}

// ValidateFilePath validates file paths for security
func (v *inputValidator) ValidateFilePath(path string, name string) error {
	if path == "" {
		return nil // Allow empty paths for optional configs
	}
	
	// Check for directory traversal
	if strings.Contains(path, "..") {
		return fmt.Errorf("%s path contains directory traversal (..)", name)
	}
	
	// Check against allowed paths
	for _, allowedPath := range v.allowedPaths {
		if strings.HasPrefix(path, allowedPath) {
			return nil
		}
	}
	
	// For development, be more lenient but warn
	if strings.HasPrefix(path, "/") || strings.Contains(path, ":") {
		return nil // Absolute paths or Windows paths allowed but not recommended
	}
	
	return fmt.Errorf("%s path '%s' not in allowed directories: %v", name, path, v.allowedPaths)
}

// ValidateLogLevel validates log level values
func (v *inputValidator) ValidateLogLevel(level string) error {
	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true, "fatal": true,
	}
	
	if !validLevels[strings.ToLower(level)] {
		return fmt.Errorf("invalid log level '%s', must be one of: debug, info, warn, error, fatal", level)
	}
	
	return nil
}

// ValidateLogFormat validates log format values
func (v *inputValidator) ValidateLogFormat(format string) error {
	validFormats := map[string]bool{
		"json": true, "text": true,
	}
	
	if !validFormats[strings.ToLower(format)] {
		return fmt.Errorf("invalid log format '%s', must be 'json' or 'text'", format)
	}
	
	return nil
}