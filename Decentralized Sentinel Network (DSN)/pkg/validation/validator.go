package validation

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Validator provides comprehensive input validation
type Validator struct {
	allowedPaths     []string
	allowedNetworks  []*net.IPNet
	maxStringLength  int
	maxArrayLength   int
}

// ValidationError represents a validation error
type ValidationError struct {
	Field   string
	Value   interface{}
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("validation error for field '%s': %s (value: %v)", e.Field, e.Message, e.Value)
}

// NewValidator creates a new validator with security defaults
func NewValidator() *Validator {
	return &Validator{
		allowedPaths: []string{
			"/etc/dsn/",
			"/var/lib/dsn/",
			"/tmp/dsn/",
		},
		maxStringLength: 1024,
		maxArrayLength:  100,
	}
}

// ValidateSentinelID validates a sentinel ID format
func (v *Validator) ValidateSentinelID(id string) error {
	if id == "" {
		return &ValidationError{"sentinel_id", id, "cannot be empty"}
	}
	
	// Allow alphanumeric, hyphens, and underscores, length 8-64
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]{8,64}$`, id)
	if !matched {
		return &ValidationError{"sentinel_id", id, "must be 8-64 characters, alphanumeric with hyphens/underscores only"}
	}
	
	return nil
}

// ValidatePort validates a network port number
func (v *Validator) ValidatePort(port int, fieldName string) error {
	if port <= 0 || port > 65535 {
		return &ValidationError{fieldName, port, "must be between 1 and 65535"}
	}
	
	// Check for privileged ports in production
	if port < 1024 {
		return &ValidationError{fieldName, port, "privileged ports (<1024) should be avoided"}
	}
	
	return nil
}

// ValidateFilePath validates and sanitizes file paths
func (v *Validator) ValidateFilePath(path string, fieldName string) error {
	if path == "" {
		return &ValidationError{fieldName, path, "cannot be empty"}
	}
	
	// Check for directory traversal attacks
	if strings.Contains(path, "..") {
		return &ValidationError{fieldName, path, "path traversal detected"}
	}
	
	// Convert to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return &ValidationError{fieldName, path, fmt.Sprintf("invalid path: %v", err)}
	}
	
	// Check if path is within allowed directories
	for _, allowedPath := range v.allowedPaths {
		if strings.HasPrefix(absPath, allowedPath) {
			return nil
		}
	}
	
	return &ValidationError{fieldName, path, "path outside allowed directories"}
}

// ValidateURL validates and sanitizes URLs
func (v *Validator) ValidateURL(rawURL string, fieldName string) error {
	if rawURL == "" {
		return &ValidationError{fieldName, rawURL, "cannot be empty"}
	}
	
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return &ValidationError{fieldName, rawURL, fmt.Sprintf("invalid URL: %v", err)}
	}
	
	// Only allow HTTPS in production
	if parsedURL.Scheme != "https" && parsedURL.Scheme != "http" {
		return &ValidationError{fieldName, rawURL, "only HTTP(S) URLs allowed"}
	}
	
	// Validate hostname
	if parsedURL.Host == "" {
		return &ValidationError{fieldName, rawURL, "hostname cannot be empty"}
	}
	
	// Check for localhost/private IPs in production URLs
	if v.isPrivateOrLocalhost(parsedURL.Host) {
		return &ValidationError{fieldName, rawURL, "private or localhost URLs not allowed in production"}
	}
	
	return nil
}

// ValidateNetworkEndpoints validates an array of network endpoints
func (v *Validator) ValidateNetworkEndpoints(endpoints []string, fieldName string) error {
	if len(endpoints) == 0 {
		return &ValidationError{fieldName, endpoints, "at least one endpoint required"}
	}
	
	if len(endpoints) > v.maxArrayLength {
		return &ValidationError{fieldName, endpoints, fmt.Sprintf("too many endpoints (max %d)", v.maxArrayLength)}
	}
	
	for i, endpoint := range endpoints {
		if err := v.ValidateNetworkEndpoint(endpoint, fmt.Sprintf("%s[%d]", fieldName, i)); err != nil {
			return err
		}
	}
	
	return nil
}

// ValidateNetworkEndpoint validates a single network endpoint
func (v *Validator) ValidateNetworkEndpoint(endpoint string, fieldName string) error {
	if endpoint == "" {
		return &ValidationError{fieldName, endpoint, "cannot be empty"}
	}
	
	// Check for host:port format
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return &ValidationError{fieldName, endpoint, fmt.Sprintf("invalid host:port format: %v", err)}
	}
	
	// Validate hostname/IP
	if host == "" {
		return &ValidationError{fieldName, endpoint, "hostname cannot be empty"}
	}
	
	// Check if it's a valid IP or hostname
	if ip := net.ParseIP(host); ip != nil {
		// It's an IP address, check if it's allowed
		if v.isPrivateIP(ip) {
			return &ValidationError{fieldName, endpoint, "private IP addresses not allowed"}
		}
	} else {
		// It's a hostname, validate format
		if !v.isValidHostname(host) {
			return &ValidationError{fieldName, endpoint, "invalid hostname format"}
		}
	}
	
	// Validate port
	if port == "" {
		return &ValidationError{fieldName, endpoint, "port cannot be empty"}
	}
	
	return nil
}

// ValidateLogLevel validates log level values
func (v *Validator) ValidateLogLevel(level string, fieldName string) error {
	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
		"fatal": true,
	}
	
	if !validLevels[strings.ToLower(level)] {
		return &ValidationError{fieldName, level, "must be one of: debug, info, warn, error, fatal"}
	}
	
	return nil
}

// ValidateLogFormat validates log format values
func (v *Validator) ValidateLogFormat(format string, fieldName string) error {
	validFormats := map[string]bool{
		"json": true,
		"text": true,
	}
	
	if !validFormats[strings.ToLower(format)] {
		return &ValidationError{fieldName, format, "must be either 'json' or 'text'"}
	}
	
	return nil
}

// ValidateDuration validates duration strings
func (v *Validator) ValidateDuration(duration string, fieldName string) error {
	if duration == "" {
		return &ValidationError{fieldName, duration, "cannot be empty"}
	}
	
	parsed, err := time.ParseDuration(duration)
	if err != nil {
		return &ValidationError{fieldName, duration, fmt.Sprintf("invalid duration format: %v", err)}
	}
	
	// Reasonable bounds checking
	if parsed < 0 {
		return &ValidationError{fieldName, duration, "duration cannot be negative"}
	}
	
	if parsed > 24*time.Hour {
		return &ValidationError{fieldName, duration, "duration too long (max 24h)"}
	}
	
	return nil
}

// ValidateStringLength validates string length
func (v *Validator) ValidateStringLength(value string, fieldName string, maxLength int) error {
	if maxLength == 0 {
		maxLength = v.maxStringLength
	}
	
	if len(value) > maxLength {
		return &ValidationError{fieldName, value, fmt.Sprintf("too long (max %d characters)", maxLength)}
	}
	
	return nil
}

// ValidatePercentage validates percentage values (0-100)
func (v *Validator) ValidatePercentage(value float64, fieldName string) error {
	if value < 0 || value > 100 {
		return &ValidationError{fieldName, value, "must be between 0 and 100"}
	}
	
	return nil
}

// Helper methods

func (v *Validator) isPrivateOrLocalhost(host string) bool {
	// Check for localhost
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	
	// Check for private IP ranges
	ip := net.ParseIP(host)
	if ip != nil {
		return v.isPrivateIP(ip)
	}
	
	return false
}

func (v *Validator) isPrivateIP(ip net.IP) bool {
	// Private IPv4 ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}
	
	for _, rangeStr := range privateRanges {
		_, network, _ := net.ParseCIDR(rangeStr)
		if network.Contains(ip) {
			return true
		}
	}
	
	return false
}

func (v *Validator) isValidHostname(hostname string) bool {
	// Basic hostname validation
	if len(hostname) == 0 || len(hostname) > 253 {
		return false
	}
	
	// Check for valid hostname format
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`, hostname)
	return matched
}

// AddAllowedPath adds a path to the allowed paths list
func (v *Validator) AddAllowedPath(path string) {
	v.allowedPaths = append(v.allowedPaths, path)
}

// AddAllowedNetwork adds a network to the allowed networks list
func (v *Validator) AddAllowedNetwork(network string) error {
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("invalid network CIDR: %w", err)
	}
	
	v.allowedNetworks = append(v.allowedNetworks, ipNet)
	return nil
}
