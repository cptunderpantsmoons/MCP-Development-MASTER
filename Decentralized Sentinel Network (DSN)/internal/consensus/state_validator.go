package consensus

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/dsn/decentralized-sentinel-network/pkg/logger"
)

// StateValidator validates system states for consensus
type StateValidator struct {
	logger           logger.Logger
	validationRules  map[string]ValidationRule
	thresholds       *ValidationThresholds
	historicalStates []StateValidationResult
	mu               sync.RWMutex
}

// ValidationRule represents a validation rule for system states
type ValidationRule struct {
	Name        string                 `json:"name"`
	Type        ValidationRuleType     `json:"type"`
	Enabled     bool                   `json:"enabled"`
	Severity    ValidationSeverity     `json:"severity"`
	Threshold   float64                `json:"threshold"`
	Description string                 `json:"description"`
	Validator   func(*SystemState) error `json:"-"`
}

// ValidationRuleType defines types of validation rules
type ValidationRuleType int

const (
	RuleTypeThreshold ValidationRuleType = iota
	RuleTypeRange
	RuleTypePattern
	RuleTypeConsistency
	RuleTypeSecurity
)

func (vrt ValidationRuleType) String() string {
	switch vrt {
	case RuleTypeThreshold:
		return "threshold"
	case RuleTypeRange:
		return "range"
	case RuleTypePattern:
		return "pattern"
	case RuleTypeConsistency:
		return "consistency"
	case RuleTypeSecurity:
		return "security"
	default:
		return "unknown"
	}
}

// ValidationSeverity defines severity levels for validation failures
type ValidationSeverity int

const (
	SeverityInfo ValidationSeverity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

func (vs ValidationSeverity) String() string {
	switch vs {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityError:
		return "error"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// ValidationThresholds holds various validation thresholds
type ValidationThresholds struct {
	MaxThreatLevel         ThreatLevel   `json:"max_threat_level"`
	MaxSecurityEvents      int           `json:"max_security_events"`
	MinHealthScore         float64       `json:"min_health_score"`
	MaxNodeDowntime        time.Duration `json:"max_node_downtime"`
	MinValidationScore     float64       `json:"min_validation_score"`
	MaxMemoryUsage         float64       `json:"max_memory_usage"`
	MaxCPUUsage           float64       `json:"max_cpu_usage"`
	MaxNetworkTraffic     uint64        `json:"max_network_traffic"`
	MinNodeCount          int           `json:"min_node_count"`
	MaxFailureRate        float64       `json:"max_failure_rate"`
}

// StateValidationResult represents the result of state validation
type StateValidationResult struct {
	StateHash      string                    `json:"state_hash"`
	Valid          bool                      `json:"valid"`
	ValidationTime time.Time                 `json:"validation_time"`
	Violations     []ValidationViolation     `json:"violations"`
	Score          float64                   `json:"score"`
	Recommendation string                    `json:"recommendation"`
	RulesApplied   []string                  `json:"rules_applied"`
}

// ValidationViolation represents a validation rule violation
type ValidationViolation struct {
	RuleName    string             `json:"rule_name"`
	Severity    ValidationSeverity `json:"severity"`
	Description string             `json:"description"`
	Expected    interface{}        `json:"expected"`
	Actual      interface{}        `json:"actual"`
	Timestamp   time.Time          `json:"timestamp"`
}

// NewStateValidator creates a new state validator
func NewStateValidator(logger logger.Logger) *StateValidator {
	validator := &StateValidator{
		logger:           logger.WithField(logger.FieldComponent, "state-validator"),
		validationRules:  make(map[string]ValidationRule),
		historicalStates: make([]StateValidationResult, 0, 1000),
		thresholds: &ValidationThresholds{
			MaxThreatLevel:     ThreatLevelHigh,
			MaxSecurityEvents:  100,
			MinHealthScore:     0.7,
			MaxNodeDowntime:    30 * time.Minute,
			MinValidationScore: 0.8,
			MaxMemoryUsage:     85.0,
			MaxCPUUsage:       80.0,
			MaxNetworkTraffic: 1000000000, // 1GB
			MinNodeCount:      2,
			MaxFailureRate:    0.1, // 10%
		},
	}

	// Initialize default validation rules
	validator.initializeDefaultRules()

	return validator
}

// ValidateState validates a system state against all rules
func (sv *StateValidator) ValidateState(state *SystemState) error {
	if state == nil {
		return fmt.Errorf("system state cannot be nil")
	}

	sv.logger.Debug("Validating system state",
		"state_hash", state.StateHash,
		"timestamp", state.Timestamp,
		"node_count", len(state.SentinelNodes),
	)

	startTime := time.Now()
	var violations []ValidationViolation
	var rulesApplied []string

	// Apply all enabled validation rules
	sv.mu.RLock()
	rules := make(map[string]ValidationRule)
	for k, v := range sv.validationRules {
		rules[k] = v
	}
	sv.mu.RUnlock()

	for ruleName, rule := range rules {
		if !rule.Enabled {
			continue
		}

		rulesApplied = append(rulesApplied, ruleName)

		if err := rule.Validator(state); err != nil {
			violation := ValidationViolation{
				RuleName:    ruleName,
				Severity:    rule.Severity,
				Description: err.Error(),
				Timestamp:   time.Now(),
			}
			violations = append(violations, violation)

			sv.logger.Debug("Validation rule violation",
				"rule", ruleName,
				"severity", rule.Severity.String(),
				"error", err.Error(),
			)
		}
	}

	// Calculate validation score
	score := sv.calculateValidationScore(violations)

	// Create validation result
	result := StateValidationResult{
		StateHash:      state.StateHash,
		Valid:          sv.determineValidity(violations),
		ValidationTime: time.Now(),
		Violations:     violations,
		Score:          score,
		Recommendation: sv.generateRecommendation(violations),
		RulesApplied:   rulesApplied,
	}

	// Store validation result
	sv.storeValidationResult(result)

	duration := time.Since(startTime)
	sv.logger.Debug("State validation completed",
		"state_hash", state.StateHash,
		"valid", result.Valid,
		"score", result.Score,
		"violations", len(violations),
		"duration", duration,
	)

	// Return error if validation failed critically
	if sv.hasCriticalViolations(violations) {
		return fmt.Errorf("state validation failed with critical violations: %s",
			sv.formatCriticalViolations(violations))
	}

	return nil
}

// initializeDefaultRules sets up the default validation rules
func (sv *StateValidator) initializeDefaultRules() {
	// Threat level validation
	sv.AddRule("threat_level_limit", ValidationRule{
		Name:        "threat_level_limit",
		Type:        RuleTypeThreshold,
		Enabled:     true,
		Severity:    SeverityError,
		Threshold:   float64(sv.thresholds.MaxThreatLevel),
		Description: "Threat level must not exceed maximum threshold",
		Validator:   sv.validateThreatLevel,
	})

	// Security events validation
	sv.AddRule("security_events_limit", ValidationRule{
		Name:        "security_events_limit",
		Type:        RuleTypeThreshold,
		Enabled:     true,
		Severity:    SeverityWarning,
		Threshold:   float64(sv.thresholds.MaxSecurityEvents),
		Description: "Number of security events must not exceed threshold",
		Validator:   sv.validateSecurityEventsCount,
	})

	// Node health validation
	sv.AddRule("node_health_minimum", ValidationRule{
		Name:        "node_health_minimum",
		Type:        RuleTypeThreshold,
		Enabled:     true,
		Severity:    SeverityError,
		Threshold:   sv.thresholds.MinHealthScore,
		Description: "Node health scores must meet minimum threshold",
		Validator:   sv.validateNodeHealth,
	})

	// Node count validation
	sv.AddRule("minimum_node_count", ValidationRule{
		Name:        "minimum_node_count",
		Type:        RuleTypeThreshold,
		Enabled:     true,
		Severity:    SeverityCritical,
		Threshold:   float64(sv.thresholds.MinNodeCount),
		Description: "Minimum number of active nodes required",
		Validator:   sv.validateNodeCount,
	})

	// Node status consistency
	sv.AddRule("node_status_consistency", ValidationRule{
		Name:        "node_status_consistency",
		Type:        RuleTypeConsistency,
		Enabled:     true,
		Severity:    SeverityWarning,
		Description: "Node statuses must be consistent with health scores",
		Validator:   sv.validateNodeStatusConsistency,
	})

	// Resource usage validation
	sv.AddRule("resource_usage_limits", ValidationRule{
		Name:        "resource_usage_limits",
		Type:        RuleTypeRange,
		Enabled:     true,
		Severity:    SeverityWarning,
		Description: "Resource usage must be within acceptable limits",
		Validator:   sv.validateResourceUsage,
	})

	// Timestamp validation
	sv.AddRule("timestamp_freshness", ValidationRule{
		Name:        "timestamp_freshness",
		Type:        RuleTypeRange,
		Enabled:     true,
		Severity:    SeverityError,
		Description: "State timestamp must be recent",
		Validator:   sv.validateTimestamp,
	})

	// Configuration hash validation
	sv.AddRule("config_hash_consistency", ValidationRule{
		Name:        "config_hash_consistency",
		Type:        RuleTypeConsistency,
		Enabled:     true,
		Severity:    SeverityInfo,
		Description: "Configuration hash should be consistent",
		Validator:   sv.validateConfigHash,
	})

	// Security pattern validation
	sv.AddRule("suspicious_activity_detection", ValidationRule{
		Name:        "suspicious_activity_detection",
		Type:        RuleTypeSecurity,
		Enabled:     true,
		Severity:    SeverityCritical,
		Description: "Detect suspicious patterns in security events",
		Validator:   sv.validateSuspiciousActivity,
	})

	sv.logger.Info("Default validation rules initialized", "rule_count", len(sv.validationRules))
}

// Validation rule implementations

func (sv *StateValidator) validateThreatLevel(state *SystemState) error {
	if state.ThreatLevel > sv.thresholds.MaxThreatLevel {
		return fmt.Errorf("threat level %s exceeds maximum %s",
			state.ThreatLevel.String(), sv.thresholds.MaxThreatLevel.String())
	}
	return nil
}

func (sv *StateValidator) validateSecurityEventsCount(state *SystemState) error {
	count := len(state.SecurityEvents)
	if count > sv.thresholds.MaxSecurityEvents {
		return fmt.Errorf("security events count %d exceeds maximum %d",
			count, sv.thresholds.MaxSecurityEvents)
	}
	return nil
}

func (sv *StateValidator) validateNodeHealth(state *SystemState) error {
	for nodeID, nodeState := range state.SentinelNodes {
		if nodeState.HealthScore < sv.thresholds.MinHealthScore {
			return fmt.Errorf("node %s health score %.2f below minimum %.2f",
				nodeID, nodeState.HealthScore, sv.thresholds.MinHealthScore)
		}
	}
	return nil
}

func (sv *StateValidator) validateNodeCount(state *SystemState) error {
	activeNodes := 0
	for _, nodeState := range state.SentinelNodes {
		if nodeState.Status == NodeStatusOnline {
			activeNodes++
		}
	}

	if activeNodes < sv.thresholds.MinNodeCount {
		return fmt.Errorf("active node count %d below minimum %d",
			activeNodes, sv.thresholds.MinNodeCount)
	}
	return nil
}

func (sv *StateValidator) validateNodeStatusConsistency(state *SystemState) error {
	for nodeID, nodeState := range state.SentinelNodes {
		// Check if node status matches health score
		if nodeState.Status == NodeStatusOnline && nodeState.HealthScore < 0.5 {
			return fmt.Errorf("node %s marked online but has low health score %.2f",
				nodeID, nodeState.HealthScore)
		}

		if nodeState.Status == NodeStatusOffline && nodeState.HealthScore > 0.8 {
			return fmt.Errorf("node %s marked offline but has high health score %.2f",
				nodeID, nodeState.HealthScore)
		}

		// Check node last seen time
		if nodeState.Status == NodeStatusOnline && 
		   time.Since(nodeState.LastSeen) > sv.thresholds.MaxNodeDowntime {
			return fmt.Errorf("node %s marked online but last seen %v ago",
				nodeID, time.Since(nodeState.LastSeen))
		}
	}
	return nil
}

func (sv *StateValidator) validateResourceUsage(state *SystemState) error {
	for nodeID, nodeState := range state.SentinelNodes {
		if nodeState.MetricSnapshot == nil {
			continue
		}

		metrics := nodeState.MetricSnapshot

		if metrics.CPUUsage > sv.thresholds.MaxCPUUsage {
			return fmt.Errorf("node %s CPU usage %.2f%% exceeds maximum %.2f%%",
				nodeID, metrics.CPUUsage, sv.thresholds.MaxCPUUsage)
		}

		if metrics.MemoryUsage > sv.thresholds.MaxMemoryUsage {
			return fmt.Errorf("node %s memory usage %.2f%% exceeds maximum %.2f%%",
				nodeID, metrics.MemoryUsage, sv.thresholds.MaxMemoryUsage)
		}

		totalNetworkTraffic := metrics.NetworkRX + metrics.NetworkTX
		if totalNetworkTraffic > sv.thresholds.MaxNetworkTraffic {
			return fmt.Errorf("node %s network traffic %d bytes exceeds maximum %d",
				nodeID, totalNetworkTraffic, sv.thresholds.MaxNetworkTraffic)
		}
	}
	return nil
}

func (sv *StateValidator) validateTimestamp(state *SystemState) error {
	now := time.Now()
	
	// State shouldn't be too old
	if now.Sub(state.Timestamp) > 1*time.Hour {
		return fmt.Errorf("state timestamp %v is too old (more than 1 hour)",
			state.Timestamp)
	}

	// State shouldn't be in the future
	if state.Timestamp.After(now.Add(5*time.Minute)) {
		return fmt.Errorf("state timestamp %v is in the future", state.Timestamp)
	}

	return nil
}

func (sv *StateValidator) validateConfigHash(state *SystemState) error {
	// Basic config hash validation
	if state.ConfigHash == "" {
		return fmt.Errorf("config hash cannot be empty")
	}

	if len(state.ConfigHash) < 16 {
		return fmt.Errorf("config hash too short: %s", state.ConfigHash)
	}

	return nil
}

func (sv *StateValidator) validateSuspiciousActivity(state *SystemState) error {
	// Look for suspicious patterns in security events
	criticalEvents := 0
	recentEvents := 0
	suspiciousPatterns := 0

	cutoff := time.Now().Add(-10 * time.Minute)

	for _, event := range state.SecurityEvents {
		if event.Severity == "critical" {
			criticalEvents++
		}

		if event.Timestamp.After(cutoff) {
			recentEvents++
		}

		// Check for suspicious patterns
		if sv.isSuspiciousEvent(event) {
			suspiciousPatterns++
		}
	}

	// Too many critical events
	if criticalEvents > 5 {
		return fmt.Errorf("too many critical security events: %d", criticalEvents)
	}

	// Too many recent events (possible attack)
	if recentEvents > 20 {
		return fmt.Errorf("suspicious spike in security events: %d in last 10 minutes",
			recentEvents)
	}

	// Suspicious patterns detected
	if suspiciousPatterns > 3 {
		return fmt.Errorf("suspicious activity patterns detected: %d", suspiciousPatterns)
	}

	return nil
}

func (sv *StateValidator) isSuspiciousEvent(event *SecurityEvent) bool {
	suspiciousTypes := []string{
		"privilege_escalation",
		"lateral_movement", 
		"data_exfiltration",
		"backdoor_installation",
		"credential_theft",
	}

	for _, suspiciousType := range suspiciousTypes {
		if strings.Contains(strings.ToLower(event.Type), suspiciousType) {
			return true
		}
	}

	return false
}

// Helper methods

func (sv *StateValidator) calculateValidationScore(violations []ValidationViolation) float64 {
	if len(violations) == 0 {
		return 1.0
	}

	penalty := 0.0
	for _, violation := range violations {
		switch violation.Severity {
		case SeverityCritical:
			penalty += 0.4
		case SeverityError:
			penalty += 0.2
		case SeverityWarning:
			penalty += 0.1
		case SeverityInfo:
			penalty += 0.05
		}
	}

	score := 1.0 - penalty
	return math.Max(score, 0.0)
}

func (sv *StateValidator) determineValidity(violations []ValidationViolation) bool {
	for _, violation := range violations {
		if violation.Severity == SeverityCritical || violation.Severity == SeverityError {
			return false
		}
	}
	return true
}

func (sv *StateValidator) generateRecommendation(violations []ValidationViolation) string {
	if len(violations) == 0 {
		return "State validation passed - no issues detected"
	}

	criticalCount := 0
	errorCount := 0
	warningCount := 0

	for _, violation := range violations {
		switch violation.Severity {
		case SeverityCritical:
			criticalCount++
		case SeverityError:
			errorCount++
		case SeverityWarning:
			warningCount++
		}
	}

	if criticalCount > 0 {
		return fmt.Sprintf("CRITICAL: %d critical issues require immediate attention", criticalCount)
	}

	if errorCount > 0 {
		return fmt.Sprintf("ERROR: %d errors must be resolved before proceeding", errorCount)
	}

	if warningCount > 0 {
		return fmt.Sprintf("WARNING: %d warnings should be addressed", warningCount)
	}

	return "State has minor issues but is acceptable"
}

func (sv *StateValidator) hasCriticalViolations(violations []ValidationViolation) bool {
	for _, violation := range violations {
		if violation.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

func (sv *StateValidator) formatCriticalViolations(violations []ValidationViolation) string {
	var messages []string
	for _, violation := range violations {
		if violation.Severity == SeverityCritical {
			messages = append(messages, fmt.Sprintf("%s: %s", violation.RuleName, violation.Description))
		}
	}
	return strings.Join(messages, "; ")
}

func (sv *StateValidator) storeValidationResult(result StateValidationResult) {
	sv.mu.Lock()
	defer sv.mu.Unlock()

	sv.historicalStates = append(sv.historicalStates, result)

	// Keep only last 1000 results
	if len(sv.historicalStates) > 1000 {
		sv.historicalStates = sv.historicalStates[1:]
	}
}

// Public API methods

// AddRule adds a new validation rule
func (sv *StateValidator) AddRule(name string, rule ValidationRule) {
	sv.mu.Lock()
	defer sv.mu.Unlock()

	sv.validationRules[name] = rule
	sv.logger.Info("Validation rule added",
		"rule_name", name,
		"type", rule.Type.String(),
		"severity", rule.Severity.String(),
	)
}

// RemoveRule removes a validation rule
func (sv *StateValidator) RemoveRule(name string) {
	sv.mu.Lock()
	defer sv.mu.Unlock()

	delete(sv.validationRules, name)
	sv.logger.Info("Validation rule removed", "rule_name", name)
}

// EnableRule enables a validation rule
func (sv *StateValidator) EnableRule(name string) error {
	sv.mu.Lock()
	defer sv.mu.Unlock()

	rule, exists := sv.validationRules[name]
	if !exists {
		return fmt.Errorf("rule %s not found", name)
	}

	rule.Enabled = true
	sv.validationRules[name] = rule
	return nil
}

// DisableRule disables a validation rule
func (sv *StateValidator) DisableRule(name string) error {
	sv.mu.Lock()
	defer sv.mu.Unlock()

	rule, exists := sv.validationRules[name]
	if !exists {
		return fmt.Errorf("rule %s not found", name)
	}

	rule.Enabled = false
	sv.validationRules[name] = rule
	return nil
}

// UpdateThresholds updates validation thresholds
func (sv *StateValidator) UpdateThresholds(thresholds *ValidationThresholds) {
	sv.mu.Lock()
	defer sv.mu.Unlock()

	sv.thresholds = thresholds
	sv.logger.Info("Validation thresholds updated")
}

// GetValidationStats returns validation statistics
func (sv *StateValidator) GetValidationStats() map[string]interface{} {
	sv.mu.RLock()
	defer sv.mu.RUnlock()

	totalValidations := len(sv.historicalStates)
	if totalValidations == 0 {
		return map[string]interface{}{
			"total_validations": 0,
			"success_rate":      0.0,
		}
	}

	successCount := 0
	violationCounts := make(map[string]int)

	for _, result := range sv.historicalStates {
		if result.Valid {
			successCount++
		}

		for _, violation := range result.Violations {
			violationCounts[violation.Severity.String()]++
		}
	}

	successRate := float64(successCount) / float64(totalValidations) * 100

	return map[string]interface{}{
		"total_validations":    totalValidations,
		"successful_validations": successCount,
		"success_rate":         successRate,
		"violation_counts":     violationCounts,
		"active_rules":         len(sv.validationRules),
		"enabled_rules": func() int {
			count := 0
			for _, rule := range sv.validationRules {
				if rule.Enabled {
					count++
				}
			}
			return count
		}(),
	}
}

// GetRules returns all validation rules
func (sv *StateValidator) GetRules() map[string]ValidationRule {
	sv.mu.RLock()
	defer sv.mu.RUnlock()

	rules := make(map[string]ValidationRule)
	for k, v := range sv.validationRules {
		rules[k] = v
	}
	return rules
}

// IsHealthy returns whether the validator is operating normally
func (sv *StateValidator) IsHealthy() bool {
	sv.mu.RLock()
	defer sv.mu.RUnlock()

	// Check recent validation success rate
	recentValidations := sv.getRecentValidations(24 * time.Hour)
	if len(recentValidations) > 5 {
		successCount := 0
		for _, result := range recentValidations {
			if result.Valid {
				successCount++
			}
		}
		successRate := float64(successCount) / float64(len(recentValidations))
		return successRate > 0.7 // 70% success rate minimum
	}

	return true // Healthy if not enough data
}

func (sv *StateValidator) getRecentValidations(duration time.Duration) []StateValidationResult {
	cutoff := time.Now().Add(-duration)
	var recent []StateValidationResult

	for _, result := range sv.historicalStates {
		if result.ValidationTime.After(cutoff) {
			recent = append(recent, result)
		}
	}

	return recent
}
