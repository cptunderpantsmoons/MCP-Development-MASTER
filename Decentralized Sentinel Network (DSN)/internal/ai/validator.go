package ai

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/dsn/decentralized-sentinel-network/pkg/logger"
)

// ThreatValidator validates AI predictions for security and accuracy
type ThreatValidator struct {
	config              *ValidationConfig
	knownPatterns       map[string]PatternInfo
	falsePositiveCache  map[string]FalsePositiveInfo
	validationHistory   []ValidationResult
	logger              logger.Logger
	mu                  sync.RWMutex
}

// ValidationConfig holds validation parameters
type ValidationConfig struct {
	MinConfidence         float64           `json:"min_confidence"`
	MaxFalsePositiveRate  float64           `json:"max_false_positive_rate"`
	RequiredIndicators    int               `json:"required_indicators"`
	MaxSeverityEscalation ThreatSeverity    `json:"max_severity_escalation"`
	ValidationTimeout     time.Duration     `json:"validation_timeout"`
	WhitelistedSources    []string          `json:"whitelisted_sources"`
	BlacklistedPatterns   []string          `json:"blacklisted_patterns"`
}

// PatternInfo stores information about known threat patterns
type PatternInfo struct {
	Pattern         string    `json:"pattern"`
	ThreatLevel     float64   `json:"threat_level"`
	Confidence      float64   `json:"confidence"`
	LastSeen        time.Time `json:"last_seen"`
	Frequency       int       `json:"frequency"`
	Verified        bool      `json:"verified"`
	Source          string    `json:"source"`
}

// FalsePositiveInfo tracks false positive patterns
type FalsePositiveInfo struct {
	Pattern         string    `json:"pattern"`
	Count           int       `json:"count"`
	LastOccurrence  time.Time `json:"last_occurrence"`
	Confidence      float64   `json:"confidence"`
	ReportedBy      []string  `json:"reported_by"`
}

// ValidationResult represents the result of threat assessment validation
type ValidationResult struct {
	AssessmentID     string                 `json:"assessment_id"`
	Valid            bool                   `json:"valid"`
	Confidence       float64                `json:"confidence"`
	ValidationTime   time.Time              `json:"validation_time"`
	Violations       []ValidationViolation  `json:"violations"`
	AdjustedSeverity ThreatSeverity         `json:"adjusted_severity"`
	Recommendation   string                 `json:"recommendation"`
}

// ValidationViolation represents a validation rule violation
type ValidationViolation struct {
	Rule        string    `json:"rule"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	Timestamp   time.Time `json:"timestamp"`
}

// NewThreatValidator creates a new threat validator with security defaults
func NewThreatValidator(logger logger.Logger) *ThreatValidator {
	config := &ValidationConfig{
		MinConfidence:         0.7,
		MaxFalsePositiveRate:  0.05,
		RequiredIndicators:    2,
		MaxSeverityEscalation: SeverityHigh,
		ValidationTimeout:     5 * time.Second,
		WhitelistedSources: []string{
			"signature_db",
			"anomaly_detector", 
			"behavioral_analyzer",
			"threat_intelligence",
		},
		BlacklistedPatterns: []string{
			"test_pattern",
			"debug_indicator",
			"benign_activity",
		},
	}

	return &ThreatValidator{
		config:             config,
		knownPatterns:      make(map[string]PatternInfo),
		falsePositiveCache: make(map[string]FalsePositiveInfo),
		validationHistory:  make([]ValidationResult, 0, 1000),
		logger:             logger.WithField(logger.FieldComponent, "threat-validator"),
	}
}

// ValidateAssessment validates a threat assessment for security and accuracy
func (tv *ThreatValidator) ValidateAssessment(assessment *ThreatAssessment) error {
	if assessment == nil {
		return fmt.Errorf("assessment cannot be nil")
	}

	tv.logger.Debug("Validating threat assessment",
		"threat_id", assessment.ThreatID,
		"confidence", assessment.Confidence,
		"severity", assessment.Severity.String(),
	)

	startTime := time.Now()
	defer func() {
		tv.logger.Debug("Threat assessment validation completed",
			"threat_id", assessment.ThreatID,
			"duration", time.Since(startTime),
		)
	}()

	var violations []ValidationViolation

	// 1. Validate confidence threshold
	if assessment.Confidence < tv.config.MinConfidence {
		violations = append(violations, ValidationViolation{
			Rule: "min_confidence",
			Description: fmt.Sprintf("Confidence %.2f below minimum threshold %.2f",
				assessment.Confidence, tv.config.MinConfidence),
			Severity:  "error",
			Timestamp: time.Now(),
		})
	}

	// 2. Validate required indicators
	if len(assessment.Indicators) < tv.config.RequiredIndicators {
		violations = append(violations, ValidationViolation{
			Rule: "required_indicators",
			Description: fmt.Sprintf("Only %d indicators provided, minimum %d required",
				len(assessment.Indicators), tv.config.RequiredIndicators),
			Severity:  "warning",
			Timestamp: time.Now(),
		})
	}

	// 3. Validate indicator sources
	for _, indicator := range assessment.Indicators {
		if !tv.isWhitelistedSource(indicator.Source) {
			violations = append(violations, ValidationViolation{
				Rule: "source_validation",
				Description: fmt.Sprintf("Indicator source '%s' not whitelisted", indicator.Source),
				Severity:  "warning",
				Timestamp: time.Now(),
			})
		}
	}

	// 4. Check for false positive patterns
	for _, indicator := range assessment.Indicators {
		if tv.isFalsePositivePattern(indicator.Value) {
			violations = append(violations, ValidationViolation{
				Rule: "false_positive_check",
				Description: fmt.Sprintf("Indicator '%s' matches known false positive pattern", indicator.Value),
				Severity:  "warning",
				Timestamp: time.Now(),
			})
		}
	}

	// 5. Validate severity escalation
	adjustedSeverity := tv.validateSeverity(assessment)
	if adjustedSeverity != assessment.Severity {
		violations = append(violations, ValidationViolation{
			Rule: "severity_validation",
			Description: fmt.Sprintf("Severity adjusted from %s to %s",
				assessment.Severity.String(), adjustedSeverity.String()),
			Severity:  "info",
			Timestamp: time.Now(),
		})
		assessment.Severity = adjustedSeverity
	}

	// 6. Validate threat type consistency
	if err := tv.validateThreatTypeConsistency(assessment); err != nil {
		violations = append(violations, ValidationViolation{
			Rule:        "threat_type_consistency",
			Description: err.Error(),
			Severity:    "error",
			Timestamp:   time.Now(),
		})
	}

	// 7. Cross-reference with known patterns
	tv.crossReferencePatterns(assessment, &violations)

	// 8. Validate timestamp freshness
	if time.Since(assessment.Timestamp) > 1*time.Hour {
		violations = append(violations, ValidationViolation{
			Rule: "timestamp_freshness",
			Description: fmt.Sprintf("Assessment timestamp is %v old",
				time.Since(assessment.Timestamp)),
			Severity:  "warning",
			Timestamp: time.Now(),
		})
	}

	// Create validation result
	result := ValidationResult{
		AssessmentID:     assessment.ThreatID,
		Valid:            len(violations) == 0 || tv.hasOnlyWarnings(violations),
		Confidence:       tv.calculateValidationConfidence(assessment, violations),
		ValidationTime:   time.Now(),
		Violations:       violations,
		AdjustedSeverity: assessment.Severity,
		Recommendation:   tv.generateRecommendation(assessment, violations),
	}

	// Store validation result
	tv.storeValidationResult(result)

	// Determine if assessment should be rejected
	criticalViolations := tv.getCriticalViolations(violations)
	if len(criticalViolations) > 0 {
		return fmt.Errorf("threat assessment validation failed: %s",
			tv.formatViolations(criticalViolations))
	}

	// Log warnings for non-critical violations
	if len(violations) > 0 {
		tv.logger.Warn("Threat assessment has validation warnings",
			"threat_id", assessment.ThreatID,
			"violation_count", len(violations),
		)
	}

	return nil
}

// UpdateKnownPattern adds or updates a known threat pattern
func (tv *ThreatValidator) UpdateKnownPattern(pattern string, info PatternInfo) {
	tv.mu.Lock()
	defer tv.mu.Unlock()

	info.LastSeen = time.Now()
	if existing, exists := tv.knownPatterns[pattern]; exists {
		info.Frequency = existing.Frequency + 1
	} else {
		info.Frequency = 1
	}

	tv.knownPatterns[pattern] = info
	tv.logger.Debug("Updated known pattern",
		"pattern", pattern,
		"threat_level", info.ThreatLevel,
		"frequency", info.Frequency,
	)
}

// ReportFalsePositive reports a false positive pattern
func (tv *ThreatValidator) ReportFalsePositive(pattern string, reportedBy string) {
	tv.mu.Lock()
	defer tv.mu.Unlock()

	if existing, exists := tv.falsePositiveCache[pattern]; exists {
		existing.Count++
		existing.LastOccurrence = time.Now()
		existing.ReportedBy = append(existing.ReportedBy, reportedBy)
		tv.falsePositiveCache[pattern] = existing
	} else {
		tv.falsePositiveCache[pattern] = FalsePositiveInfo{
			Pattern:        pattern,
			Count:          1,
			LastOccurrence: time.Now(),
			Confidence:     0.7,
			ReportedBy:     []string{reportedBy},
		}
	}

	tv.logger.Info("False positive reported",
		"pattern", pattern,
		"reported_by", reportedBy,
		"total_reports", tv.falsePositiveCache[pattern].Count,
	)
}

// Helper methods

func (tv *ThreatValidator) isWhitelistedSource(source string) bool {
	for _, whitelisted := range tv.config.WhitelistedSources {
		if source == whitelisted {
			return true
		}
	}
	return false
}

func (tv *ThreatValidator) isFalsePositivePattern(value string) bool {
	tv.mu.RLock()
	defer tv.mu.RUnlock()

	// Check against known false positive cache
	if fpInfo, exists := tv.falsePositiveCache[value]; exists {
		return fpInfo.Confidence > 0.5
	}

	// Check against blacklisted patterns
	for _, pattern := range tv.config.BlacklistedPatterns {
		if strings.Contains(value, pattern) {
			return true
		}
	}

	return false
}

func (tv *ThreatValidator) validateSeverity(assessment *ThreatAssessment) ThreatSeverity {
	// Calculate severity based on confidence and indicator count
	calculatedSeverity := tv.calculateSeverityFromMetrics(assessment)
	
	// Don't allow escalation beyond configured maximum
	if calculatedSeverity > tv.config.MaxSeverityEscalation {
		return tv.config.MaxSeverityEscalation
	}

	// Don't allow downgrade below Low if we have high confidence
	if assessment.Confidence > 0.9 && calculatedSeverity < SeverityMedium {
		return SeverityMedium
	}

	return calculatedSeverity
}

func (tv *ThreatValidator) calculateSeverityFromMetrics(assessment *ThreatAssessment) ThreatSeverity {
	score := assessment.Confidence

	// Add weight for number of indicators
	score += float64(len(assessment.Indicators)) * 0.1

	// Add weight for high-confidence indicators
	for _, indicator := range assessment.Indicators {
		if indicator.Confidence > 0.8 {
			score += 0.1
		}
	}

	// Convert score to severity
	switch {
	case score >= 1.2:
		return SeverityCritical
	case score >= 0.9:
		return SeverityHigh
	case score >= 0.6:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

func (tv *ThreatValidator) validateThreatTypeConsistency(assessment *ThreatAssessment) error {
	expectedTypes := map[string][]string{
		"signature_based": {"file_hash", "process_pattern", "registry_key"},
		"anomaly_based":   {"cpu_anomaly", "memory_anomaly", "network_anomaly"},
		"behavioral":      {"suspicious_activity", "access_pattern", "user_behavior"},
	}

	if expectedIndicators, exists := expectedTypes[assessment.ThreatType]; exists {
		foundExpected := false
		for _, indicator := range assessment.Indicators {
			for _, expected := range expectedIndicators {
				if indicator.Type == expected {
					foundExpected = true
					break
				}
			}
			if foundExpected {
				break
			}
		}

		if !foundExpected {
			return fmt.Errorf("threat type '%s' inconsistent with indicator types",
				assessment.ThreatType)
		}
	}

	return nil
}

func (tv *ThreatValidator) crossReferencePatterns(assessment *ThreatAssessment, violations *[]ValidationViolation) {
	tv.mu.RLock()
	defer tv.mu.RUnlock()

	for _, indicator := range assessment.Indicators {
		if pattern, exists := tv.knownPatterns[indicator.Value]; exists {
			// Update frequency
			pattern.Frequency++
			pattern.LastSeen = time.Now()
			tv.knownPatterns[indicator.Value] = pattern

			// Check if confidence matches known pattern
			confidenceDiff := math.Abs(indicator.Confidence - pattern.Confidence)
			if confidenceDiff > 0.3 {
				*violations = append(*violations, ValidationViolation{
					Rule: "pattern_confidence_mismatch",
					Description: fmt.Sprintf("Indicator confidence %.2f differs from known pattern confidence %.2f",
						indicator.Confidence, pattern.Confidence),
					Severity:  "warning",
					Timestamp: time.Now(),
				})
			}
		}
	}
}

func (tv *ThreatValidator) hasOnlyWarnings(violations []ValidationViolation) bool {
	for _, violation := range violations {
		if violation.Severity == "error" {
			return false
		}
	}
	return true
}

func (tv *ThreatValidator) calculateValidationConfidence(assessment *ThreatAssessment, violations []ValidationViolation) float64 {
	baseConfidence := assessment.Confidence

	// Reduce confidence for each violation
	for _, violation := range violations {
		switch violation.Severity {
		case "error":
			baseConfidence -= 0.3
		case "warning":
			baseConfidence -= 0.1
		}
	}

	// Ensure confidence stays in valid range
	if baseConfidence < 0 {
		baseConfidence = 0
	}
	if baseConfidence > 1 {
		baseConfidence = 1
	}

	return baseConfidence
}

func (tv *ThreatValidator) generateRecommendation(assessment *ThreatAssessment, violations []ValidationViolation) string {
	if len(violations) == 0 {
		return "Assessment passed all validation checks"
	}

	errorCount := 0
	warningCount := 0
	for _, violation := range violations {
		if violation.Severity == "error" {
			errorCount++
		} else if violation.Severity == "warning" {
			warningCount++
		}
	}

	if errorCount > 0 {
		return fmt.Sprintf("Assessment has %d critical issues requiring attention", errorCount)
	}

	if warningCount > 0 {
		return fmt.Sprintf("Assessment has %d warnings - proceed with caution", warningCount)
	}

	return "Assessment requires manual review"
}

func (tv *ThreatValidator) getCriticalViolations(violations []ValidationViolation) []ValidationViolation {
	var critical []ValidationViolation
	for _, violation := range violations {
		if violation.Severity == "error" {
			critical = append(critical, violation)
		}
	}
	return critical
}

func (tv *ThreatValidator) formatViolations(violations []ValidationViolation) string {
	var messages []string
	for _, violation := range violations {
		messages = append(messages, fmt.Sprintf("%s: %s", violation.Rule, violation.Description))
	}
	return strings.Join(messages, "; ")
}

func (tv *ThreatValidator) storeValidationResult(result ValidationResult) {
	tv.mu.Lock()
	defer tv.mu.Unlock()

	// Add to history
	tv.validationHistory = append(tv.validationHistory, result)

	// Keep only last 1000 results
	if len(tv.validationHistory) > 1000 {
		tv.validationHistory = tv.validationHistory[1:]
	}
}

// GetValidationStats returns validation statistics
func (tv *ThreatValidator) GetValidationStats() map[string]interface{} {
	tv.mu.RLock()
	defer tv.mu.RUnlock()

	totalValidations := len(tv.validationHistory)
	if totalValidations == 0 {
		return map[string]interface{}{
			"total_validations": 0,
			"success_rate":      0.0,
		}
	}

	successCount := 0
	errorCount := 0
	warningCount := 0

	for _, result := range tv.validationHistory {
		if result.Valid {
			successCount++
		}
		for _, violation := range result.Violations {
			if violation.Severity == "error" {
				errorCount++
			} else if violation.Severity == "warning" {
				warningCount++
			}
		}
	}

	successRate := float64(successCount) / float64(totalValidations) * 100

	return map[string]interface{}{
		"total_validations":     totalValidations,
		"successful_validations": successCount,
		"success_rate":          successRate,
		"total_errors":          errorCount,
		"total_warnings":        warningCount,
		"known_patterns":        len(tv.knownPatterns),
		"false_positive_cache":  len(tv.falsePositiveCache),
	}
}

// UpdateConfig updates the validation configuration
func (tv *ThreatValidator) UpdateConfig(config *ValidationConfig) {
	tv.mu.Lock()
	defer tv.mu.Unlock()

	tv.config = config
	tv.logger.Info("Threat validator configuration updated",
		"min_confidence", config.MinConfidence,
		"max_false_positive_rate", config.MaxFalsePositiveRate,
		"required_indicators", config.RequiredIndicators,
	)
}

// IsHealthy returns whether the validator is operating normally
func (tv *ThreatValidator) IsHealthy() bool {
	tv.mu.RLock()
	defer tv.mu.RUnlock()

	// Check recent validation success rate
	recentValidations := tv.getRecentValidations(24 * time.Hour)
	if len(recentValidations) > 10 {
		successCount := 0
		for _, result := range recentValidations {
			if result.Valid {
				successCount++
			}
		}
		successRate := float64(successCount) / float64(len(recentValidations))
		return successRate > 0.8 // 80% success rate minimum
	}

	return true // Healthy if not enough data
}

func (tv *ThreatValidator) getRecentValidations(duration time.Duration) []ValidationResult {
	cutoff := time.Now().Add(-duration)
	var recent []ValidationResult

	for _, result := range tv.validationHistory {
		if result.ValidationTime.After(cutoff) {
			recent = append(recent, result)
		}
	}

	return recent
}
