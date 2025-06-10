package healing

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/dsn/decentralized-sentinel-network/internal/ai"
	"github.com/dsn/decentralized-sentinel-network/pkg/logger"
)

// StrategyRegistry manages healing strategies for different threat types
type StrategyRegistry struct {
	logger     logger.Logger
	strategies map[string]*HealingStrategy
	selectors  []StrategySelector
	mu         sync.RWMutex
}

// HealingStrategy defines a strategy for responding to threats
type HealingStrategy struct {
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	ThreatTypes     []string               `json:"threat_types"`
	MinSeverity     ai.ThreatSeverity     `json:"min_severity"`
	MaxSeverity     ai.ThreatSeverity     `json:"max_severity"`
	Actions         []*ActionPlan          `json:"actions"`
	Prerequisites   []string               `json:"prerequisites"`
	EstimatedTime   time.Duration          `json:"estimated_time"`
	SuccessRate     float64                `json:"success_rate"`
	RiskLevel       StrategyRiskLevel      `json:"risk_level"`
	Priority        int                    `json:"priority"`
	Enabled         bool                   `json:"enabled"`
	CreatedAt       time.Time              `json:"created_at"`
	LastUsed        *time.Time             `json:"last_used,omitempty"`
	UseCount        int                    `json:"use_count"`
	SuccessCount    int                    `json:"success_count"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ActionPlan defines a planned action within a strategy
type ActionPlan struct {
	Type         ActionType             `json:"type"`
	Description  string                 `json:"description"`
	Parameters   map[string]interface{} `json:"parameters"`
	Order        int                    `json:"order"`
	Critical     bool                   `json:"critical"`
	DelayAfter   time.Duration          `json:"delay_after"`
	Timeout      time.Duration          `json:"timeout"`
	MinSeverity  *ai.ThreatSeverity    `json:"min_severity,omitempty"`
	ThreatTypes  []string               `json:"threat_types,omitempty"`
	Conditions   []ActionCondition      `json:"conditions"`
	Rollback     *ActionPlan            `json:"rollback,omitempty"`
}

// ActionCondition defines when an action should be executed
type ActionCondition struct {
	Type        ConditionType          `json:"type"`
	Parameter   string                 `json:"parameter"`
	Operator    ConditionOperator      `json:"operator"`
	Value       interface{}            `json:"value"`
	Description string                 `json:"description"`
}

// StrategySelector selects the best strategy for a threat
type StrategySelector interface {
	SelectStrategy(threat *ai.ThreatAssessment, strategies []*HealingStrategy) (*HealingStrategy, error)
	GetSelectionCriteria() []string
	GetWeight() float64
}

// Enums for strategy system

type StrategyRiskLevel int

const (
	RiskLevelLow StrategyRiskLevel = iota
	RiskLevelMedium
	RiskLevelHigh
	RiskLevelCritical
)

func (srl StrategyRiskLevel) String() string {
	switch srl {
	case RiskLevelLow:
		return "low"
	case RiskLevelMedium:
		return "medium"
	case RiskLevelHigh:
		return "high"
	case RiskLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

type ConditionType int

const (
	ConditionThreatSeverity ConditionType = iota
	ConditionThreatType
	ConditionConfidence
	ConditionIndicatorCount
	ConditionSystemLoad
	ConditionTimeOfDay
)

func (ct ConditionType) String() string {
	switch ct {
	case ConditionThreatSeverity:
		return "threat_severity"
	case ConditionThreatType:
		return "threat_type"
	case ConditionConfidence:
		return "confidence"
	case ConditionIndicatorCount:
		return "indicator_count"
	case ConditionSystemLoad:
		return "system_load"
	case ConditionTimeOfDay:
		return "time_of_day"
	default:
		return "unknown"
	}
}

type ConditionOperator int

const (
	OperatorEqual ConditionOperator = iota
	OperatorNotEqual
	OperatorGreaterThan
	OperatorLessThan
	OperatorGreaterThanOrEqual
	OperatorLessThanOrEqual
	OperatorContains
	OperatorNotContains
)

func (co ConditionOperator) String() string {
	switch co {
	case OperatorEqual:
		return "eq"
	case OperatorNotEqual:
		return "ne"
	case OperatorGreaterThan:
		return "gt"
	case OperatorLessThan:
		return "lt"
	case OperatorGreaterThanOrEqual:
		return "gte"
	case OperatorLessThanOrEqual:
		return "lte"
	case OperatorContains:
		return "contains"
	case OperatorNotContains:
		return "not_contains"
	default:
		return "unknown"
	}
}

// NewStrategyRegistry creates a new strategy registry
func NewStrategyRegistry(log logger.Logger) *StrategyRegistry {
	registry := &StrategyRegistry{
		logger:     log.WithField(logger.FieldComponent, "strategy-registry"),
		strategies: make(map[string]*HealingStrategy),
		selectors:  make([]StrategySelector, 0),
	}

	// Initialize default strategy selectors
	registry.initializeDefaultSelectors()
	
	// Load default strategies
	registry.loadDefaultStrategies()

	return registry
}

// SelectStrategy selects the best healing strategy for a threat
func (sr *StrategyRegistry) SelectStrategy(threat *ai.ThreatAssessment) (*HealingStrategy, error) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	if threat == nil {
		return nil, fmt.Errorf("threat assessment cannot be nil")
	}

	sr.logger.Debug("Selecting healing strategy",
		"threat_type", threat.ThreatType,
		"severity", threat.Severity.String(),
		"confidence", threat.Confidence,
	)

	// Filter strategies by threat compatibility
	compatibleStrategies := sr.getCompatibleStrategies(threat)
	if len(compatibleStrategies) == 0 {
		return nil, fmt.Errorf("no compatible strategies found for threat type: %s", threat.ThreatType)
	}

	// Use selectors to rank strategies
	bestStrategy, err := sr.selectBestStrategy(threat, compatibleStrategies)
	if err != nil {
		return nil, fmt.Errorf("strategy selection failed: %w", err)
	}

	// Update strategy usage statistics
	sr.updateStrategyUsage(bestStrategy)

	sr.logger.Info("Strategy selected",
		"strategy_name", bestStrategy.Name,
		"threat_type", threat.ThreatType,
		"estimated_time", bestStrategy.EstimatedTime,
		"success_rate", bestStrategy.SuccessRate,
	)

	return bestStrategy, nil
}

// getCompatibleStrategies filters strategies compatible with the threat
func (sr *StrategyRegistry) getCompatibleStrategies(threat *ai.ThreatAssessment) []*HealingStrategy {
	var compatible []*HealingStrategy

	for _, strategy := range sr.strategies {
		if !strategy.Enabled {
			continue
		}

		// Check severity range
		if threat.Severity < strategy.MinSeverity || threat.Severity > strategy.MaxSeverity {
			continue
		}

		// Check threat type compatibility
		if len(strategy.ThreatTypes) > 0 {
			found := false
			for _, threatType := range strategy.ThreatTypes {
				if threatType == threat.ThreatType || threatType == "*" {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		compatible = append(compatible, strategy)
	}

	return compatible
}

// selectBestStrategy uses selectors to choose the best strategy
func (sr *StrategyRegistry) selectBestStrategy(threat *ai.ThreatAssessment, strategies []*HealingStrategy) (*HealingStrategy, error) {
	if len(strategies) == 0 {
		return nil, fmt.Errorf("no strategies to select from")
	}

	if len(strategies) == 1 {
		return strategies[0], nil
	}

	// Score strategies using selectors
	type strategyScore struct {
		strategy *HealingStrategy
		score    float64
	}

	var scored []strategyScore

	for _, strategy := range strategies {
		totalScore := float64(0)
		totalWeight := float64(0)

		for _, selector := range sr.selectors {
			if selectedStrategy, err := selector.SelectStrategy(threat, []*HealingStrategy{strategy}); err == nil && selectedStrategy != nil {
				weight := selector.GetWeight()
				totalScore += weight
				totalWeight += weight
			}
		}

		// Normalize score
		var normalizedScore float64
		if totalWeight > 0 {
			normalizedScore = totalScore / totalWeight
		}

		// Add strategy-specific factors
		normalizedScore += sr.calculateStrategyBonus(strategy)

		scored = append(scored, strategyScore{
			strategy: strategy,
			score:    normalizedScore,
		})
	}

	// Sort by score (highest first)
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	if len(scored) == 0 {
		return strategies[0], nil // Fallback to first strategy
	}

	return scored[0].strategy, nil
}

// calculateStrategyBonus calculates bonus score for strategy-specific factors
func (sr *StrategyRegistry) calculateStrategyBonus(strategy *HealingStrategy) float64 {
	bonus := float64(0)

	// Success rate bonus
	bonus += strategy.SuccessRate * 0.3

	// Priority bonus
	bonus += float64(strategy.Priority) * 0.1

	// Recent usage penalty (prevent overuse)
	if strategy.LastUsed != nil && time.Since(*strategy.LastUsed) < 1*time.Hour {
		bonus -= 0.1
	}

	// Risk level consideration
	switch strategy.RiskLevel {
	case RiskLevelLow:
		bonus += 0.1
	case RiskLevelMedium:
		bonus += 0.05
	case RiskLevelHigh:
		bonus -= 0.05
	case RiskLevelCritical:
		bonus -= 0.1
	}

	return bonus
}

// updateStrategyUsage updates strategy usage statistics
func (sr *StrategyRegistry) updateStrategyUsage(strategy *HealingStrategy) {
	strategy.UseCount++
	now := time.Now()
	strategy.LastUsed = &now
}

// loadDefaultStrategies loads predefined healing strategies
func (sr *StrategyRegistry) loadDefaultStrategies() {
	// Malware response strategy
	sr.AddStrategy(&HealingStrategy{
		Name:        "malware_containment",
		Description: "Isolate and quarantine malware threats",
		ThreatTypes: []string{"signature_based", "malware_detection"},
		MinSeverity: ai.SeverityMedium,
		MaxSeverity: ai.SeverityCritical,
		Actions: []*ActionPlan{
			{
				Type:        ActionQuarantine,
				Description: "Quarantine suspicious files",
				Parameters:  map[string]interface{}{"isolation_level": "high"},
				Order:       1,
				Critical:    false,
				DelayAfter:  2 * time.Second,
			},
			{
				Type:        ActionKillProcess,
				Description: "Terminate malicious processes",
				Parameters:  map[string]interface{}{"force": true},
				Order:       2,
				Critical:    true,
				DelayAfter:  1 * time.Second,
			},
			{
				Type:        ActionUpdateFirewall,
				Description: "Block malicious network connections",
				Parameters:  map[string]interface{}{"action": "block_all"},
				Order:       3,
				Critical:    false,
			},
		],
		EstimatedTime: 2 * time.Minute,
		SuccessRate:   0.85,
		RiskLevel:     RiskLevelMedium,
		Priority:      5,
		Enabled:       true,
		CreatedAt:     time.Now(),
	})

	// Anomaly response strategy
	sr.AddStrategy(&HealingStrategy{
		Name:        "anomaly_investigation",
		Description: "Investigate and contain anomalous behavior",
		ThreatTypes: []string{"anomaly_based", "behavioral"},
		MinSeverity: ai.SeverityLow,
		MaxSeverity: ai.SeverityHigh,
		Actions: []*ActionPlan{
			{
				Type:        ActionAlert,
				Description: "Alert security team of anomaly",
				Parameters:  map[string]interface{}{"priority": "medium"},
				Order:       1,
				Critical:    false,
			},
			{
				Type:        ActionBackup,
				Description: "Create system backup before intervention",
				Parameters:  map[string]interface{}{"type": "incremental"},
				Order:       2,
				Critical:    false,
				DelayAfter:  5 * time.Second,
			},
			{
				Type:        ActionIsolate,
				Description: "Isolate affected components",
				Parameters:  map[string]interface{}{"scope": "process"},
				Order:       3,
				Critical:    true,
				MinSeverity: &[]ai.ThreatSeverity{ai.SeverityMedium}[0],
			},
		],
		EstimatedTime: 5 * time.Minute,
		SuccessRate:   0.75,
		RiskLevel:     RiskLevelLow,
		Priority:      3,
		Enabled:       true,
		CreatedAt:     time.Now(),
	})

	// Network intrusion response
	sr.AddStrategy(&HealingStrategy{
		Name:        "network_intrusion_response",
		Description: "Respond to network-based attacks",
		ThreatTypes: []string{"network_attack", "intrusion_detection"},
		MinSeverity: ai.SeverityMedium,
		MaxSeverity: ai.SeverityCritical,
		Actions: []*ActionPlan{
			{
				Type:        ActionBlockIP,
				Description: "Block attacking IP addresses",
				Parameters:  map[string]interface{}{"duration": "24h"},
				Order:       1,
				Critical:    true,
			},
			{
				Type:        ActionUpdateFirewall,
				Description: "Update firewall rules",
				Parameters:  map[string]interface{}{"mode": "strict"},
				Order:       2,
				Critical:    false,
				DelayAfter:  1 * time.Second,
			},
			{
				Type:        ActionRotateCredentials,
				Description: "Rotate potentially compromised credentials",
				Parameters:  map[string]interface{}{"scope": "network_services"},
				Order:       3,
				Critical:    false,
				MinSeverity: &[]ai.ThreatSeverity{ai.SeverityHigh}[0],
				DelayAfter:  10 * time.Second,
			},
		],
		EstimatedTime: 3 * time.Minute,
		SuccessRate:   0.90,
		RiskLevel:     RiskLevelMedium,
		Priority:      7,
		Enabled:       true,
		CreatedAt:     time.Now(),
	})

	// Critical system failure response
	sr.AddStrategy(&HealingStrategy{
		Name:        "critical_system_recovery",
		Description: "Emergency response for critical system failures",
		ThreatTypes: []string{"*"}, // Apply to any threat type
		MinSeverity: ai.SeverityCritical,
		MaxSeverity: ai.SeverityCritical,
		Actions: []*ActionPlan{
			{
				Type:        ActionAlert,
				Description: "Send critical alert to all administrators",
				Parameters:  map[string]interface{}{"priority": "critical", "channels": []string{"email", "sms", "slack"}},
				Order:       1,
				Critical:    true,
			},
			{
				Type:        ActionEscalate,
				Description: "Escalate to security incident response team",
				Parameters:  map[string]interface{}{"team": "SIRT", "severity": "critical"},
				Order:       2,
				Critical:    true,
			},
			{
				Type:        ActionIsolate,
				Description: "Isolate affected systems immediately",
				Parameters:  map[string]interface{}{"scope": "full_isolation"},
				Order:       3,
				Critical:    true,
				DelayAfter:  2 * time.Second,
			},
			{
				Type:        ActionBackup,
				Description: "Emergency backup of critical data",
				Parameters:  map[string]interface{}{"type": "emergency", "priority": "high"},
				Order:       4,
				Critical:    false,
			},
		},
		EstimatedTime: 10 * time.Minute,
		SuccessRate:   0.95,
		RiskLevel:     RiskLevelCritical,
		Priority:      10,
		Enabled:       true,
		CreatedAt:     time.Now(),
	})

	// Low-severity monitoring strategy
	sr.AddStrategy(&HealingStrategy{
		Name:        "enhanced_monitoring",
		Description: "Increase monitoring for low-severity threats",
		ThreatTypes: []string{"*"},
		MinSeverity: ai.SeverityLow,
		MaxSeverity: ai.SeverityMedium,
		Actions: []*ActionPlan{
			{
				Type:        ActionAlert,
				Description: "Log security event for analysis",
				Parameters:  map[string]interface{}{"priority": "low", "type": "log_only"},
				Order:       1,
				Critical:    false,
			},
		},
		EstimatedTime: 30 * time.Second,
		SuccessRate:   0.99,
		RiskLevel:     RiskLevelLow,
		Priority:      1,
		Enabled:       true,
		CreatedAt:     time.Now(),
	})

	sr.logger.Info("Default healing strategies loaded", "strategy_count", len(sr.strategies))
}

// initializeDefaultSelectors sets up default strategy selectors
func (sr *StrategyRegistry) initializeDefaultSelectors() {
	// Severity-based selector
	sr.selectors = append(sr.selectors, &SeverityBasedSelector{Weight: 0.4})
	
	// Success rate selector
	sr.selectors = append(sr.selectors, &SuccessRateSelector{Weight: 0.3})
	
	// Risk-aware selector
	sr.selectors = append(sr.selectors, &RiskAwareSelector{Weight: 0.2})
	
	// Time-based selector
	sr.selectors = append(sr.selectors, &TimeBasedSelector{Weight: 0.1})

	sr.logger.Info("Default strategy selectors initialized", "selector_count", len(sr.selectors))
}

// Strategy management methods

// AddStrategy adds a new healing strategy
func (sr *StrategyRegistry) AddStrategy(strategy *HealingStrategy) error {
	if strategy == nil {
		return fmt.Errorf("strategy cannot be nil")
	}

	if strategy.Name == "" {
		return fmt.Errorf("strategy name is required")
	}

	sr.mu.Lock()
	defer sr.mu.Unlock()

	// Validate strategy
	if err := sr.validateStrategy(strategy); err != nil {
		return fmt.Errorf("strategy validation failed: %w", err)
	}

	sr.strategies[strategy.Name] = strategy
	sr.logger.Info("Strategy added", "strategy_name", strategy.Name)

	return nil
}

// RemoveStrategy removes a healing strategy
func (sr *StrategyRegistry) RemoveStrategy(name string) error {
	sr.mu.Lock()
	defer sr.mu.Unlock()

	if _, exists := sr.strategies[name]; !exists {
		return fmt.Errorf("strategy not found: %s", name)
	}

	delete(sr.strategies, name)
	sr.logger.Info("Strategy removed", "strategy_name", name)

	return nil
}

// UpdateStrategy updates an existing strategy
func (sr *StrategyRegistry) UpdateStrategy(strategy *HealingStrategy) error {
	if strategy == nil {
		return fmt.Errorf("strategy cannot be nil")
	}

	sr.mu.Lock()
	defer sr.mu.Unlock()

	if _, exists := sr.strategies[strategy.Name]; !exists {
		return fmt.Errorf("strategy not found: %s", strategy.Name)
	}

	// Validate updated strategy
	if err := sr.validateStrategy(strategy); err != nil {
		return fmt.Errorf("strategy validation failed: %w", err)
	}

	sr.strategies[strategy.Name] = strategy
	sr.logger.Info("Strategy updated", "strategy_name", strategy.Name)

	return nil
}

// validateStrategy validates a strategy configuration
func (sr *StrategyRegistry) validateStrategy(strategy *HealingStrategy) error {
	if len(strategy.Actions) == 0 {
		return fmt.Errorf("strategy must have at least one action")
	}

	if strategy.MinSeverity > strategy.MaxSeverity {
		return fmt.Errorf("min_severity cannot be greater than max_severity")
	}

	if strategy.SuccessRate < 0 || strategy.SuccessRate > 1 {
		return fmt.Errorf("success_rate must be between 0 and 1")
	}

	// Validate action plans
	for i, action := range strategy.Actions {
		if action.Type < 0 {
			return fmt.Errorf("action %d has invalid type", i)
		}

		if action.Order < 0 {
			return fmt.Errorf("action %d has invalid order", i)
		}
	}

	return nil
}

// Public API methods

// GetStrategy retrieves a strategy by name
func (sr *StrategyRegistry) GetStrategy(name string) (*HealingStrategy, error) {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	strategy, exists := sr.strategies[name]
	if !exists {
		return nil, fmt.Errorf("strategy not found: %s", name)
	}

	return strategy, nil
}

// GetAllStrategies returns all registered strategies
func (sr *StrategyRegistry) GetAllStrategies() map[string]*HealingStrategy {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	strategies := make(map[string]*HealingStrategy)
	for k, v := range sr.strategies {
		strategies[k] = v
	}
	return strategies
}

// GetStrategyCount returns the number of registered strategies
func (sr *StrategyRegistry) GetStrategyCount() int {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	return len(sr.strategies)
}

// GetStrategiesForThreatType returns strategies compatible with a threat type
func (sr *StrategyRegistry) GetStrategiesForThreatType(threatType string) []*HealingStrategy {
	sr.mu.RLock()
	defer sr.mu.RUnlock()

	var compatible []*HealingStrategy
	for _, strategy := range sr.strategies {
		for _, sType := range strategy.ThreatTypes {
			if sType == threatType || sType == "*" {
				compatible = append(compatible, strategy)
				break
			}
		}
	}

	return compatible
}

// Strategy selector implementations

type SeverityBasedSelector struct {
	Weight float64
}

func (s *SeverityBasedSelector) SelectStrategy(threat *ai.ThreatAssessment, strategies []*HealingStrategy) (*HealingStrategy, error) {
	for _, strategy := range strategies {
		if threat.Severity >= strategy.MinSeverity && threat.Severity <= strategy.MaxSeverity {
			return strategy, nil
		}
	}
	return nil, fmt.Errorf("no strategy matches threat severity")
}

func (s *SeverityBasedSelector) GetSelectionCriteria() []string {
	return []string{"threat_severity", "strategy_severity_range"}
}

func (s *SeverityBasedSelector) GetWeight() float64 {
	return s.Weight
}

type SuccessRateSelector struct {
	Weight float64
}

func (s *SuccessRateSelector) SelectStrategy(threat *ai.ThreatAssessment, strategies []*HealingStrategy) (*HealingStrategy, error) {
	var best *HealingStrategy
	var bestRate float64

	for _, strategy := range strategies {
		if strategy.SuccessRate > bestRate {
			bestRate = strategy.SuccessRate
			best = strategy
		}
	}

	if best == nil {
		return nil, fmt.Errorf("no strategy found")
	}

	return best, nil
}

func (s *SuccessRateSelector) GetSelectionCriteria() []string {
	return []string{"success_rate"}
}

func (s *SuccessRateSelector) GetWeight() float64 {
	return s.Weight
}

type RiskAwareSelector struct {
	Weight float64
}

func (s *RiskAwareSelector) SelectStrategy(threat *ai.ThreatAssessment, strategies []*HealingStrategy) (*HealingStrategy, error) {
	// Prefer lower risk strategies for lower severity threats
	targetRisk := RiskLevelLow
	if threat.Severity >= ai.SeverityHigh {
		targetRisk = RiskLevelMedium
	}
	if threat.Severity >= ai.SeverityCritical {
		targetRisk = RiskLevelHigh
	}

	for _, strategy := range strategies {
		if strategy.RiskLevel <= targetRisk {
			return strategy, nil
		}
	}

	// If no low-risk strategy found, return any strategy
	if len(strategies) > 0 {
		return strategies[0], nil
	}

	return nil, fmt.Errorf("no strategy found")
}

func (s *RiskAwareSelector) GetSelectionCriteria() []string {
	return []string{"risk_level", "threat_severity"}
}

func (s *RiskAwareSelector) GetWeight() float64 {
	return s.Weight
}

type TimeBasedSelector struct {
	Weight float64
}

func (s *TimeBasedSelector) SelectStrategy(threat *ai.ThreatAssessment, strategies []*HealingStrategy) (*HealingStrategy, error) {
	// Prefer faster strategies during business hours
	now := time.Now()
	hour := now.Hour()
	isBusinessHours := hour >= 9 && hour <= 17

	var best *HealingStrategy
	var bestTime time.Duration

	for _, strategy := range strategies {
		if best == nil {
			best = strategy
			bestTime = strategy.EstimatedTime
			continue
		}

		if isBusinessHours && strategy.EstimatedTime < bestTime {
			best = strategy
			bestTime = strategy.EstimatedTime
		} else if !isBusinessHours && strategy.EstimatedTime > bestTime {
			// Prefer more thorough strategies outside business hours
			best = strategy
			bestTime = strategy.EstimatedTime
		}
	}

	if best == nil {
		return nil, fmt.Errorf("no strategy found")
	}

	return best, nil
}

func (s *TimeBasedSelector) GetSelectionCriteria() []string {
	return []string{"estimated_time", "time_of_day"}
}

func (s *TimeBasedSelector) GetWeight() float64 {
	return s.Weight
}
