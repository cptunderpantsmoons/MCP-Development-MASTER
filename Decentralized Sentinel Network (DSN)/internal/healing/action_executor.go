package healing

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/dsn/decentralized-sentinel-network/internal/ai"
	"github.com/dsn/decentralized-sentinel-network/pkg/config"
	"github.com/dsn/decentralized-sentinel-network/pkg/logger"
)

// ActionExecutor safely executes healing actions with proper security controls
type ActionExecutor struct {
	config           *config.SentinelConfig
	logger           logger.Logger
	safetyValidator  *SafetyValidator
	executionLimiter *ExecutionLimiter
	actionHandlers   map[ActionType]ActionHandler
	
	// Execution tracking
	activeActions    map[string]*ExecutionContext
	executionHistory []ExecutionRecord
	
	// Security controls
	allowedCommands  []string
	blockedCommands  []string
	maxExecutionTime time.Duration
	
	// State
	mu      sync.RWMutex
	running bool
}

// ActionHandler defines the interface for action-specific handlers
type ActionHandler interface {
	Execute(ctx context.Context, action *HealingAction, threat *ai.ThreatAssessment) (float64, error)
	Validate(action *HealingAction) error
	GetRequiredPermissions() []string
	IsReversible() bool
	EstimateImpact() ActionImpact
}

// ExecutionContext tracks the execution of a healing action
type ExecutionContext struct {
	ActionID      string
	ActionType    ActionType
	StartTime     time.Time
	Timeout       time.Duration
	CancelFunc    context.CancelFunc
	ProcessID     int
	ResourceUsage ResourceUsage
}

// ExecutionRecord records the execution of a healing action
type ExecutionRecord struct {
	ActionID      string                 `json:"action_id"`
	ActionType    ActionType             `json:"action_type"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       time.Time              `json:"end_time"`
	Duration      time.Duration          `json:"duration"`
	Success       bool                   `json:"success"`
	Effectiveness float64                `json:"effectiveness"`
	ErrorMessage  string                 `json:"error_message,omitempty"`
	Parameters    map[string]interface{} `json:"parameters"`
	Impact        ActionImpact           `json:"impact"`
}

// SafetyValidator validates actions before execution
type SafetyValidator struct {
	logger           logger.Logger
	dangerousActions map[ActionType]bool
	safetyRules      []SafetyRule
	mu               sync.RWMutex
}

// ExecutionLimiter controls action execution rates and resource usage
type ExecutionLimiter struct {
	maxConcurrentActions int
	actionsPerMinute     int
	resourceLimits       ResourceLimits
	currentActions       int
	actionTimes          []time.Time
	mu                   sync.Mutex
}

// Resource usage and limits
type ResourceUsage struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryMB      int64   `json:"memory_mb"`
	DiskReadMB    int64   `json:"disk_read_mb"`
	DiskWriteMB   int64   `json:"disk_write_mb"`
	NetworkConnections int `json:"network_connections"`
}

type ResourceLimits struct {
	MaxCPUPercent         float64 `json:"max_cpu_percent"`
	MaxMemoryMB           int64   `json:"max_memory_mb"`
	MaxDiskOperationsMB   int64   `json:"max_disk_operations_mb"`
	MaxNetworkConnections int     `json:"max_network_connections"`
}

type ActionImpact int

const (
	ImpactMinimal ActionImpact = iota
	ImpactLow
	ImpactMedium
	ImpactHigh
	ImpactCritical
)

func (ai ActionImpact) String() string {
	switch ai {
	case ImpactMinimal:
		return "minimal"
	case ImpactLow:
		return "low"
	case ImpactMedium:
		return "medium"
	case ImpactHigh:
		return "high"
	case ImpactCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// SafetyRule defines a safety rule for action validation
type SafetyRule struct {
	Name        string
	Description string
	Validator   func(*HealingAction, *ai.ThreatAssessment) error
	Severity    ValidationSeverity
}

// NewActionExecutor creates a new action executor with security controls
func NewActionExecutor(cfg *config.SentinelConfig, log logger.Logger) (*ActionExecutor, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if log == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Initialize safety validator
	safetyValidator := &SafetyValidator{
		logger:           log.WithField(logger.FieldComponent, "safety-validator"),
		dangerousActions: make(map[ActionType]bool),
		safetyRules:      make([]SafetyRule, 0),
	}

	// Initialize execution limiter
	executionLimiter := &ExecutionLimiter{
		maxConcurrentActions: 5, // Maximum 5 concurrent actions
		actionsPerMinute:     20, // Maximum 20 actions per minute
		resourceLimits: ResourceLimits{
			MaxCPUPercent:         50.0, // Max 50% CPU
			MaxMemoryMB:           1024, // Max 1GB memory
			MaxDiskOperationsMB:   500,  // Max 500MB disk operations
			MaxNetworkConnections: 100,  // Max 100 network connections
		},
		actionTimes: make([]time.Time, 0),
	}

	executor := &ActionExecutor{
		config:           cfg,
		logger:           log.WithField(logger.FieldComponent, "action-executor"),
		safetyValidator:  safetyValidator,
		executionLimiter: executionLimiter,
		actionHandlers:   make(map[ActionType]ActionHandler),
		activeActions:    make(map[string]*ExecutionContext),
		executionHistory: make([]ExecutionRecord, 0, 1000),
		maxExecutionTime: 5 * time.Minute,
		
		// Security controls
		allowedCommands: []string{
			"iptables", "systemctl", "docker", "kubectl",
			"pkill", "chmod", "chown", "mv", "cp",
		},
		blockedCommands: []string{
			"rm", "rmdir", "dd", "mkfs", "fdisk",
			"shutdown", "reboot", "halt", "init",
		},
	}

	// Initialize action handlers
	executor.initializeActionHandlers()
	
	// Initialize safety rules
	safetyValidator.initializeSafetyRules()

	return executor, nil
}

// Start initializes and starts the action executor
func (ae *ActionExecutor) Start(ctx context.Context) error {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	if ae.running {
		return fmt.Errorf("action executor already running")
	}

	ae.logger.Info("Starting action executor with security controls")
	ae.running = true

	return nil
}

// Stop gracefully stops the action executor
func (ae *ActionExecutor) Stop() error {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	if !ae.running {
		return nil
	}

	ae.logger.Info("Stopping action executor")

	// Cancel all active actions
	for actionID, execCtx := range ae.activeActions {
		ae.logger.Info("Cancelling active action", "action_id", actionID)
		if execCtx.CancelFunc != nil {
			execCtx.CancelFunc()
		}
	}

	ae.running = false
	return nil
}

// ExecuteAction safely executes a healing action
func (ae *ActionExecutor) ExecuteAction(action *HealingAction, threat *ai.ThreatAssessment) (float64, error) {
	if !ae.running {
		return 0, fmt.Errorf("action executor not running")
	}

	ae.logger.Info("Executing healing action",
		"action_id", action.ID,
		"action_type", action.Type.String(),
		"threat_type", threat.ThreatType,
	)

	// Pre-execution validation
	if err := ae.validateAction(action, threat); err != nil {
		return 0, fmt.Errorf("action validation failed: %w", err)
	}

	// Check execution limits
	if err := ae.executionLimiter.CheckLimits(); err != nil {
		return 0, fmt.Errorf("execution limits exceeded: %w", err)
	}

	// Get action handler
	handler, exists := ae.actionHandlers[action.Type]
	if !exists {
		return 0, fmt.Errorf("no handler for action type: %s", action.Type.String())
	}

	// Create execution context
	ctx, cancel := context.WithTimeout(context.Background(), ae.maxExecutionTime)
	execCtx := &ExecutionContext{
		ActionID:   action.ID,
		ActionType: action.Type,
		StartTime:  time.Now(),
		Timeout:    ae.maxExecutionTime,
		CancelFunc: cancel,
	}

	ae.mu.Lock()
	ae.activeActions[action.ID] = execCtx
	ae.mu.Unlock()

	defer func() {
		cancel()
		ae.mu.Lock()
		delete(ae.activeActions, action.ID)
		ae.mu.Unlock()
	}()

	// Execute action with monitoring
	startTime := time.Now()
	effectiveness, err := ae.executeWithMonitoring(ctx, handler, action, threat, execCtx)
	duration := time.Since(startTime)

	// Record execution
	record := ExecutionRecord{
		ActionID:      action.ID,
		ActionType:    action.Type,
		StartTime:     startTime,
		EndTime:       time.Now(),
		Duration:      duration,
		Success:       err == nil,
		Effectiveness: effectiveness,
		Parameters:    action.Parameters,
		Impact:        handler.EstimateImpact(),
	}

	if err != nil {
		record.ErrorMessage = err.Error()
	}

	ae.recordExecution(record)

	if err != nil {
		ae.logger.Error("Action execution failed",
			"action_id", action.ID,
			"action_type", action.Type.String(),
			"duration", duration,
			logger.FieldError, err,
		)
		return 0, err
	}

	ae.logger.Info("Action executed successfully",
		"action_id", action.ID,
		"action_type", action.Type.String(),
		"effectiveness", effectiveness,
		"duration", duration,
	)

	return effectiveness, nil
}

// executeWithMonitoring executes an action with resource monitoring
func (ae *ActionExecutor) executeWithMonitoring(ctx context.Context, handler ActionHandler, action *HealingAction, threat *ai.ThreatAssessment, execCtx *ExecutionContext) (float64, error) {
	// Start resource monitoring
	resourceChan := make(chan ResourceUsage, 10)
	go ae.monitorResources(ctx, execCtx, resourceChan)

	// Execute action
	effectiveness, err := handler.Execute(ctx, action, threat)

	// Check resource usage
	select {
	case usage := <-resourceChan:
		if ae.exceedsResourceLimits(usage) {
			return 0, fmt.Errorf("action exceeded resource limits: %+v", usage)
		}
		execCtx.ResourceUsage = usage
	default:
		// No resource data available
	}

	return effectiveness, err
}

// validateAction validates an action before execution
func (ae *ActionExecutor) validateAction(action *HealingAction, threat *ai.ThreatAssessment) error {
	// Basic validation
	if action == nil {
		return fmt.Errorf("action cannot be nil")
	}

	if action.ID == "" {
		return fmt.Errorf("action ID is required")
	}

	// Safety validation
	if err := ae.safetyValidator.ValidateAction(action, threat); err != nil {
		return fmt.Errorf("safety validation failed: %w", err)
	}

	// Handler-specific validation
	if handler, exists := ae.actionHandlers[action.Type]; exists {
		if err := handler.Validate(action); err != nil {
			return fmt.Errorf("handler validation failed: %w", err)
		}
	}

	return nil
}

// monitorResources monitors resource usage during action execution
func (ae *ActionExecutor) monitorResources(ctx context.Context, execCtx *ExecutionContext, resourceChan chan<- ResourceUsage) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			usage := ae.getCurrentResourceUsage(execCtx)
			select {
			case resourceChan <- usage:
			default:
				// Channel full, skip this reading
			}
		}
	}
}

// getCurrentResourceUsage gets current resource usage (simplified implementation)
func (ae *ActionExecutor) getCurrentResourceUsage(execCtx *ExecutionContext) ResourceUsage {
	// In production, this would use proper system monitoring
	// For now, return simulated values
	return ResourceUsage{
		CPUPercent:         10.0,
		MemoryMB:          128,
		DiskReadMB:        10,
		DiskWriteMB:       5,
		NetworkConnections: 2,
	}
}

// exceedsResourceLimits checks if resource usage exceeds limits
func (ae *ActionExecutor) exceedsResourceLimits(usage ResourceUsage) bool {
	limits := ae.executionLimiter.resourceLimits

	return usage.CPUPercent > limits.MaxCPUPercent ||
		   usage.MemoryMB > limits.MaxMemoryMB ||
		   (usage.DiskReadMB+usage.DiskWriteMB) > limits.MaxDiskOperationsMB ||
		   usage.NetworkConnections > limits.MaxNetworkConnections
}

// recordExecution records an execution in history
func (ae *ActionExecutor) recordExecution(record ExecutionRecord) {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	ae.executionHistory = append(ae.executionHistory, record)

	// Keep only last 1000 records
	if len(ae.executionHistory) > 1000 {
		ae.executionHistory = ae.executionHistory[1:]
	}
}

// initializeActionHandlers sets up handlers for different action types
func (ae *ActionExecutor) initializeActionHandlers() {
	ae.actionHandlers[ActionIsolate] = &IsolateHandler{logger: ae.logger}
	ae.actionHandlers[ActionKillProcess] = &KillProcessHandler{logger: ae.logger}
	ae.actionHandlers[ActionBlockIP] = &BlockIPHandler{logger: ae.logger}
	ae.actionHandlers[ActionRotateCredentials] = &RotateCredentialsHandler{logger: ae.logger}
	ae.actionHandlers[ActionRestartService] = &RestartServiceHandler{logger: ae.logger}
	ae.actionHandlers[ActionUpdateFirewall] = &UpdateFirewallHandler{logger: ae.logger}
	ae.actionHandlers[ActionQuarantine] = &QuarantineHandler{logger: ae.logger}
	ae.actionHandlers[ActionBackup] = &BackupHandler{logger: ae.logger}
	ae.actionHandlers[ActionRestore] = &RestoreHandler{logger: ae.logger}
	ae.actionHandlers[ActionAlert] = &AlertHandler{logger: ae.logger}
	ae.actionHandlers[ActionEscalate] = &EscalateHandler{logger: ae.logger}

	ae.logger.Info("Action handlers initialized", "handler_count", len(ae.actionHandlers))
}

// Safety validator methods

func (sv *SafetyValidator) ValidateAction(action *HealingAction, threat *ai.ThreatAssessment) error {
	sv.mu.RLock()
	defer sv.mu.RUnlock()

	// Check if action is marked as dangerous
	if sv.dangerousActions[action.Type] && threat.Severity < ai.SeverityHigh {
		return fmt.Errorf("dangerous action %s requires high severity threat", action.Type.String())
	}

	// Apply safety rules
	for _, rule := range sv.safetyRules {
		if err := rule.Validator(action, threat); err != nil {
			return fmt.Errorf("safety rule '%s' failed: %w", rule.Name, err)
		}
	}

	return nil
}

func (sv *SafetyValidator) initializeSafetyRules() {
	// Mark dangerous actions
	sv.dangerousActions[ActionIsolate] = true
	sv.dangerousActions[ActionKillProcess] = true
	sv.dangerousActions[ActionRestartService] = true

	// Add safety rules
	sv.safetyRules = append(sv.safetyRules, SafetyRule{
		Name:        "require_process_name",
		Description: "Kill process actions must specify process name",
		Validator: func(action *HealingAction, threat *ai.ThreatAssessment) error {
			if action.Type == ActionKillProcess {
				if processName, exists := action.Parameters["process_name"]; !exists || processName == "" {
					return fmt.Errorf("process_name parameter required for kill_process action")
				}
			}
			return nil
		},
		Severity: SeverityError,
	})

	sv.safetyRules = append(sv.safetyRules, SafetyRule{
		Name:        "validate_ip_address",
		Description: "Block IP actions must have valid IP address",
		Validator: func(action *HealingAction, threat *ai.ThreatAssessment) error {
			if action.Type == ActionBlockIP {
				if ipAddr, exists := action.Parameters["ip_address"]; !exists || ipAddr == "" {
					return fmt.Errorf("ip_address parameter required for block_ip action")
				}
				// Add IP validation logic here
			}
			return nil
		},
		Severity: SeverityError,
	})

	sv.logger.Info("Safety rules initialized", "rule_count", len(sv.safetyRules))
}

// Execution limiter methods

func (el *ExecutionLimiter) CheckLimits() error {
	el.mu.Lock()
	defer el.mu.Unlock()

	// Check concurrent actions limit
	if el.currentActions >= el.maxConcurrentActions {
		return fmt.Errorf("maximum concurrent actions (%d) exceeded", el.maxConcurrentActions)
	}

	// Check rate limit
	now := time.Now()
	cutoff := now.Add(-1 * time.Minute)

	// Remove old action times
	validTimes := el.actionTimes[:0]
	for _, actionTime := range el.actionTimes {
		if actionTime.After(cutoff) {
			validTimes = append(validTimes, actionTime)
		}
	}
	el.actionTimes = validTimes

	if len(el.actionTimes) >= el.actionsPerMinute {
		return fmt.Errorf("action rate limit (%d per minute) exceeded", el.actionsPerMinute)
	}

	// Record this action time
	el.actionTimes = append(el.actionTimes, now)
	el.currentActions++

	return nil
}

func (el *ExecutionLimiter) ReleaseLimit() {
	el.mu.Lock()
	defer el.mu.Unlock()

	if el.currentActions > 0 {
		el.currentActions--
	}
}

// Public API methods

// GetActiveActions returns currently active actions
func (ae *ActionExecutor) GetActiveActions() map[string]*ExecutionContext {
	ae.mu.RLock()
	defer ae.mu.RUnlock()

	actions := make(map[string]*ExecutionContext)
	for k, v := range ae.activeActions {
		actions[k] = v
	}
	return actions
}

// GetExecutionHistory returns recent execution history
func (ae *ActionExecutor) GetExecutionHistory(limit int) []ExecutionRecord {
	ae.mu.RLock()
	defer ae.mu.RUnlock()

	if limit <= 0 || limit > len(ae.executionHistory) {
		limit = len(ae.executionHistory)
	}

	start := len(ae.executionHistory) - limit
	history := make([]ExecutionRecord, limit)
	copy(history, ae.executionHistory[start:])
	return history
}

// GetExecutionStats returns execution statistics
func (ae *ActionExecutor) GetExecutionStats() map[string]interface{} {
	ae.mu.RLock()
	defer ae.mu.RUnlock()

	totalExecutions := len(ae.executionHistory)
	successCount := 0
	totalEffectiveness := float64(0)

	for _, record := range ae.executionHistory {
		if record.Success {
			successCount++
		}
		totalEffectiveness += record.Effectiveness
	}

	var averageEffectiveness float64
	if totalExecutions > 0 {
		averageEffectiveness = totalEffectiveness / float64(totalExecutions)
	}

	return map[string]interface{}{
		"total_executions":      totalExecutions,
		"successful_executions": successCount,
		"success_rate": func() float64 {
			if totalExecutions > 0 {
				return float64(successCount) / float64(totalExecutions) * 100
			}
			return 0
		}(),
		"average_effectiveness": averageEffectiveness,
		"active_actions":        len(ae.activeActions),
		"available_handlers":    len(ae.actionHandlers),
	}
}

// IsHealthy returns whether the action executor is healthy
func (ae *ActionExecutor) IsHealthy() bool {
	ae.mu.RLock()
	defer ae.mu.RUnlock()

	if !ae.running {
		return false
	}

	// Check if too many actions are active
	if len(ae.activeActions) > ae.executionLimiter.maxConcurrentActions {
		return false
	}

	// Check recent success rate
	recentExecutions := ae.getRecentExecutions(1 * time.Hour)
	if len(recentExecutions) > 5 {
		successCount := 0
		for _, record := range recentExecutions {
			if record.Success {
				successCount++
			}
		}
		successRate := float64(successCount) / float64(len(recentExecutions))
		if successRate < 0.7 { // 70% success rate minimum
			return false
		}
	}

	return true
}

func (ae *ActionExecutor) getRecentExecutions(duration time.Duration) []ExecutionRecord {
	cutoff := time.Now().Add(-duration)
	var recent []ExecutionRecord

	for _, record := range ae.executionHistory {
		if record.StartTime.After(cutoff) {
			recent = append(recent, record)
		}
	}

	return recent
}

// GetStatus returns detailed status information
func (ae *ActionExecutor) GetStatus() interface{} {
	return map[string]interface{}{
		"running":           ae.running,
		"active_actions":    len(ae.activeActions),
		"total_handlers":    len(ae.actionHandlers),
		"execution_history": len(ae.executionHistory),
		"is_healthy":        ae.IsHealthy(),
		"resource_limits":   ae.executionLimiter.resourceLimits,
		"safety_rules":      len(ae.safetyValidator.safetyRules),
	}
}

// Simple action handler implementations
// In production, these would be much more sophisticated

type IsolateHandler struct {
	logger logger.Logger
}

func (h *IsolateHandler) Execute(ctx context.Context, action *HealingAction, threat *ai.ThreatAssessment) (float64, error) {
	h.logger.Info("Executing isolate action", "action_id", action.ID)
	// Simulate isolation logic
	time.Sleep(2 * time.Second)
	return 0.9, nil
}

func (h *IsolateHandler) Validate(action *HealingAction) error {
	return nil
}

func (h *IsolateHandler) GetRequiredPermissions() []string {
	return []string{"network_admin", "container_admin"}
}

func (h *IsolateHandler) IsReversible() bool {
	return true
}

func (h *IsolateHandler) EstimateImpact() ActionImpact {
	return ImpactMedium
}

// Additional handler implementations would follow the same pattern...
// For brevity, I'll implement just a few key ones

type KillProcessHandler struct {
	logger logger.Logger
}

func (h *KillProcessHandler) Execute(ctx context.Context, action *HealingAction, threat *ai.ThreatAssessment) (float64, error) {
	processName, exists := action.Parameters["process_name"]
	if !exists {
		return 0, fmt.Errorf("process_name parameter required")
	}

	h.logger.Info("Executing kill process action", 
		"action_id", action.ID,
		"process_name", processName,
	)

	// In production, this would use proper process management
	// For now, simulate the action
	time.Sleep(1 * time.Second)
	return 0.95, nil
}

func (h *KillProcessHandler) Validate(action *HealingAction) error {
	if _, exists := action.Parameters["process_name"]; !exists {
		return fmt.Errorf("process_name parameter required")
	}
	return nil
}

func (h *KillProcessHandler) GetRequiredPermissions() []string {
	return []string{"process_admin"}
}

func (h *KillProcessHandler) IsReversible() bool {
	return false
}

func (h *KillProcessHandler) EstimateImpact() ActionImpact {
	return ImpactHigh
}

type BlockIPHandler struct {
	logger logger.Logger
}

func (h *BlockIPHandler) Execute(ctx context.Context, action *HealingAction, threat *ai.ThreatAssessment) (float64, error) {
	ipAddress, exists := action.Parameters["ip_address"]
	if !exists {
		return 0, fmt.Errorf("ip_address parameter required")
	}

	h.logger.Info("Executing block IP action", 
		"action_id", action.ID,
		"ip_address", ipAddress,
	)

	// Simulate firewall rule addition
	time.Sleep(500 * time.Millisecond)
	return 0.85, nil
}

func (h *BlockIPHandler) Validate(action *HealingAction) error {
	if _, exists := action.Parameters["ip_address"]; !exists {
		return fmt.Errorf("ip_address parameter required")
	}
	return nil
}

func (h *BlockIPHandler) GetRequiredPermissions() []string {
	return []string{"firewall_admin"}
}

func (h *BlockIPHandler) IsReversible() bool {
	return true
}

func (h *BlockIPHandler) EstimateImpact() ActionImpact {
	return ImpactLow
}

// Placeholder implementations for remaining handlers
type RotateCredentialsHandler struct{ logger logger.Logger }
func (h *RotateCredentialsHandler) Execute(ctx context.Context, action *HealingAction, threat *ai.ThreatAssessment) (float64, error) { return 0.8, nil }
func (h *RotateCredentialsHandler) Validate(action *HealingAction) error { return nil }
func (h *RotateCredentialsHandler) GetRequiredPermissions() []string { return []string{"credential_admin"} }
func (h *RotateCredentialsHandler) IsReversible() bool { return false }
func (h *RotateCredentialsHandler) EstimateImpact() ActionImpact { return ImpactMedium }

type RestartServiceHandler struct{ logger logger.Logger }
func (h *RestartServiceHandler) Execute(ctx context.Context, action *HealingAction, threat *ai.ThreatAssessment) (float64, error) { return 0.7, nil }
func (h *RestartServiceHandler) Validate(action *HealingAction) error { return nil }
func (h *RestartServiceHandler) GetRequiredPermissions() []string { return []string{"service_admin"} }
func (h *RestartServiceHandler) IsReversible() bool { return true }
func (h *RestartServiceHandler) EstimateImpact() ActionImpact { return ImpactHigh }

type UpdateFirewallHandler struct{ logger logger.Logger }
func (h *UpdateFirewallHandler) Execute(ctx context.Context, action *HealingAction, threat *ai.ThreatAssessment) (float64, error) { return 0.9, nil }
func (h *UpdateFirewallHandler) Validate(action *HealingAction) error { return nil }
func (h *UpdateFirewallHandler) GetRequiredPermissions() []string { return []string{"firewall_admin"} }
func (h *UpdateFirewallHandler) IsReversible() bool { return true }
func (h *UpdateFirewallHandler) EstimateImpact() ActionImpact { return ImpactMedium }

type QuarantineHandler struct{ logger logger.Logger }
func (h *QuarantineHandler) Execute(ctx context.Context, action *HealingAction, threat *ai.ThreatAssessment) (float64, error) { return 0.85, nil }
func (h *QuarantineHandler) Validate(action *HealingAction) error { return nil }
func (h *QuarantineHandler) GetRequiredPermissions() []string { return []string{"file_admin"} }
func (h *QuarantineHandler) IsReversible() bool { return true }
func (h *QuarantineHandler) EstimateImpact() ActionImpact { return ImpactLow }

type BackupHandler struct{ logger logger.Logger }
func (h *BackupHandler) Execute(ctx context.Context, action *HealingAction, threat *ai.ThreatAssessment) (float64, error) { return 0.95, nil }
func (h *BackupHandler) Validate(action *HealingAction) error { return nil }
func (h *BackupHandler) GetRequiredPermissions() []string { return []string{"backup_admin"} }
func (h *BackupHandler) IsReversible() bool { return false }
func (h *BackupHandler) EstimateImpact() ActionImpact { return ImpactMinimal }

type RestoreHandler struct{ logger logger.Logger }
func (h *RestoreHandler) Execute(ctx context.Context, action *HealingAction, threat *ai.ThreatAssessment) (float64, error) { return 0.9, nil }
func (h *RestoreHandler) Validate(action *HealingAction) error { return nil }
func (h *RestoreHandler) GetRequiredPermissions() []string { return []string{"restore_admin"} }
func (h *RestoreHandler) IsReversible() bool { return false }
func (h *RestoreHandler) EstimateImpact() ActionImpact { return ImpactHigh }

type AlertHandler struct{ logger logger.Logger }
func (h *AlertHandler) Execute(ctx context.Context, action *HealingAction, threat *ai.ThreatAssessment) (float64, error) { return 1.0, nil }
func (h *AlertHandler) Validate(action *HealingAction) error { return nil }
func (h *AlertHandler) GetRequiredPermissions() []string { return []string{"alert_admin"} }
func (h *AlertHandler) IsReversible() bool { return false }
func (h *AlertHandler) EstimateImpact() ActionImpact { return ImpactMinimal }

type EscalateHandler struct{ logger logger.Logger }
func (h *EscalateHandler) Execute(ctx context.Context, action *HealingAction, threat *ai.ThreatAssessment) (float64, error) { return 1.0, nil }
func (h *EscalateHandler) Validate(action *HealingAction) error { return nil }
func (h *EscalateHandler) GetRequiredPermissions() []string { return []string{"escalation_admin"} }
func (h *EscalateHandler) IsReversible() bool { return false }
func (h *EscalateHandler) EstimateImpact() ActionImpact { return ImpactMinimal }
