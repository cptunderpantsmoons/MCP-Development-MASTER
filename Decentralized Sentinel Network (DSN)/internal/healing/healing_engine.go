package healing

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dsn/decentralized-sentinel-network/internal/ai"
	"github.com/dsn/decentralized-sentinel-network/pkg/config"
	"github.com/dsn/decentralized-sentinel-network/pkg/logger"
)

// HealingEngine implements automated threat remediation and system recovery
type HealingEngine struct {
	config           *config.SentinelConfig
	logger           logger.Logger
	actionExecutor   *ActionExecutor
	strategyRegistry *StrategyRegistry
	recoveryMonitor  *RecoveryMonitor
	
	// Active incidents
	activeIncidents  map[string]*HealingIncident
	incidentHistory  []HealingIncident
	
	// Healing state
	healingQueue     chan *HealingRequest
	responseQueue    chan *HealingResponse
	
	// Lifecycle
	mu       sync.RWMutex
	running  bool
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// HealingRequest represents a request for automated healing
type HealingRequest struct {
	ID               string                  `json:"id"`
	ThreatAssessment *ai.ThreatAssessment   `json:"threat_assessment"`
	SystemState      interface{}            `json:"system_state"`
	Priority         HealingPriority        `json:"priority"`
	RequestedBy      string                 `json:"requested_by"`
	Timestamp        time.Time              `json:"timestamp"`
	Context          map[string]interface{} `json:"context"`
}

// HealingResponse represents the result of a healing action
type HealingResponse struct {
	RequestID    string          `json:"request_id"`
	Status       HealingStatus   `json:"status"`
	ActionsRun   []string        `json:"actions_run"`
	Effectiveness float64        `json:"effectiveness"`
	Duration     time.Duration   `json:"duration"`
	ErrorMessage string          `json:"error_message,omitempty"`
	Timestamp    time.Time       `json:"timestamp"`
}

// HealingIncident tracks an active security incident and response
type HealingIncident struct {
	ID                 string                `json:"id"`
	ThreatType         string                `json:"threat_type"`
	Severity           ai.ThreatSeverity     `json:"severity"`
	StartTime          time.Time             `json:"start_time"`
	Status             IncidentStatus        `json:"status"`
	ActionsAttempted   []HealingAction       `json:"actions_attempted"`
	CurrentStrategy    string                `json:"current_strategy"`
	RecoveryProgress   float64               `json:"recovery_progress"`
	LastUpdate         time.Time             `json:"last_update"`
	ResolutionTime     *time.Time            `json:"resolution_time,omitempty"`
	AffectedComponents []string              `json:"affected_components"`
}

// HealingAction represents a specific healing action taken
type HealingAction struct {
	ID           string                 `json:"id"`
	Type         ActionType             `json:"type"`
	Description  string                 `json:"description"`
	Parameters   map[string]interface{} `json:"parameters"`
	Status       ActionStatus           `json:"status"`
	StartTime    time.Time              `json:"start_time"`
	EndTime      *time.Time             `json:"end_time,omitempty"`
	Effectiveness float64               `json:"effectiveness"`
	ErrorMessage string                 `json:"error_message,omitempty"`
}

// Enums for healing system

type HealingPriority int

const (
	PriorityLow HealingPriority = iota
	PriorityMedium
	PriorityHigh
	PriorityCritical
	PriorityEmergency
)

func (hp HealingPriority) String() string {
	switch hp {
	case PriorityLow:
		return "low"
	case PriorityMedium:
		return "medium"
	case PriorityHigh:
		return "high"
	case PriorityCritical:
		return "critical"
	case PriorityEmergency:
		return "emergency"
	default:
		return "unknown"
	}
}

type HealingStatus int

const (
	StatusPending HealingStatus = iota
	StatusInProgress
	StatusCompleted
	StatusFailed
	StatusPartialSuccess
	StatusRollback
)

func (hs HealingStatus) String() string {
	switch hs {
	case StatusPending:
		return "pending"
	case StatusInProgress:
		return "in_progress"
	case StatusCompleted:
		return "completed"
	case StatusFailed:
		return "failed"
	case StatusPartialSuccess:
		return "partial_success"
	case StatusRollback:
		return "rollback"
	default:
		return "unknown"
	}
}

type IncidentStatus int

const (
	IncidentActive IncidentStatus = iota
	IncidentContained
	IncidentResolved
	IncidentEscalated
)

func (is IncidentStatus) String() string {
	switch is {
	case IncidentActive:
		return "active"
	case IncidentContained:
		return "contained"
	case IncidentResolved:
		return "resolved"
	case IncidentEscalated:
		return "escalated"
	default:
		return "unknown"
	}
}

type ActionType int

const (
	ActionIsolate ActionType = iota
	ActionKillProcess
	ActionBlockIP
	ActionRotateCredentials
	ActionRestartService
	ActionUpdateFirewall
	ActionQuarantine
	ActionBackup
	ActionRestore
	ActionAlert
	ActionEscalate
)

func (at ActionType) String() string {
	switch at {
	case ActionIsolate:
		return "isolate"
	case ActionKillProcess:
		return "kill_process"
	case ActionBlockIP:
		return "block_ip"
	case ActionRotateCredentials:
		return "rotate_credentials"
	case ActionRestartService:
		return "restart_service"
	case ActionUpdateFirewall:
		return "update_firewall"
	case ActionQuarantine:
		return "quarantine"
	case ActionBackup:
		return "backup"
	case ActionRestore:
		return "restore"
	case ActionAlert:
		return "alert"
	case ActionEscalate:
		return "escalate"
	default:
		return "unknown"
	}
}

type ActionStatus int

const (
	ActionPending ActionStatus = iota
	ActionRunning
	ActionSuccess
	ActionFailed
	ActionSkipped
	ActionRolledBack
)

func (as ActionStatus) String() string {
	switch as {
	case ActionPending:
		return "pending"
	case ActionRunning:
		return "running"
	case ActionSuccess:
		return "success"
	case ActionFailed:
		return "failed"
	case ActionSkipped:
		return "skipped"
	case ActionRolledBack:
		return "rolled_back"
	default:
		return "unknown"
	}
}

// NewHealingEngine creates a new healing engine
func NewHealingEngine(cfg *config.SentinelConfig, log logger.Logger) (*HealingEngine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if log == nil {
		return nil, fmt.Errorf("logger is required")
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize components
	actionExecutor, err := NewActionExecutor(cfg, log)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create action executor: %w", err)
	}

	strategyRegistry := NewStrategyRegistry(log)
	recoveryMonitor := NewRecoveryMonitor(log)

	engine := &HealingEngine{
		config:           cfg,
		logger:           log.WithField(logger.FieldComponent, "healing-engine"),
		actionExecutor:   actionExecutor,
		strategyRegistry: strategyRegistry,
		recoveryMonitor:  recoveryMonitor,
		
		activeIncidents:  make(map[string]*HealingIncident),
		incidentHistory:  make([]HealingIncident, 0, 1000),
		
		healingQueue:     make(chan *HealingRequest, 1000),
		responseQueue:    make(chan *HealingResponse, 1000),
		
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize default healing strategies
	engine.initializeDefaultStrategies()

	return engine, nil
}

// Start initializes and starts the healing engine
func (he *HealingEngine) Start(ctx context.Context) error {
	he.mu.Lock()
	defer he.mu.Unlock()

	if he.running {
		return fmt.Errorf("healing engine already running")
	}

	he.logger.Info("Starting automated healing engine")

	// Start worker goroutines
	he.wg.Add(3)
	go he.healingWorker()
	go he.incidentMonitor()
	go he.responseProcessor()

	// Start component services
	if err := he.actionExecutor.Start(ctx); err != nil {
		return fmt.Errorf("failed to start action executor: %w", err)
	}

	if err := he.recoveryMonitor.Start(ctx); err != nil {
		return fmt.Errorf("failed to start recovery monitor: %w", err)
	}

	he.running = true
	he.logger.Info("Healing engine started successfully")

	return nil
}

// Stop gracefully stops the healing engine
func (he *HealingEngine) Stop() error {
	he.mu.Lock()
	defer he.mu.Unlock()

	if !he.running {
		return nil
	}

	he.logger.Info("Stopping healing engine")
	he.cancel()

	// Wait for workers to finish
	he.wg.Wait()

	// Stop components
	he.actionExecutor.Stop()
	he.recoveryMonitor.Stop()

	he.running = false
	he.logger.Info("Healing engine stopped")

	return nil
}

// RequestHealing submits a healing request
func (he *HealingEngine) RequestHealing(request *HealingRequest) error {
	if !he.running {
		return fmt.Errorf("healing engine not running")
	}

	if request == nil {
		return fmt.Errorf("healing request cannot be nil")
	}

	// Validate request
	if err := he.validateHealingRequest(request); err != nil {
		return fmt.Errorf("invalid healing request: %w", err)
	}

	// Generate ID if not provided
	if request.ID == "" {
		request.ID = he.generateRequestID()
	}

	request.Timestamp = time.Now()

	he.logger.Info("Healing request received",
		"request_id", request.ID,
		"priority", request.Priority.String(),
		"threat_type", request.ThreatAssessment.ThreatType,
	)

	// Submit to queue
	select {
	case he.healingQueue <- request:
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("healing queue full - request rejected")
	}
}

// healingWorker processes healing requests from the queue
func (he *HealingEngine) healingWorker() {
	defer he.wg.Done()

	for {
		select {
		case <-he.ctx.Done():
			return
		case request := <-he.healingQueue:
			he.processHealingRequest(request)
		}
	}
}

// processHealingRequest processes a single healing request
func (he *HealingEngine) processHealingRequest(request *HealingRequest) {
	startTime := time.Now()
	
	he.logger.Info("Processing healing request",
		"request_id", request.ID,
		"threat_severity", request.ThreatAssessment.Severity.String(),
	)

	// Create incident
	incident := &HealingIncident{
		ID:                 he.generateIncidentID(),
		ThreatType:         request.ThreatAssessment.ThreatType,
		Severity:           request.ThreatAssessment.Severity,
		StartTime:          time.Now(),
		Status:             IncidentActive,
		ActionsAttempted:   make([]HealingAction, 0),
		RecoveryProgress:   0.0,
		LastUpdate:         time.Now(),
		AffectedComponents: he.identifyAffectedComponents(request),
	}

	he.mu.Lock()
	he.activeIncidents[incident.ID] = incident
	he.mu.Unlock()

	// Select healing strategy
	strategy, err := he.strategyRegistry.SelectStrategy(request.ThreatAssessment)
	if err != nil {
		he.logger.Error("Failed to select healing strategy", logger.FieldError, err)
		he.sendResponse(request.ID, StatusFailed, nil, 0, time.Since(startTime), err.Error())
		return
	}

	incident.CurrentStrategy = strategy.Name
	he.logger.Info("Selected healing strategy",
		"strategy", strategy.Name,
		"incident_id", incident.ID,
	)

	// Execute healing actions
	response := he.executeHealingStrategy(request, incident, strategy)
	response.RequestID = request.ID
	response.Duration = time.Since(startTime)

	// Send response
	he.responseQueue <- response

	// Update incident status
	he.updateIncidentStatus(incident, response)
}

// executeHealingStrategy executes a healing strategy
func (he *HealingEngine) executeHealingStrategy(request *HealingRequest, incident *HealingIncident, strategy *HealingStrategy) *HealingResponse {
	var actionsRun []string
	var totalEffectiveness float64
	var lastError error

	for _, actionPlan := range strategy.Actions {
		// Check if action should be executed based on conditions
		if !he.shouldExecuteAction(actionPlan, request, incident) {
			he.logger.Debug("Skipping action due to conditions",
				"action", actionPlan.Type.String(),
				"incident_id", incident.ID,
			)
			continue
		}

		// Create healing action
		action := HealingAction{
			ID:          he.generateActionID(),
			Type:        actionPlan.Type,
			Description: actionPlan.Description,
			Parameters:  actionPlan.Parameters,
			Status:      ActionPending,
			StartTime:   time.Now(),
		}

		// Execute action
		he.logger.Info("Executing healing action",
			"action_type", action.Type.String(),
			"incident_id", incident.ID,
		)

		action.Status = ActionRunning
		incident.ActionsAttempted = append(incident.ActionsAttempted, action)

		// Execute the action
		effectiveness, err := he.actionExecutor.ExecuteAction(&action, request.ThreatAssessment)
		endTime := time.Now()
		action.EndTime = &endTime

		if err != nil {
			action.Status = ActionFailed
			action.ErrorMessage = err.Error()
			lastError = err
			he.logger.Error("Healing action failed",
				"action_type", action.Type.String(),
				"incident_id", incident.ID,
				logger.FieldError, err,
			)

			// Check if this is a critical action
			if actionPlan.Critical {
				break // Stop execution on critical action failure
			}
		} else {
			action.Status = ActionSuccess
			action.Effectiveness = effectiveness
			totalEffectiveness += effectiveness
			actionsRun = append(actionsRun, action.Type.String())

			he.logger.Info("Healing action completed successfully",
				"action_type", action.Type.String(),
				"effectiveness", effectiveness,
				"incident_id", incident.ID,
			)
		}

		// Update incident
		incident.ActionsAttempted[len(incident.ActionsAttempted)-1] = action
		incident.LastUpdate = time.Now()

		// Wait between actions if specified
		if actionPlan.DelayAfter > 0 {
			time.Sleep(actionPlan.DelayAfter)
		}
	}

	// Calculate overall status and effectiveness
	var status HealingStatus
	averageEffectiveness := float64(0)

	if len(actionsRun) == 0 {
		status = StatusFailed
	} else if lastError != nil {
		status = StatusPartialSuccess
		averageEffectiveness = totalEffectiveness / float64(len(actionsRun))
	} else {
		status = StatusCompleted
		averageEffectiveness = totalEffectiveness / float64(len(actionsRun))
	}

	response := &HealingResponse{
		Status:        status,
		ActionsRun:    actionsRun,
		Effectiveness: averageEffectiveness,
		Timestamp:     time.Now(),
	}

	if lastError != nil {
		response.ErrorMessage = lastError.Error()
	}

	return response
}

// Helper methods

func (he *HealingEngine) validateHealingRequest(request *HealingRequest) error {
	if request.ThreatAssessment == nil {
		return fmt.Errorf("threat assessment is required")
	}

	if request.ThreatAssessment.ThreatType == "" {
		return fmt.Errorf("threat type cannot be empty")
	}

	if request.RequestedBy == "" {
		return fmt.Errorf("requester identification is required")
	}

	return nil
}

func (he *HealingEngine) generateRequestID() string {
	return fmt.Sprintf("healing_req_%d", time.Now().UnixNano())
}

func (he *HealingEngine) generateIncidentID() string {
	return fmt.Sprintf("incident_%d", time.Now().UnixNano())
}

func (he *HealingEngine) generateActionID() string {
	return fmt.Sprintf("action_%d", time.Now().UnixNano())
}

func (he *HealingEngine) identifyAffectedComponents(request *HealingRequest) []string {
	// Simple component identification based on threat indicators
	var components []string

	for _, indicator := range request.ThreatAssessment.Indicators {
		switch indicator.Type {
		case "process_pattern":
			components = append(components, "process_manager")
		case "network_anomaly":
			components = append(components, "network_stack")
		case "file_hash":
			components = append(components, "file_system")
		case "memory_anomaly":
			components = append(components, "memory_manager")
		}
	}

	if len(components) == 0 {
		components = append(components, "unknown")
	}

	return components
}

func (he *HealingEngine) shouldExecuteAction(actionPlan *ActionPlan, request *HealingRequest, incident *HealingIncident) bool {
	// Check severity requirements
	if actionPlan.MinSeverity != nil && request.ThreatAssessment.Severity < *actionPlan.MinSeverity {
		return false
	}

	// Check threat type requirements
	if len(actionPlan.ThreatTypes) > 0 {
		found := false
		for _, threatType := range actionPlan.ThreatTypes {
			if threatType == request.ThreatAssessment.ThreatType {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check if action was already attempted
	for _, action := range incident.ActionsAttempted {
		if action.Type == actionPlan.Type && action.Status != ActionFailed {
			return false // Don't retry successful actions
		}
	}

	return true
}

func (he *HealingEngine) sendResponse(requestID string, status HealingStatus, actionsRun []string, effectiveness float64, duration time.Duration, errorMsg string) {
	response := &HealingResponse{
		RequestID:     requestID,
		Status:        status,
		ActionsRun:    actionsRun,
		Effectiveness: effectiveness,
		Duration:      duration,
		ErrorMessage:  errorMsg,
		Timestamp:     time.Now(),
	}

	select {
	case he.responseQueue <- response:
	default:
		he.logger.Warn("Response queue full, dropping response", "request_id", requestID)
	}
}

func (he *HealingEngine) updateIncidentStatus(incident *HealingIncident, response *HealingResponse) {
	he.mu.Lock()
	defer he.mu.Unlock()

	switch response.Status {
	case StatusCompleted:
		if response.Effectiveness > 0.8 {
			incident.Status = IncidentResolved
			now := time.Now()
			incident.ResolutionTime = &now
		} else {
			incident.Status = IncidentContained
		}
	case StatusPartialSuccess:
		incident.Status = IncidentContained
	case StatusFailed:
		if incident.Severity >= ai.SeverityHigh {
			incident.Status = IncidentEscalated
		}
	}

	incident.RecoveryProgress = response.Effectiveness
	incident.LastUpdate = time.Now()

	// Move to history if resolved
	if incident.Status == IncidentResolved {
		he.incidentHistory = append(he.incidentHistory, *incident)
		delete(he.activeIncidents, incident.ID)

		// Keep only last 1000 historical incidents
		if len(he.incidentHistory) > 1000 {
			he.incidentHistory = he.incidentHistory[1:]
		}
	}
}

// Background monitoring and processing

func (he *HealingEngine) incidentMonitor() {
	defer he.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-he.ctx.Done():
			return
		case <-ticker.C:
			he.monitorActiveIncidents()
		}
	}
}

func (he *HealingEngine) monitorActiveIncidents() {
	he.mu.RLock()
	incidents := make([]*HealingIncident, 0, len(he.activeIncidents))
	for _, incident := range he.activeIncidents {
		incidents = append(incidents, incident)
	}
	he.mu.RUnlock()

	for _, incident := range incidents {
		// Check for stale incidents
		if time.Since(incident.LastUpdate) > 1*time.Hour {
			he.logger.Warn("Stale incident detected",
				"incident_id", incident.ID,
				"last_update", incident.LastUpdate,
			)

			he.mu.Lock()
			incident.Status = IncidentEscalated
			incident.LastUpdate = time.Now()
			he.mu.Unlock()
		}

		// Check recovery progress
		if incident.RecoveryProgress > 0 {
			he.recoveryMonitor.MonitorRecovery(incident)
		}
	}
}

func (he *HealingEngine) responseProcessor() {
	defer he.wg.Done()

	for {
		select {
		case <-he.ctx.Done():
			return
		case response := <-he.responseQueue:
			he.processResponse(response)
		}
	}
}

func (he *HealingEngine) processResponse(response *HealingResponse) {
	he.logger.Info("Healing response processed",
		"request_id", response.RequestID,
		"status", response.Status.String(),
		"effectiveness", response.Effectiveness,
		"duration", response.Duration,
	)

	// Log metrics
	he.recordHealingMetrics(response)

	// Handle failed responses
	if response.Status == StatusFailed {
		he.logger.Error("Healing request failed",
			"request_id", response.RequestID,
			"error", response.ErrorMessage,
		)
	}
}

func (he *HealingEngine) recordHealingMetrics(response *HealingResponse) {
	// In production, this would record metrics to Prometheus
	// For now, just log key metrics
	he.logger.Debug("Healing metrics recorded",
		"status", response.Status.String(),
		"effectiveness", response.Effectiveness,
		"duration_ms", response.Duration.Milliseconds(),
		"actions_count", len(response.ActionsRun),
	)
}

// Public API methods

// GetActiveIncidents returns all active incidents
func (he *HealingEngine) GetActiveIncidents() map[string]*HealingIncident {
	he.mu.RLock()
	defer he.mu.RUnlock()

	incidents := make(map[string]*HealingIncident)
	for k, v := range he.activeIncidents {
		incidents[k] = v
	}
	return incidents
}

// GetIncidentHistory returns recent incident history
func (he *HealingEngine) GetIncidentHistory(limit int) []HealingIncident {
	he.mu.RLock()
	defer he.mu.RUnlock()

	if limit <= 0 || limit > len(he.incidentHistory) {
		limit = len(he.incidentHistory)
	}

	start := len(he.incidentHistory) - limit
	history := make([]HealingIncident, limit)
	copy(history, he.incidentHistory[start:])
	return history
}

// GetHealingStats returns healing engine statistics
func (he *HealingEngine) GetHealingStats() map[string]interface{} {
	he.mu.RLock()
	defer he.mu.RUnlock()

	totalIncidents := len(he.incidentHistory)
	resolvedCount := 0
	totalEffectiveness := float64(0)

	for _, incident := range he.incidentHistory {
		if incident.Status == IncidentResolved {
			resolvedCount++
		}
		totalEffectiveness += incident.RecoveryProgress
	}

	var averageEffectiveness float64
	if totalIncidents > 0 {
		averageEffectiveness = totalEffectiveness / float64(totalIncidents)
	}

	return map[string]interface{}{
		"active_incidents":     len(he.activeIncidents),
		"total_incidents":      totalIncidents,
		"resolved_incidents":   resolvedCount,
		"resolution_rate":      func() float64 {
			if totalIncidents > 0 {
				return float64(resolvedCount) / float64(totalIncidents) * 100
			}
			return 0
		}(),
		"average_effectiveness": averageEffectiveness,
		"queue_size":           len(he.healingQueue),
		"strategies_available": he.strategyRegistry.GetStrategyCount(),
	}
}

// IsHealthy returns whether the healing engine is healthy
func (he *HealingEngine) IsHealthy() bool {
	he.mu.RLock()
	defer he.mu.RUnlock()

	if !he.running {
		return false
	}

	// Check if queue is backing up
	if len(he.healingQueue) > 800 { // 80% of capacity
		return false
	}

	// Check component health
	if !he.actionExecutor.IsHealthy() || !he.recoveryMonitor.IsHealthy() {
		return false
	}

	return true
}

// GetStatus returns detailed status information
func (he *HealingEngine) GetStatus() interface{} {
	return map[string]interface{}{
		"running":              he.running,
		"active_incidents":     len(he.activeIncidents),
		"queue_size":           len(he.healingQueue),
		"strategies_loaded":    he.strategyRegistry.GetStrategyCount(),
		"action_executor":      he.actionExecutor.GetStatus(),
		"recovery_monitor":     he.recoveryMonitor.GetStatus(),
		"is_healthy":          he.IsHealthy(),
	}
}

// initializeDefaultStrategies loads default healing strategies
func (he *HealingEngine) initializeDefaultStrategies() {
	// This will be implemented in the strategy registry
	he.logger.Info("Default healing strategies will be initialized by strategy registry")
}
