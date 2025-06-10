package ai

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/dsn/decentralized-sentinel-network/pkg/logger"
)

// SecuritySandbox provides isolated execution environment for AI models
type SecuritySandbox struct {
	maxExecutionTime time.Duration
	maxMemoryMB      int
	maxCPUPercent    float64
	allowedSysCalls  []string
	logger           logger.Logger
	
	// Resource tracking
	activeExecutions sync.Map
	totalExecutions  int64
	failedExecutions int64
	mu               sync.RWMutex
}

// ExecutionContext tracks sandbox execution
type ExecutionContext struct {
	ID            string
	StartTime     time.Time
	MaxDuration   time.Duration
	InitialMemory uint64
	MaxMemory     uint64
	cancelled     chan struct{}
}

// SandboxViolation represents a security violation in the sandbox
type SandboxViolation struct {
	Type        ViolationType
	Description string
	Timestamp   time.Time
	Context     *ExecutionContext
}

// ViolationType defines types of sandbox violations
type ViolationType int

const (
	ViolationTimeout ViolationType = iota
	ViolationMemoryLimit
	ViolationCPULimit
	ViolationSysCall
	ViolationResourceExhaustion
)

func (vt ViolationType) String() string {
	switch vt {
	case ViolationTimeout:
		return "execution_timeout"
	case ViolationMemoryLimit:
		return "memory_limit_exceeded"
	case ViolationCPULimit:
		return "cpu_limit_exceeded"
	case ViolationSysCall:
		return "unauthorized_syscall"
	case ViolationResourceExhaustion:
		return "resource_exhaustion"
	default:
		return "unknown_violation"
	}
}

// NewSecuritySandbox creates a new security sandbox with default constraints
func NewSecuritySandbox(logger logger.Logger) *SecuritySandbox {
	return &SecuritySandbox{
		maxExecutionTime: 30 * time.Second,
		maxMemoryMB:      256,
		maxCPUPercent:    80.0,
		allowedSysCalls: []string{
			"read", "write", "open", "close", "mmap", "munmap",
			"brk", "rt_sigaction", "rt_sigprocmask", "getpid",
			"gettid", "futex", "clone", "exit_group",
		},
		logger: logger.WithField(logger.FieldComponent, "ai-sandbox"),
	}
}

// Execute runs a function in the security sandbox with resource constraints
func (ss *SecuritySandbox) Execute(ctx context.Context, fn func() (*ThreatAssessment, error)) (*ThreatAssessment, error) {
	// Create execution context
	execCtx := &ExecutionContext{
		ID:            ss.generateExecutionID(),
		StartTime:     time.Now(),
		MaxDuration:   ss.maxExecutionTime,
		InitialMemory: ss.getCurrentMemoryUsage(),
		MaxMemory:     uint64(ss.maxMemoryMB * 1024 * 1024),
		cancelled:     make(chan struct{}),
	}

	// Track active execution
	ss.activeExecutions.Store(execCtx.ID, execCtx)
	defer ss.activeExecutions.Delete(execCtx.ID)

	ss.mu.Lock()
	ss.totalExecutions++
	ss.mu.Unlock()

	ss.logger.Debug("Starting sandboxed execution",
		"execution_id", execCtx.ID,
		"max_duration", execCtx.MaxDuration,
		"max_memory_mb", ss.maxMemoryMB,
	)

	// Create context with timeout
	execCtxWithTimeout, cancel := context.WithTimeout(ctx, ss.maxExecutionTime)
	defer cancel()

	// Start resource monitoring
	violationChan := make(chan *SandboxViolation, 1)
	go ss.monitorResources(execCtxWithTimeout, execCtx, violationChan)

	// Execute function with monitoring
	resultChan := make(chan struct {
		result *ThreatAssessment
		err    error
	}, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				ss.logger.Error("Sandbox execution panicked",
					"execution_id", execCtx.ID,
					"panic", r,
				)
				resultChan <- struct {
					result *ThreatAssessment
					err    error
				}{nil, fmt.Errorf("sandbox execution panicked: %v", r)}
			}
		}()

		result, err := fn()
		resultChan <- struct {
			result *ThreatAssessment
			err    error
		}{result, err}
	}()

	// Wait for completion or violation
	select {
	case result := <-resultChan:
		duration := time.Since(execCtx.StartTime)
		ss.logger.Debug("Sandboxed execution completed",
			"execution_id", execCtx.ID,
			"duration", duration,
			"success", result.err == nil,
		)
		return result.result, result.err

	case violation := <-violationChan:
		close(execCtx.cancelled)
		ss.handleViolation(violation)
		ss.mu.Lock()
		ss.failedExecutions++
		ss.mu.Unlock()
		return nil, fmt.Errorf("sandbox violation: %s - %s", 
			violation.Type.String(), violation.Description)

	case <-execCtxWithTimeout.Done():
		close(execCtx.cancelled)
		ss.logger.Warn("Sandbox execution timed out",
			"execution_id", execCtx.ID,
			"duration", time.Since(execCtx.StartTime),
		)
		ss.mu.Lock()
		ss.failedExecutions++
		ss.mu.Unlock()
		return nil, fmt.Errorf("execution timed out after %v", ss.maxExecutionTime)
	}
}

// monitorResources continuously monitors resource usage during execution
func (ss *SecuritySandbox) monitorResources(ctx context.Context, execCtx *ExecutionContext, violationChan chan<- *SandboxViolation) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-execCtx.cancelled:
			return
		case <-ticker.C:
			// Check memory usage
			currentMemory := ss.getCurrentMemoryUsage()
			memoryUsed := currentMemory - execCtx.InitialMemory
			
			if memoryUsed > execCtx.MaxMemory {
				violation := &SandboxViolation{
					Type: ViolationMemoryLimit,
					Description: fmt.Sprintf("Memory usage %d MB exceeds limit %d MB",
						memoryUsed/(1024*1024), ss.maxMemoryMB),
					Timestamp: time.Now(),
					Context:   execCtx,
				}
				select {
				case violationChan <- violation:
				default:
				}
				return
			}

			// Check CPU usage (simplified check)
			if ss.isHighCPUUsage() {
				violation := &SandboxViolation{
					Type: ViolationCPULimit,
					Description: fmt.Sprintf("CPU usage exceeds limit %.1f%%", ss.maxCPUPercent),
					Timestamp: time.Now(),
					Context:   execCtx,
				}
				select {
				case violationChan <- violation:
				default:
				}
				return
			}

			// Check execution time
			if time.Since(execCtx.StartTime) > execCtx.MaxDuration {
				violation := &SandboxViolation{
					Type: ViolationTimeout,
					Description: fmt.Sprintf("Execution time %v exceeds limit %v",
						time.Since(execCtx.StartTime), execCtx.MaxDuration),
					Timestamp: time.Now(),
					Context:   execCtx,
				}
				select {
				case violationChan <- violation:
				default:
				}
				return
			}
		}
	}
}

// handleViolation processes security violations
func (ss *SecuritySandbox) handleViolation(violation *SandboxViolation) {
	ss.logger.Error("Sandbox security violation detected",
		"violation_type", violation.Type.String(),
		"description", violation.Description,
		"execution_id", violation.Context.ID,
		"timestamp", violation.Timestamp,
	)

	// In production, this would:
	// 1. Log to security event system
	// 2. Trigger alerts
	// 3. Update threat intelligence
	// 4. Potentially blacklist problematic code patterns
}

// getCurrentMemoryUsage returns current memory usage in bytes
func (ss *SecuritySandbox) getCurrentMemoryUsage() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Sys // Total memory obtained from system
}

// isHighCPUUsage checks if CPU usage is too high (simplified implementation)
func (ss *SecuritySandbox) isHighCPUUsage() bool {
	// In production, this would use more sophisticated CPU monitoring
	// For now, just check if we have too many goroutines (simple heuristic)
	return runtime.NumGoroutine() > 1000
}

// generateExecutionID creates a unique execution ID
func (ss *SecuritySandbox) generateExecutionID() string {
	return fmt.Sprintf("exec_%d_%d", time.Now().UnixNano(), runtime.NumGoroutine())
}

// GetStats returns sandbox execution statistics
func (ss *SecuritySandbox) GetStats() map[string]interface{} {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	activeCount := 0
	ss.activeExecutions.Range(func(key, value interface{}) bool {
		activeCount++
		return true
	})

	var successRate float64
	if ss.totalExecutions > 0 {
		successRate = float64(ss.totalExecutions-ss.failedExecutions) / float64(ss.totalExecutions) * 100
	}

	return map[string]interface{}{
		"total_executions":  ss.totalExecutions,
		"failed_executions": ss.failedExecutions,
		"active_executions": activeCount,
		"success_rate":      successRate,
		"max_memory_mb":     ss.maxMemoryMB,
		"max_execution_time": ss.maxExecutionTime.String(),
	}
}

// UpdateConstraints allows updating sandbox constraints
func (ss *SecuritySandbox) UpdateConstraints(maxMemoryMB int, maxExecutionTime time.Duration, maxCPUPercent float64) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	if maxMemoryMB > 0 && maxMemoryMB <= 1024 { // Max 1GB
		ss.maxMemoryMB = maxMemoryMB
	}

	if maxExecutionTime > 0 && maxExecutionTime <= 5*time.Minute { // Max 5 minutes
		ss.maxExecutionTime = maxExecutionTime
	}

	if maxCPUPercent > 0 && maxCPUPercent <= 90 { // Max 90%
		ss.maxCPUPercent = maxCPUPercent
	}

	ss.logger.Info("Sandbox constraints updated",
		"max_memory_mb", ss.maxMemoryMB,
		"max_execution_time", ss.maxExecutionTime,
		"max_cpu_percent", ss.maxCPUPercent,
	)
}

// IsHealthy returns whether the sandbox is operating normally
func (ss *SecuritySandbox) IsHealthy() bool {
	ss.mu.RLock()
	defer ss.mu.RUnlock()

	// Consider unhealthy if too many failures
	if ss.totalExecutions > 0 {
		failureRate := float64(ss.failedExecutions) / float64(ss.totalExecutions)
		return failureRate < 0.1 // Less than 10% failure rate
	}

	return true
}
