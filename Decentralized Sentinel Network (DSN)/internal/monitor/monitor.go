package monitor

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"go.uber.org/zap"
)

// Monitor handles system health monitoring and metrics collection
type Monitor struct {
	logger   *zap.Logger
	metrics  *Metrics
	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
	mu       sync.RWMutex
	running  bool
	
	// Security: Rate limiting to prevent DDoS attacks
	rateLimiter *RateLimiter
	
	// Security: Metric validation to prevent spoofing
	validator *MetricValidator
}

// Metrics contains Prometheus metrics for monitoring
type Metrics struct {
	// System metrics with DSN-specific prefixes to prevent spoofing
	CPUUsage    prometheus.Gauge
	MemoryUsage prometheus.Gauge
	NetworkIO   *prometheus.CounterVec
	
	// DSN-specific metrics for audit operations
	AuditLoad        prometheus.Gauge
	ScanFrequency    prometheus.Counter
	ThreatDetections prometheus.Counter
	NodeHealth       prometheus.Gauge
	
	// Security metrics for attack detection
	SecurityEvents   *prometheus.CounterVec
	AlertsTriggered  prometheus.Counter
	MetricAnomalies  prometheus.Counter
}

// RateLimiter prevents metric flooding attacks - THREAD SAFE VERSION
type RateLimiter struct {
	tokens     int64         // Use int64 for atomic operations
	maxTokens  int64
	refillRate time.Duration
	lastRefill int64         // Unix nano timestamp for atomic access
	mu         sync.Mutex    // Protects refill operations
}

// MetricValidator ensures metric integrity - THREAD SAFE VERSION
type MetricValidator struct {
	expectedRanges map[string]MetricRange
	mu            sync.RWMutex // Protects concurrent access to ranges
}

// MetricRange defines valid ranges for metrics
type MetricRange struct {
	Min float64
	Max float64
}

// Config holds monitor configuration
type Config struct {
	Interval        time.Duration `yaml:"interval"`
	MetricsEnabled  bool          `yaml:"metrics_enabled"`
	SecurityEnabled bool          `yaml:"security_enabled"`
	RateLimit       int           `yaml:"rate_limit"`
}

// NewMonitor creates a new monitor instance with security features
func NewMonitor(logger *zap.Logger, config *Config) *Monitor {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Initialize rate limiter to prevent DDoS - THREAD SAFE
	rateLimiter := &RateLimiter{
		tokens:     int64(config.RateLimit),
		maxTokens:  int64(config.RateLimit),
		refillRate: time.Second,
		lastRefill: time.Now().UnixNano(),
	}
	
	// Initialize metric validator with expected ranges
	validator := &MetricValidator{
		expectedRanges: map[string]MetricRange{
			"cpu_usage":    {Min: 0.0, Max: 100.0},
			"memory_usage": {Min: 0.0, Max: 100.0},
			"node_health":  {Min: 0.0, Max: 1.0},
		},
	}
	
	return &Monitor{
		logger:      logger,
		metrics:     initMetrics(),
		interval:    config.Interval,
		ctx:         ctx,
		cancel:      cancel,
		rateLimiter: rateLimiter,
		validator:   validator,
	}
}

// initMetrics initializes Prometheus metrics with DSN-specific naming
func initMetrics() *Metrics {
	return &Metrics{
		CPUUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "dsn",
			Subsystem: "sentinel",
			Name:      "cpu_usage_percent",
			Help:      "Current CPU usage percentage",
		}),
		MemoryUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "dsn",
			Subsystem: "sentinel",
			Name:      "memory_usage_percent",
			Help:      "Current memory usage percentage",
		}),
		NetworkIO: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "dsn",
			Subsystem: "sentinel",
			Name:      "network_io_bytes_total",
			Help:      "Total network I/O bytes",
		}, []string{"direction"}),
		AuditLoad: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "dsn",
			Subsystem: "audit",
			Name:      "load_factor",
			Help:      "Current audit load factor",
		}),
		ScanFrequency: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: "dsn",
			Subsystem: "audit",
			Name:      "scans_total",
			Help:      "Total number of security scans performed",
		}),
		ThreatDetections: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: "dsn",
			Subsystem: "security",
			Name:      "threats_detected_total",
			Help:      "Total number of threats detected",
		}),
		NodeHealth: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "dsn",
			Subsystem: "sentinel",
			Name:      "node_health_score",
			Help:      "Current node health score (0-1)",
		}),
		SecurityEvents: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "dsn",
			Subsystem: "security",
			Name:      "events_total",
			Help:      "Total security events by type",
		}, []string{"event_type", "severity"}),
		AlertsTriggered: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: "dsn",
			Subsystem: "security",
			Name:      "alerts_triggered_total",
			Help:      "Total security alerts triggered",
		}),
		MetricAnomalies: promauto.NewCounter(prometheus.CounterOpts{
			Namespace: "dsn",
			Subsystem: "security",
			Name:      "metric_anomalies_total",
			Help:      "Total metric anomalies detected",
		}),
	}
}

// Start begins the monitoring process
func (m *Monitor) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if m.running {
		return fmt.Errorf("monitor is already running")
	}
	
	m.logger.Info("Starting DSN monitor with security features")
	m.running = true
	
	// Start monitoring goroutine
	m.wg.Add(1)
	go m.monitorLoop()
	
	return nil
}

// Stop gracefully stops the monitoring process
func (m *Monitor) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	
	if !m.running {
		return fmt.Errorf("monitor is not running")
	}
	
	m.logger.Info("Stopping DSN monitor")
	m.cancel()
	m.wg.Wait()
	m.running = false
	
	return nil
}

// monitorLoop is the main monitoring loop with security checks
func (m *Monitor) monitorLoop() {
	defer m.wg.Done()
	
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	
	for {
		select {
		case <-m.ctx.Done():
			m.logger.Info("Monitor loop stopped")
			return
		case <-ticker.C:
			if err := m.collectMetrics(); err != nil {
				m.logger.Error("Failed to collect metrics", zap.Error(err))
				m.metrics.SecurityEvents.WithLabelValues("metric_collection_error", "warning").Inc()
			}
		}
	}
}

// collectMetrics gathers system and DSN-specific metrics with security validation
func (m *Monitor) collectMetrics() error {
	// Security: Check rate limit to prevent DDoS
	if !m.rateLimiter.Allow() {
		m.logger.Warn("Metric collection rate limited")
		m.metrics.SecurityEvents.WithLabelValues("rate_limit_exceeded", "warning").Inc()
		return fmt.Errorf("rate limit exceeded")
	}
	
	// Collect CPU usage
	cpuPercent, err := cpu.Percent(0, false)
	if err != nil {
		return fmt.Errorf("failed to get CPU usage: %w", err)
	}
	
	if len(cpuPercent) > 0 {
		cpuUsage := cpuPercent[0]
		if m.validator.ValidateMetric("cpu_usage", cpuUsage) {
			m.metrics.CPUUsage.Set(cpuUsage)
		} else {
			m.logger.Warn("Invalid CPU metric detected", zap.Float64("value", cpuUsage))
			m.metrics.MetricAnomalies.Inc()
		}
	}
	
	// Collect memory usage
	memInfo, err := mem.VirtualMemory()
	if err != nil {
		return fmt.Errorf("failed to get memory usage: %w", err)
	}
	
	memUsage := memInfo.UsedPercent
	if m.validator.ValidateMetric("memory_usage", memUsage) {
		m.metrics.MemoryUsage.Set(memUsage)
	} else {
		m.logger.Warn("Invalid memory metric detected", zap.Float64("value", memUsage))
		m.metrics.MetricAnomalies.Inc()
	}
	
	// Collect network I/O
	netStats, err := net.IOCounters(false)
	if err != nil {
		return fmt.Errorf("failed to get network stats: %w", err)
	}
	
	if len(netStats) > 0 {
		m.metrics.NetworkIO.WithLabelValues("rx").Add(float64(netStats[0].BytesRecv))
		m.metrics.NetworkIO.WithLabelValues("tx").Add(float64(netStats[0].BytesSent))
	}
	
	// Calculate node health score
	healthScore := m.calculateHealthScore(cpuPercent[0], memUsage)
	if m.validator.ValidateMetric("node_health", healthScore) {
		m.metrics.NodeHealth.Set(healthScore)
	}
	
	// Log metrics collection
	m.logger.Debug("Metrics collected successfully",
		zap.Float64("cpu_usage", cpuPercent[0]),
		zap.Float64("memory_usage", memUsage),
		zap.Float64("health_score", healthScore),
	)
	
	return nil
}

// calculateHealthScore computes overall node health (0-1 scale)
func (m *Monitor) calculateHealthScore(cpuUsage, memUsage float64) float64 {
	// Simple health calculation - can be enhanced with more sophisticated algorithms
	cpuHealth := 1.0 - (cpuUsage / 100.0)
	memHealth := 1.0 - (memUsage / 100.0)
	
	// Weighted average (CPU 60%, Memory 40%)
	healthScore := (cpuHealth * 0.6) + (memHealth * 0.4)
	
	// Ensure score is between 0 and 1
	if healthScore < 0 {
		healthScore = 0
	}
	if healthScore > 1 {
		healthScore = 1
	}
	
	return healthScore
}

// RecordAuditLoad records the current audit load
func (m *Monitor) RecordAuditLoad(load float64) {
	m.metrics.AuditLoad.Set(load)
	m.logger.Debug("Audit load recorded", zap.Float64("load", load))
}

// RecordScan increments the scan counter
func (m *Monitor) RecordScan() {
	m.metrics.ScanFrequency.Inc()
	m.logger.Debug("Security scan recorded")
}

// RecordThreatDetection increments the threat detection counter
func (m *Monitor) RecordThreatDetection(threatType string) {
	m.metrics.ThreatDetections.Inc()
	m.metrics.SecurityEvents.WithLabelValues("threat_detected", "critical").Inc()
	m.logger.Info("Threat detection recorded", zap.String("type", threatType))
}

// TriggerAlert records a security alert
func (m *Monitor) TriggerAlert(alertType string, severity string) {
	m.metrics.AlertsTriggered.Inc()
	m.metrics.SecurityEvents.WithLabelValues(alertType, severity).Inc()
	m.logger.Warn("Security alert triggered",
		zap.String("type", alertType),
		zap.String("severity", severity),
	)
}

// Allow checks if an operation is allowed by the rate limiter - THREAD SAFE
func (rl *RateLimiter) Allow() bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now().UnixNano()
	lastRefill := atomic.LoadInt64(&rl.lastRefill)
	elapsed := time.Duration(now - lastRefill)
	
	// Refill tokens based on elapsed time
	if elapsed >= rl.refillRate {
		tokensToAdd := int64(elapsed / rl.refillRate)
		currentTokens := atomic.LoadInt64(&rl.tokens)
		newTokens := currentTokens + tokensToAdd
		
		if newTokens > rl.maxTokens {
			newTokens = rl.maxTokens
		}
		
		atomic.StoreInt64(&rl.tokens, newTokens)
		atomic.StoreInt64(&rl.lastRefill, now)
	}
	
	// Try to consume a token
	currentTokens := atomic.LoadInt64(&rl.tokens)
	if currentTokens > 0 {
		// Use compare-and-swap to safely decrement
		if atomic.CompareAndSwapInt64(&rl.tokens, currentTokens, currentTokens-1) {
			return true
		}
	}
	
	return false
}

// ValidateMetric checks if a metric value is within expected ranges
func (mv *MetricValidator) ValidateMetric(name string, value float64) bool {
	mv.mu.RLock()
	defer mv.mu.RUnlock()
	
	if metricRange, exists := mv.expectedRanges[name]; exists {
		return value >= metricRange.Min && value <= metricRange.Max
	}
	
	// If no range defined, allow the metric
	return true
}

// GetMetrics returns the current metrics instance
func (m *Monitor) GetMetrics() *Metrics {
	return m.metrics
}

// IsRunning returns whether the monitor is currently running
func (m *Monitor) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}