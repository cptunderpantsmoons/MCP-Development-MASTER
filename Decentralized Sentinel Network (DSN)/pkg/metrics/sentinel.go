package metrics

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// SentinelMetrics holds all Prometheus metrics for a sentinel node
type SentinelMetrics struct {
	// System metrics
	cpuUsage    prometheus.Gauge
	memoryUsage prometheus.Gauge
	diskUsage   prometheus.Gauge
	networkIO   *prometheus.CounterVec

	// Component health metrics
	componentHealth *prometheus.GaugeVec

	// Threat detection metrics
	threatsDetected   *prometheus.CounterVec
	scanDuration      *prometheus.HistogramVec
	scanErrors        *prometheus.CounterVec
	activeScanGauge   prometheus.Gauge

	// Configuration validation metrics
	configValidations *prometheus.CounterVec
	configErrors      *prometheus.CounterVec

	// API metrics
	grpcRequests    *prometheus.CounterVec
	grpcDuration    *prometheus.HistogramVec
	httpRequests    *prometheus.CounterVec
	httpDuration    *prometheus.HistogramVec

	// Health check metrics
	healthChecks *prometheus.CounterVec
	uptime       prometheus.Gauge

	// Audit metrics
	auditsStarted   *prometheus.CounterVec
	auditsCompleted *prometheus.CounterVec
	auditDuration   *prometheus.HistogramVec

	// Internal state
	sentinelID string
	startTime  time.Time
	mu         sync.RWMutex
}

// SystemMetrics represents system resource metrics
type SystemMetrics struct {
	CPUUsagePercent    float64
	MemoryUsageBytes   int64
	MemoryTotalBytes   int64
	DiskUsageBytes     int64
	DiskTotalBytes     int64
	NetworkBytesIn     int64
	NetworkBytesOut    int64
	ActiveConnections  int
}

// NewSentinelMetrics creates a new SentinelMetrics instance
func NewSentinelMetrics(sentinelID string) (*SentinelMetrics, error) {
	namespace := "dsn"
	subsystem := "sentinel"

	labels := prometheus.Labels{
		"sentinel_id": sentinelID,
	}

	metrics := &SentinelMetrics{
		sentinelID: sentinelID,
		startTime:  time.Now(),

		// System metrics
		cpuUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "cpu_usage_percent",
			Help:        "Current CPU usage percentage",
			ConstLabels: labels,
		}),

		memoryUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "memory_usage_bytes",
			Help:        "Current memory usage in bytes",
			ConstLabels: labels,
		}),

		diskUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "disk_usage_bytes",
			Help:        "Current disk usage in bytes",
			ConstLabels: labels,
		}),

		networkIO: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "network_bytes_total",
			Help:        "Total network bytes transferred",
			ConstLabels: labels,
		}, []string{"direction"}), // in, out

		// Component health metrics
		componentHealth: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "component_health",
			Help:        "Health status of sentinel components (1=healthy, 0=unhealthy)",
			ConstLabels: labels,
		}, []string{"component"}),

		// Threat detection metrics
		threatsDetected: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "threats_detected_total",
			Help:        "Total number of threats detected",
			ConstLabels: labels,
		}, []string{"severity", "type"}),

		scanDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "scan_duration_seconds",
			Help:        "Duration of threat detection scans",
			ConstLabels: labels,
			Buckets:     prometheus.ExponentialBuckets(0.1, 2, 10), // 0.1s to ~100s
		}, []string{"scan_type"}),

		scanErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "scan_errors_total",
			Help:        "Total number of scan errors",
			ConstLabels: labels,
		}, []string{"scan_type", "error_type"}),

		activeScanGauge: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "active_scans",
			Help:        "Number of currently active scans",
			ConstLabels: labels,
		}),

		// Configuration validation metrics
		configValidations: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "config_validations_total",
			Help:        "Total number of configuration validations",
			ConstLabels: labels,
		}, []string{"config_type", "result"}), // result: valid, invalid

		configErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "config_errors_total",
			Help:        "Total number of configuration errors",
			ConstLabels: labels,
		}, []string{"config_type", "error_type"}),

		// API metrics
		grpcRequests: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "grpc_requests_total",
			Help:        "Total number of gRPC requests",
			ConstLabels: labels,
		}, []string{"method", "status"}),

		grpcDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "grpc_request_duration_seconds",
			Help:        "Duration of gRPC requests",
			ConstLabels: labels,
			Buckets:     prometheus.DefBuckets,
		}, []string{"method"}),

		httpRequests: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "http_requests_total",
			Help:        "Total number of HTTP requests",
			ConstLabels: labels,
		}, []string{"method", "endpoint", "status"}),

		httpDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "http_request_duration_seconds",
			Help:        "Duration of HTTP requests",
			ConstLabels: labels,
			Buckets:     prometheus.DefBuckets,
		}, []string{"method", "endpoint"}),

		// Health check metrics
		healthChecks: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "health_checks_total",
			Help:        "Total number of health checks",
			ConstLabels: labels,
		}, []string{"component", "status"}), // status: healthy, unhealthy

		uptime: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "uptime_seconds",
			Help:        "Uptime of the sentinel node in seconds",
			ConstLabels: labels,
		}),

		// Audit metrics
		auditsStarted: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "audits_started_total",
			Help:        "Total number of audits started",
			ConstLabels: labels,
		}, []string{"audit_type"}),

		auditsCompleted: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "audits_completed_total",
			Help:        "Total number of audits completed",
			ConstLabels: labels,
		}, []string{"audit_type", "status"}), // status: success, failure

		auditDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "audit_duration_seconds",
			Help:        "Duration of audits",
			ConstLabels: labels,
			Buckets:     prometheus.ExponentialBuckets(1, 2, 12), // 1s to ~1 hour
		}, []string{"audit_type"}),
	}

	return metrics, nil
}

// Start begins metrics collection
func (m *SentinelMetrics) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Start uptime tracking
	go m.trackUptime()
}

// Stop stops metrics collection
func (m *SentinelMetrics) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Cleanup if needed
}

// UpdateSystemMetrics updates system resource metrics
func (m *SentinelMetrics) UpdateSystemMetrics(metrics *SystemMetrics) {
	m.cpuUsage.Set(metrics.CPUUsagePercent)
	m.memoryUsage.Set(float64(metrics.MemoryUsageBytes))
	m.diskUsage.Set(float64(metrics.DiskUsageBytes))
	m.networkIO.WithLabelValues("in").Add(float64(metrics.NetworkBytesIn))
	m.networkIO.WithLabelValues("out").Add(float64(metrics.NetworkBytesOut))
}

// UpdateComponentHealth updates component health status
func (m *SentinelMetrics) UpdateComponentHealth(component string, healthy bool) {
	value := 0.0
	if healthy {
		value = 1.0
	}
	m.componentHealth.WithLabelValues(component).Set(value)
	
	status := "unhealthy"
	if healthy {
		status = "healthy"
	}
	m.healthChecks.WithLabelValues(component, status).Inc()
}

// RecordThreatDetected records a detected threat
func (m *SentinelMetrics) RecordThreatDetected(severity, threatType string) {
	m.threatsDetected.WithLabelValues(severity, threatType).Inc()
}

// RecordScanDuration records the duration of a scan
func (m *SentinelMetrics) RecordScanDuration(scanType string, duration time.Duration) {
	m.scanDuration.WithLabelValues(scanType).Observe(duration.Seconds())
}

// RecordScanError records a scan error
func (m *SentinelMetrics) RecordScanError(scanType, errorType string) {
	m.scanErrors.WithLabelValues(scanType, errorType).Inc()
}

// SetActiveScans sets the number of active scans
func (m *SentinelMetrics) SetActiveScans(count int) {
	m.activeScanGauge.Set(float64(count))
}

// RecordConfigValidation records a configuration validation
func (m *SentinelMetrics) RecordConfigValidation(configType string, valid bool) {
	result := "invalid"
	if valid {
		result = "valid"
	}
	m.configValidations.WithLabelValues(configType, result).Inc()
}

// RecordConfigError records a configuration error
func (m *SentinelMetrics) RecordConfigError(configType, errorType string) {
	m.configErrors.WithLabelValues(configType, errorType).Inc()
}

// RecordGRPCRequest records a gRPC request
func (m *SentinelMetrics) RecordGRPCRequest(method, status string, duration time.Duration) {
	m.grpcRequests.WithLabelValues(method, status).Inc()
	m.grpcDuration.WithLabelValues(method).Observe(duration.Seconds())
}

// RecordHTTPRequest records an HTTP request
func (m *SentinelMetrics) RecordHTTPRequest(method, endpoint, status string, duration time.Duration) {
	m.httpRequests.WithLabelValues(method, endpoint, status).Inc()
	m.httpDuration.WithLabelValues(method, endpoint).Observe(duration.Seconds())
}

// RecordAuditStarted records an audit start
func (m *SentinelMetrics) RecordAuditStarted(auditType string) {
	m.auditsStarted.WithLabelValues(auditType).Inc()
}

// RecordAuditCompleted records an audit completion
func (m *SentinelMetrics) RecordAuditCompleted(auditType string, success bool, duration time.Duration) {
	status := "failure"
	if success {
		status = "success"
	}
	m.auditsCompleted.WithLabelValues(auditType, status).Inc()
	m.auditDuration.WithLabelValues(auditType).Observe(duration.Seconds())
}

// trackUptime continuously updates the uptime metric
func (m *SentinelMetrics) trackUptime() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		uptime := time.Since(m.startTime).Seconds()
		m.uptime.Set(uptime)
	}
}

// GetSentinelID returns the sentinel ID
func (m *SentinelMetrics) GetSentinelID() string {
	return m.sentinelID
}

// GetStartTime returns the start time
func (m *SentinelMetrics) GetStartTime() time.Time {
	return m.startTime
}

// MetricsCollector provides a way to collect custom metrics
type MetricsCollector struct {
	metrics map[string]prometheus.Collector
	mu      sync.RWMutex
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		metrics: make(map[string]prometheus.Collector),
	}
}

// RegisterMetric registers a custom metric
func (mc *MetricsCollector) RegisterMetric(name string, metric prometheus.Collector) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if _, exists := mc.metrics[name]; exists {
		return prometheus.ErrAlreadyReg
	}

	if err := prometheus.Register(metric); err != nil {
		return err
	}

	mc.metrics[name] = metric
	return nil
}

// UnregisterMetric unregisters a custom metric
func (mc *MetricsCollector) UnregisterMetric(name string) bool {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if metric, exists := mc.metrics[name]; exists {
		prometheus.Unregister(metric)
		delete(mc.metrics, name)
		return true
	}

	return false
}

// GetMetric retrieves a registered metric
func (mc *MetricsCollector) GetMetric(name string) (prometheus.Collector, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	metric, exists := mc.metrics[name]
	return metric, exists
}

// ListMetrics returns all registered metric names
func (mc *MetricsCollector) ListMetrics() []string {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	names := make([]string, 0, len(mc.metrics))
	for name := range mc.metrics {
		names = append(names, name)
	}

	return names
}