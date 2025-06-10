package unit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/dsn/internal/monitor"
)

func TestNewMonitor(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &monitor.Config{
		Interval:        time.Second,
		MetricsEnabled:  true,
		SecurityEnabled: true,
		RateLimit:       100,
	}

	mon := monitor.NewMonitor(logger, config)
	assert.NotNil(t, mon)
	assert.False(t, mon.IsRunning())
}

func TestMonitorStartStop(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &monitor.Config{
		Interval:        100 * time.Millisecond,
		MetricsEnabled:  true,
		SecurityEnabled: true,
		RateLimit:       100,
	}

	mon := monitor.NewMonitor(logger, config)

	// Test start
	err := mon.Start()
	require.NoError(t, err)
	assert.True(t, mon.IsRunning())

	// Test double start (should fail)
	err = mon.Start()
	assert.Error(t, err)

	// Wait a bit to let monitoring run
	time.Sleep(200 * time.Millisecond)

	// Test stop
	err = mon.Stop()
	require.NoError(t, err)
	assert.False(t, mon.IsRunning())

	// Test double stop (should fail)
	err = mon.Stop()
	assert.Error(t, err)
}

func TestMonitorMetricsCollection(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &monitor.Config{
		Interval:        50 * time.Millisecond,
		MetricsEnabled:  true,
		SecurityEnabled: true,
		RateLimit:       1000,
	}

	mon := monitor.NewMonitor(logger, config)
	metrics := mon.GetMetrics()
	assert.NotNil(t, metrics)

	// Start monitoring
	err := mon.Start()
	require.NoError(t, err)
	defer mon.Stop()

	// Wait for metrics collection
	time.Sleep(150 * time.Millisecond)

	// Verify metrics are being collected (values should be > 0)
	// Note: In a real test environment, we might mock the system calls
	// For now, we just verify the metrics objects exist
	assert.NotNil(t, metrics.CPUUsage)
	assert.NotNil(t, metrics.MemoryUsage)
	assert.NotNil(t, metrics.NetworkIO)
	assert.NotNil(t, metrics.NodeHealth)
}

func TestMonitorAuditOperations(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &monitor.Config{
		Interval:        time.Second,
		MetricsEnabled:  true,
		SecurityEnabled: true,
		RateLimit:       100,
	}

	mon := monitor.NewMonitor(logger, config)

	// Test audit load recording
	mon.RecordAuditLoad(0.75)
	// In a real implementation, we'd verify the metric value

	// Test scan recording
	mon.RecordScan()
	// In a real implementation, we'd verify the counter increment

	// Test threat detection recording
	mon.RecordThreatDetection("badbox_2.0")
	// In a real implementation, we'd verify the counter increment
}

func TestMonitorSecurityFeatures(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &monitor.Config{
		Interval:        time.Second,
		MetricsEnabled:  true,
		SecurityEnabled: true,
		RateLimit:       100,
	}

	mon := monitor.NewMonitor(logger, config)

	// Test alert triggering
	mon.TriggerAlert("suspicious_activity", "high")
	mon.TriggerAlert("ddos_attempt", "critical")
	// In a real implementation, we'd verify alert counters
}

func TestRateLimiter(t *testing.T) {
	rateLimiter := &monitor.RateLimiter{
		Tokens:     2,
		MaxTokens:  2,
		RefillRate: time.Second,
		LastRefill: time.Now(),
	}

	// Should allow first two requests
	assert.True(t, rateLimiter.Allow())
	assert.True(t, rateLimiter.Allow())

	// Should deny third request (no tokens left)
	assert.False(t, rateLimiter.Allow())

	// Wait for refill and try again
	time.Sleep(time.Second + 10*time.Millisecond)
	assert.True(t, rateLimiter.Allow())
}

func TestMetricValidator(t *testing.T) {
	validator := &monitor.MetricValidator{
		ExpectedRanges: map[string]monitor.MetricRange{
			"cpu_usage":    {Min: 0.0, Max: 100.0},
			"memory_usage": {Min: 0.0, Max: 100.0},
			"node_health":  {Min: 0.0, Max: 1.0},
		},
	}

	// Test valid metrics
	assert.True(t, validator.ValidateMetric("cpu_usage", 50.0))
	assert.True(t, validator.ValidateMetric("memory_usage", 75.5))
	assert.True(t, validator.ValidateMetric("node_health", 0.85))

	// Test invalid metrics (out of range)
	assert.False(t, validator.ValidateMetric("cpu_usage", -10.0))
	assert.False(t, validator.ValidateMetric("cpu_usage", 150.0))
	assert.False(t, validator.ValidateMetric("memory_usage", 200.0))
	assert.False(t, validator.ValidateMetric("node_health", 1.5))

	// Test unknown metric (should allow)
	assert.True(t, validator.ValidateMetric("unknown_metric", 999.0))
}

func TestHealthScoreCalculation(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &monitor.Config{
		Interval:        time.Second,
		MetricsEnabled:  true,
		SecurityEnabled: true,
		RateLimit:       100,
	}

	mon := monitor.NewMonitor(logger, config)

	// Test health score calculation with reflection or by exposing the method
	// For now, we'll test through the monitoring process
	err := mon.Start()
	require.NoError(t, err)
	defer mon.Stop()

	// Let it run briefly to calculate health
	time.Sleep(100 * time.Millisecond)

	// Health score should be calculated and set
	// In a real implementation, we'd have a way to get the calculated value
}

// Benchmark tests for performance under load
func BenchmarkMetricsCollection(b *testing.B) {
	logger := zap.NewNop()
	config := &monitor.Config{
		Interval:        time.Millisecond,
		MetricsEnabled:  true,
		SecurityEnabled: true,
		RateLimit:       10000,
	}

	mon := monitor.NewMonitor(logger, config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mon.RecordScan()
		mon.RecordAuditLoad(float64(i % 100))
	}
}

func BenchmarkRateLimiter(b *testing.B) {
	rateLimiter := &monitor.RateLimiter{
		Tokens:     1000,
		MaxTokens:  1000,
		RefillRate: time.Millisecond,
		LastRefill: time.Now(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rateLimiter.Allow()
	}
}

// Fuzz test for metric validation (security testing)
func FuzzMetricValidator(f *testing.F) {
	validator := &monitor.MetricValidator{
		ExpectedRanges: map[string]monitor.MetricRange{
			"cpu_usage": {Min: 0.0, Max: 100.0},
		},
	}

	// Add seed inputs
	f.Add("cpu_usage", 50.0)
	f.Add("cpu_usage", -10.0)
	f.Add("cpu_usage", 150.0)
	f.Add("unknown", 999.0)

	f.Fuzz(func(t *testing.T, metricName string, value float64) {
		// Should not panic regardless of input
		result := validator.ValidateMetric(metricName, value)
		
		// For known metrics, validate the result makes sense
		if metricName == "cpu_usage" {
			expected := value >= 0.0 && value <= 100.0
			assert.Equal(t, expected, result)
		}
	})
}

// Test concurrent access (race condition testing)
func TestConcurrentAccess(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &monitor.Config{
		Interval:        10 * time.Millisecond,
		MetricsEnabled:  true,
		SecurityEnabled: true,
		RateLimit:       1000,
	}

	mon := monitor.NewMonitor(logger, config)
	err := mon.Start()
	require.NoError(t, err)
	defer mon.Stop()

	// Run concurrent operations
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				mon.RecordScan()
				mon.RecordAuditLoad(float64(j))
				mon.TriggerAlert("test_alert", "low")
			}
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Should not have crashed
	assert.True(t, mon.IsRunning())
}

// Test memory usage under load (anti-memory exhaustion)
func TestMemoryUsage(t *testing.T) {
	logger := zap.NewNop() // Reduce memory overhead
	config := &monitor.Config{
		Interval:        time.Millisecond,
		MetricsEnabled:  true,
		SecurityEnabled: true,
		RateLimit:       10000,
	}

	mon := monitor.NewMonitor(logger, config)
	err := mon.Start()
	require.NoError(t, err)
	defer mon.Stop()

	// Generate load for a short period
	start := time.Now()
	for time.Since(start) < 100*time.Millisecond {
		mon.RecordScan()
		mon.RecordAuditLoad(0.5)
	}

	// Memory should not grow excessively
	// In a real test, we'd measure actual memory usage
}

// Test error handling and recovery
func TestErrorHandling(t *testing.T) {
	logger := zaptest.NewLogger(t)
	config := &monitor.Config{
		Interval:        10 * time.Millisecond,
		MetricsEnabled:  true,
		SecurityEnabled: true,
		RateLimit:       100,
	}

	mon := monitor.NewMonitor(logger, config)
	err := mon.Start()
	require.NoError(t, err)
	defer mon.Stop()

	// Monitor should continue running even if individual metric collection fails
	time.Sleep(50 * time.Millisecond)
	assert.True(t, mon.IsRunning())
}