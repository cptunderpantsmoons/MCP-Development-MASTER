package sentinel

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/dsn/decentralized-sentinel-network/internal/sentinel/detector"
	"github.com/dsn/decentralized-sentinel-network/internal/sentinel/monitor"
	"github.com/dsn/decentralized-sentinel-network/internal/sentinel/server"
	"github.com/dsn/decentralized-sentinel-network/internal/sentinel/validator"
	"github.com/dsn/decentralized-sentinel-network/pkg/config"
	"github.com/dsn/decentralized-sentinel-network/pkg/logger"
	"github.com/dsn/decentralized-sentinel-network/pkg/metrics"
	sentinelv1 "github.com/dsn/decentralized-sentinel-network/proto/sentinel/v1"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// Sentinel represents a sentinel node instance
type Sentinel struct {
	config *config.SentinelConfig
	logger logger.Logger

	// Core components
	monitor   *monitor.Monitor
	detector  *detector.ThreatDetector
	validator *validator.ConfigValidator

	// Servers
	grpcServer    *grpc.Server
	httpServer    *http.Server
	metricsServer *http.Server
	healthServer  *health.Server

	// Metrics
	metrics *metrics.SentinelMetrics

	// Lifecycle
	mu       sync.RWMutex
	started  bool
	stopping bool
	done     chan struct{}
}

// New creates a new sentinel node instance
func New(cfg *config.SentinelConfig, log logger.Logger) (*Sentinel, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if log == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Initialize metrics
	sentinelMetrics, err := metrics.NewSentinelMetrics(cfg.SentinelID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize metrics: %w", err)
	}

	// Create core components
	systemMonitor, err := monitor.New(cfg, log.WithField(logger.FieldComponent, logger.ComponentMonitor))
	if err != nil {
		return nil, fmt.Errorf("failed to create monitor: %w", err)
	}

	threatDetector, err := detector.New(cfg, log.WithField(logger.FieldComponent, logger.ComponentDetector))
	if err != nil {
		return nil, fmt.Errorf("failed to create threat detector: %w", err)
	}

	configValidator, err := validator.New(cfg, log.WithField(logger.FieldComponent, logger.ComponentValidator))
	if err != nil {
		return nil, fmt.Errorf("failed to create config validator: %w", err)
	}

	return &Sentinel{
		config:    cfg,
		logger:    log.WithField(logger.FieldComponent, logger.ComponentSentinel),
		monitor:   systemMonitor,
		detector:  threatDetector,
		validator: configValidator,
		metrics:   sentinelMetrics,
		done:      make(chan struct{}),
	}, nil
}

// Start starts the sentinel node and all its components
func (s *Sentinel) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return fmt.Errorf("sentinel already started")
	}

	s.logger.Info("Starting sentinel node", logger.FieldSentinelID, s.config.SentinelID)

	// Start metrics collection
	s.metrics.Start()

	// Start core components
	if err := s.startComponents(ctx); err != nil {
		return fmt.Errorf("failed to start components: %w", err)
	}

	// Start servers
	if err := s.startServers(ctx); err != nil {
		return fmt.Errorf("failed to start servers: %w", err)
	}

	s.started = true
	s.logger.Info("Sentinel node started successfully",
		logger.FieldSentinelID, s.config.SentinelID,
		"grpc_port", s.config.Server.GRPCPort,
		"http_port", s.config.Server.HTTPPort,
		"metrics_port", s.config.Server.MetricsPort,
	)

	// Start background tasks
	go s.runBackgroundTasks(ctx)

	return nil
}

// Stop gracefully stops the sentinel node
func (s *Sentinel) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started || s.stopping {
		return nil
	}

	s.stopping = true
	s.logger.Info("Stopping sentinel node", logger.FieldSentinelID, s.config.SentinelID)

	// Stop servers
	s.stopServers()

	// Stop components
	s.stopComponents()

	// Stop metrics
	s.metrics.Stop()

	close(s.done)
	s.started = false
	s.stopping = false

	s.logger.Info("Sentinel node stopped", logger.FieldSentinelID, s.config.SentinelID)
	return nil
}

// IsHealthy returns the health status of the sentinel node
func (s *Sentinel) IsHealthy() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if !s.started || s.stopping {
		return false
	}

	// Check component health
	if !s.monitor.IsHealthy() {
		return false
	}

	if !s.detector.IsHealthy() {
		return false
	}

	if !s.validator.IsHealthy() {
		return false
	}

	return true
}

// GetStatus returns the current status of the sentinel node
func (s *Sentinel) GetStatus() *SentinelStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()

	status := &SentinelStatus{
		SentinelID: s.config.SentinelID,
		Started:    s.started,
		Healthy:    s.IsHealthy(),
		StartTime:  time.Now(), // This should be stored when starting
		Components: make(map[string]ComponentStatus),
	}

	// Get component statuses
	status.Components["monitor"] = ComponentStatus{
		Name:    "monitor",
		Healthy: s.monitor.IsHealthy(),
		Status:  s.monitor.GetStatus(),
	}

	status.Components["detector"] = ComponentStatus{
		Name:    "detector",
		Healthy: s.detector.IsHealthy(),
		Status:  s.detector.GetStatus(),
	}

	status.Components["validator"] = ComponentStatus{
		Name:    "validator",
		Healthy: s.validator.IsHealthy(),
		Status:  s.validator.GetStatus(),
	}

	return status
}

// startComponents starts all core components
func (s *Sentinel) startComponents(ctx context.Context) error {
	s.logger.Debug("Starting core components")

	// Start monitor
	if err := s.monitor.Start(ctx); err != nil {
		return fmt.Errorf("failed to start monitor: %w", err)
	}

	// Start threat detector
	if err := s.detector.Start(ctx); err != nil {
		return fmt.Errorf("failed to start threat detector: %w", err)
	}

	// Start config validator
	if err := s.validator.Start(ctx); err != nil {
		return fmt.Errorf("failed to start config validator: %w", err)
	}

	s.logger.Debug("Core components started successfully")
	return nil
}

// stopComponents stops all core components
func (s *Sentinel) stopComponents() {
	s.logger.Debug("Stopping core components")

	// Stop components in reverse order
	if s.validator != nil {
		s.validator.Stop()
	}

	if s.detector != nil {
		s.detector.Stop()
	}

	if s.monitor != nil {
		s.monitor.Stop()
	}

	s.logger.Debug("Core components stopped")
}

// startServers starts all servers (gRPC, HTTP, metrics)
func (s *Sentinel) startServers(ctx context.Context) error {
	s.logger.Debug("Starting servers")

	// Start gRPC server
	if err := s.startGRPCServer(); err != nil {
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}

	// Start HTTP server
	if err := s.startHTTPServer(); err != nil {
		return fmt.Errorf("failed to start HTTP server: %w", err)
	}

	// Start metrics server
	if s.config.Metrics.Enabled {
		if err := s.startMetricsServer(); err != nil {
			return fmt.Errorf("failed to start metrics server: %w", err)
		}
	}

	s.logger.Debug("Servers started successfully")
	return nil
}

// stopServers stops all servers
func (s *Sentinel) stopServers() {
	s.logger.Debug("Stopping servers")

	// Stop gRPC server
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}

	// Stop HTTP server
	if s.httpServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.httpServer.Shutdown(ctx)
	}

	// Stop metrics server
	if s.metricsServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		s.metricsServer.Shutdown(ctx)
	}

	s.logger.Debug("Servers stopped")
}

// startGRPCServer starts the gRPC server
func (s *Sentinel) startGRPCServer() error {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", s.config.Server.GRPCPort))
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port %d: %w", s.config.Server.GRPCPort, err)
	}

	// Create gRPC server with options
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(4 * 1024 * 1024), // 4MB
		grpc.MaxSendMsgSize(4 * 1024 * 1024), // 4MB
	}

	// Add TLS if enabled
	if s.config.Security.TLS.Enabled {
		// TODO: Add TLS credentials
		s.logger.Debug("TLS enabled for gRPC server")
	}

	s.grpcServer = grpc.NewServer(opts...)

	// Register health service
	s.healthServer = health.NewServer()
	grpc_health_v1.RegisterHealthServer(s.grpcServer, s.healthServer)

	// Register sentinel service
	sentinelService := server.NewSentinelService(s.config, s.logger, s.monitor, s.detector, s.validator)
	sentinelv1.RegisterSentinelServiceServer(s.grpcServer, sentinelService)

	// Start server in goroutine
	go func() {
		s.logger.Info("gRPC server listening", "port", s.config.Server.GRPCPort)
		if err := s.grpcServer.Serve(lis); err != nil {
			s.logger.Error("gRPC server error", logger.FieldError, err)
		}
	}()

	// Set health status
	s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	return nil
}

// startHTTPServer starts the HTTP server (for REST API via grpc-gateway)
func (s *Sentinel) startHTTPServer() error {
	mux := http.NewServeMux()

	// TODO: Add grpc-gateway handlers
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/status", s.handleStatus)

	s.httpServer = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.config.Server.HTTPPort),
		Handler:      mux,
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
	}

	// Start server in goroutine
	go func() {
		s.logger.Info("HTTP server listening", "port", s.config.Server.HTTPPort)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("HTTP server error", logger.FieldError, err)
		}
	}()

	return nil
}

// startMetricsServer starts the metrics server
func (s *Sentinel) startMetricsServer() error {
	mux := http.NewServeMux()
	mux.Handle(s.config.Metrics.Path, promhttp.Handler())

	s.metricsServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.config.Server.MetricsPort),
		Handler: mux,
	}

	// Start server in goroutine
	go func() {
		s.logger.Info("Metrics server listening", "port", s.config.Server.MetricsPort)
		if err := s.metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error("Metrics server error", logger.FieldError, err)
		}
	}()

	return nil
}

// runBackgroundTasks runs background maintenance tasks
func (s *Sentinel) runBackgroundTasks(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-ticker.C:
			s.performMaintenanceTasks()
		}
	}
}

// performMaintenanceTasks performs periodic maintenance
func (s *Sentinel) performMaintenanceTasks() {
	s.logger.Debug("Performing maintenance tasks")

	// Update health status
	if s.healthServer != nil {
		if s.IsHealthy() {
			s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
		} else {
			s.healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		}
	}

	// Update metrics
	s.metrics.UpdateComponentHealth("monitor", s.monitor.IsHealthy())
	s.metrics.UpdateComponentHealth("detector", s.detector.IsHealthy())
	s.metrics.UpdateComponentHealth("validator", s.validator.IsHealthy())

	// Collect system metrics
	if systemMetrics := s.monitor.GetSystemMetrics(); systemMetrics != nil {
		s.metrics.UpdateSystemMetrics(systemMetrics)
	}
}

// HTTP handlers
func (s *Sentinel) handleHealth(w http.ResponseWriter, r *http.Request) {
	if s.IsHealthy() {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("Unhealthy"))
	}
}

func (s *Sentinel) handleStatus(w http.ResponseWriter, r *http.Request) {
	status := s.GetStatus()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	
	// TODO: Marshal status to JSON
	w.Write([]byte(fmt.Sprintf(`{"sentinel_id":"%s","healthy":%t}`, status.SentinelID, status.Healthy)))
}

// Status types
type SentinelStatus struct {
	SentinelID string                       `json:"sentinel_id"`
	Started    bool                         `json:"started"`
	Healthy    bool                         `json:"healthy"`
	StartTime  time.Time                    `json:"start_time"`
	Components map[string]ComponentStatus   `json:"components"`
}

type ComponentStatus struct {
	Name    string      `json:"name"`
	Healthy bool        `json:"healthy"`
	Status  interface{} `json:"status"`
}