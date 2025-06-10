package consensus

import (
	"context"
	"crypto/tls"
	"fmt"
	"sync"
	"time"

	"github.com/dsn/decentralized-sentinel-network/pkg/logger"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// PeerNode represents a peer node in the consensus network
type PeerNode struct {
	ID         string
	Endpoint   string
	Status     PeerStatus
	LastSeen   time.Time
	Connection *grpc.ClientConn
	logger     logger.Logger
	
	// Connection management
	mu            sync.RWMutex
	connected     bool
	reconnecting  bool
	maxRetries    int
	retryDelay    time.Duration
	
	// Communication channels
	proposalChan chan *Proposal
	voteChan     chan *Vote
	commitChan   chan *CommitMessage
	
	// Health tracking
	heartbeatInterval time.Duration
	lastHeartbeat     time.Time
	healthScore       float64
	
	// Metrics
	totalMessages   int64
	failedMessages  int64
	avgLatency      time.Duration
}

// PeerStatus represents the status of a peer node
type PeerStatus int

const (
	PeerStatusConnected PeerStatus = iota
	PeerStatusDisconnected
	PeerStatusConnecting
	PeerStatusSuspicious
	PeerStatusMaintenance
)

func (ps PeerStatus) String() string {
	switch ps {
	case PeerStatusConnected:
		return "connected"
	case PeerStatusDisconnected:
		return "disconnected"
	case PeerStatusConnecting:
		return "connecting"
	case PeerStatusSuspicious:
		return "suspicious"
	case PeerStatusMaintenance:
		return "maintenance"
	default:
		return "unknown"
	}
}

// PeerMetrics holds metrics for a peer
type PeerMetrics struct {
	TotalMessages    int64         `json:"total_messages"`
	FailedMessages   int64         `json:"failed_messages"`
	SuccessRate      float64       `json:"success_rate"`
	AverageLatency   time.Duration `json:"average_latency"`
	LastSeen         time.Time     `json:"last_seen"`
	HealthScore      float64       `json:"health_score"`
	Status           string        `json:"status"`
}

// NewPeerNode creates a new peer node connection
func NewPeerNode(endpoint string, logger logger.Logger) (*PeerNode, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("endpoint is required")
	}

	// Generate peer ID from endpoint (simplified)
	peerID := fmt.Sprintf("peer_%s_%d", endpoint, time.Now().Unix())

	peer := &PeerNode{
		ID:                peerID,
		Endpoint:          endpoint,
		Status:            PeerStatusDisconnected,
		LastSeen:          time.Now(),
		logger:            logger.WithField("peer_id", peerID),
		maxRetries:        5,
		retryDelay:        5 * time.Second,
		heartbeatInterval: 30 * time.Second,
		healthScore:       1.0,
		
		proposalChan: make(chan *Proposal, 100),
		voteChan:     make(chan *Vote, 100),
		commitChan:   make(chan *CommitMessage, 100),
	}

	// Attempt initial connection
	if err := peer.connect(); err != nil {
		peer.logger.Warn("Initial connection failed", logger.FieldError, err)
		// Don't return error for initial connection failure
		// Connection will be retried automatically
	}

	// Start background tasks
	go peer.connectionManager()
	go peer.heartbeatMonitor()

	return peer, nil
}

// connect establishes a gRPC connection to the peer
func (p *PeerNode) connect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.connected {
		return nil
	}

	p.Status = PeerStatusConnecting
	p.logger.Debug("Connecting to peer", "endpoint", p.Endpoint)

	// Configure gRPC connection options
	opts := []grpc.DialOption{
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second,
			Timeout:             3 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(4*1024*1024), // 4MB
			grpc.MaxCallSendMsgSize(4*1024*1024), // 4MB
		),
	}

	// Add TLS credentials if available
	if tlsConfig := p.getTLSConfig(); tlsConfig != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithInsecure())
	}

	// Establish connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, p.Endpoint, opts...)
	if err != nil {
		p.Status = PeerStatusDisconnected
		p.updateHealthScore(false)
		return fmt.Errorf("failed to connect to peer %s: %w", p.Endpoint, err)
	}

	p.Connection = conn
	p.connected = true
	p.Status = PeerStatusConnected
	p.LastSeen = time.Now()
	p.updateHealthScore(true)

	p.logger.Info("Connected to peer", "endpoint", p.Endpoint)
	return nil
}

// disconnect closes the connection to the peer
func (p *PeerNode) disconnect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.connected || p.Connection == nil {
		return nil
	}

	err := p.Connection.Close()
	p.Connection = nil
	p.connected = false
	p.Status = PeerStatusDisconnected

	p.logger.Info("Disconnected from peer", "endpoint", p.Endpoint)
	return err
}

// connectionManager handles automatic reconnection
func (p *PeerNode) connectionManager() {
	ticker := time.NewTicker(p.retryDelay)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.mu.RLock()
			needsReconnect := !p.connected && !p.reconnecting
			p.mu.RUnlock()

			if needsReconnect {
				p.attemptReconnect()
			}
		}
	}
}

// attemptReconnect attempts to reconnect to the peer
func (p *PeerNode) attemptReconnect() {
	p.mu.Lock()
	if p.reconnecting {
		p.mu.Unlock()
		return
	}
	p.reconnecting = true
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		p.reconnecting = false
		p.mu.Unlock()
	}()

	for attempt := 1; attempt <= p.maxRetries; attempt++ {
		p.logger.Debug("Attempting reconnection",
			"attempt", attempt,
			"max_retries", p.maxRetries,
		)

		if err := p.connect(); err == nil {
			p.logger.Info("Reconnection successful")
			return
		}

		// Exponential backoff
		delay := time.Duration(attempt) * p.retryDelay
		time.Sleep(delay)
	}

	p.logger.Warn("Max reconnection attempts reached",
		"max_retries", p.maxRetries,
		"endpoint", p.Endpoint,
	)

	// Mark as suspicious after failed reconnection attempts
	p.mu.Lock()
	p.Status = PeerStatusSuspicious
	p.healthScore *= 0.5 // Reduce health score
	p.mu.Unlock()
}

// heartbeatMonitor monitors peer health
func (p *PeerNode) heartbeatMonitor() {
	ticker := time.NewTicker(p.heartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.sendHeartbeat()
		}
	}
}

// sendHeartbeat sends a heartbeat to the peer
func (p *PeerNode) sendHeartbeat() {
	p.mu.RLock()
	connected := p.connected
	p.mu.RUnlock()

	if !connected {
		return
	}

	start := time.Now()
	
	// Simple heartbeat implementation
	// In production, this would use a proper gRPC health check service
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Simulate heartbeat call
	if err := p.simulateHeartbeat(ctx); err != nil {
		p.logger.Debug("Heartbeat failed", logger.FieldError, err)
		p.updateHealthScore(false)
		
		// If heartbeat fails, mark as disconnected
		p.mu.Lock()
		p.connected = false
		p.Status = PeerStatusDisconnected
		p.mu.Unlock()
	} else {
		latency := time.Since(start)
		p.updateLatency(latency)
		p.updateHealthScore(true)
		
		p.mu.Lock()
		p.lastHeartbeat = time.Now()
		p.LastSeen = time.Now()
		p.mu.Unlock()
	}
}

// SendProposal sends a proposal to the peer
func (p *PeerNode) SendProposal(proposal *Proposal) error {
	if !p.isConnected() {
		return fmt.Errorf("peer not connected")
	}

	start := time.Now()
	
	// Send proposal via gRPC (simplified implementation)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	err := p.sendProposalGRPC(ctx, proposal)
	
	// Update metrics
	p.updateMessageMetrics(err == nil, time.Since(start))
	
	if err != nil {
		p.logger.Debug("Failed to send proposal", 
			"proposal_id", proposal.ID,
			logger.FieldError, err,
		)
		return err
	}

	p.logger.Debug("Proposal sent successfully", 
		"proposal_id", proposal.ID,
		"peer", p.ID,
	)

	return nil
}

// SendVote sends a vote to the peer
func (p *PeerNode) SendVote(vote *Vote) error {
	if !p.isConnected() {
		return fmt.Errorf("peer not connected")
	}

	start := time.Now()
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := p.sendVoteGRPC(ctx, vote)
	
	p.updateMessageMetrics(err == nil, time.Since(start))
	
	if err != nil {
		p.logger.Debug("Failed to send vote", 
			"proposal_id", vote.ProposalID,
			logger.FieldError, err,
		)
		return err
	}

	return nil
}

// SendCommit sends a commit message to the peer
func (p *PeerNode) SendCommit(commit *CommitMessage) error {
	if !p.isConnected() {
		return fmt.Errorf("peer not connected")
	}

	start := time.Now()
	
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := p.sendCommitGRPC(ctx, commit)
	
	p.updateMessageMetrics(err == nil, time.Since(start))
	
	if err != nil {
		p.logger.Debug("Failed to send commit", 
			"proposal_id", commit.ProposalID,
			logger.FieldError, err,
		)
		return err
	}

	return nil
}

// GetBlockchainHeight gets the blockchain height from the peer
func (p *PeerNode) GetBlockchainHeight() (int64, error) {
	if !p.isConnected() {
		return 0, fmt.Errorf("peer not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Simplified implementation
	// In production, this would use proper gRPC calls
	return p.getHeightGRPC(ctx)
}

// Helper methods

func (p *PeerNode) isConnected() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.connected && p.Connection != nil
}

func (p *PeerNode) updateHealthScore(success bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if success {
		p.healthScore = min(p.healthScore*1.1, 1.0) // Increase up to 1.0
	} else {
		p.healthScore = max(p.healthScore*0.9, 0.1) // Decrease down to 0.1
	}
}

func (p *PeerNode) updateLatency(latency time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Simple moving average
	if p.avgLatency == 0 {
		p.avgLatency = latency
	} else {
		p.avgLatency = (p.avgLatency + latency) / 2
	}
}

func (p *PeerNode) updateMessageMetrics(success bool, latency time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.totalMessages++
	if !success {
		p.failedMessages++
	}

	p.updateLatency(latency)
}

func (p *PeerNode) getTLSConfig() *tls.Config {
	// Simplified TLS config
	// In production, use proper certificate validation
	return &tls.Config{
		InsecureSkipVerify: true, // Only for development
		ServerName:         "dsn-consensus",
	}
}

// Simplified gRPC method implementations
// In production, these would use proper protobuf definitions and gRPC services

func (p *PeerNode) simulateHeartbeat(ctx context.Context) error {
	// Simulate heartbeat call
	// In production, implement proper health check gRPC service
	time.Sleep(10 * time.Millisecond) // Simulate network latency
	return nil
}

func (p *PeerNode) sendProposalGRPC(ctx context.Context, proposal *Proposal) error {
	// Simulate proposal sending
	// In production, implement proper consensus gRPC service
	time.Sleep(50 * time.Millisecond) // Simulate network latency
	return nil
}

func (p *PeerNode) sendVoteGRPC(ctx context.Context, vote *Vote) error {
	// Simulate vote sending
	time.Sleep(20 * time.Millisecond)
	return nil
}

func (p *PeerNode) sendCommitGRPC(ctx context.Context, commit *CommitMessage) error {
	// Simulate commit sending
	time.Sleep(30 * time.Millisecond)
	return nil
}

func (p *PeerNode) getHeightGRPC(ctx context.Context) (int64, error) {
	// Simulate height query
	time.Sleep(15 * time.Millisecond)
	return 100, nil // Simulated height
}

// GetMetrics returns peer metrics
func (p *PeerNode) GetMetrics() *PeerMetrics {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var successRate float64
	if p.totalMessages > 0 {
		successRate = float64(p.totalMessages-p.failedMessages) / float64(p.totalMessages) * 100
	}

	return &PeerMetrics{
		TotalMessages:  p.totalMessages,
		FailedMessages: p.failedMessages,
		SuccessRate:    successRate,
		AverageLatency: p.avgLatency,
		LastSeen:       p.LastSeen,
		HealthScore:    p.healthScore,
		Status:         p.Status.String(),
	}
}

// IsHealthy returns whether the peer is healthy
func (p *PeerNode) IsHealthy() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return p.connected && 
		   p.healthScore > 0.5 && 
		   time.Since(p.LastSeen) < 5*time.Minute &&
		   p.Status == PeerStatusConnected
}

// SetStatus updates the peer status
func (p *PeerNode) SetStatus(status PeerStatus) {
	p.mu.Lock()
	defer p.mu.Unlock()

	oldStatus := p.Status
	p.Status = status

	if oldStatus != status {
		p.logger.Info("Peer status changed",
			"old_status", oldStatus.String(),
			"new_status", status.String(),
		)
	}
}

// Close gracefully closes the peer connection
func (p *PeerNode) Close() error {
	p.logger.Info("Closing peer connection")
	
	// Close channels
	close(p.proposalChan)
	close(p.voteChan)
	close(p.commitChan)
	
	// Disconnect
	return p.disconnect()
}

// Utility functions
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
