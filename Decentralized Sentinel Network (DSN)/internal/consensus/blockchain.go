package consensus

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/dsn/decentralized-sentinel-network/pkg/logger"
)

// Blockchain represents a simple blockchain for consensus state validation
type Blockchain struct {
	chain    []*Block
	nodeID   string
	logger   logger.Logger
	mu       sync.RWMutex
}

// Block represents a block in the blockchain
type Block struct {
	Height       int64        `json:"height"`
	Hash         string       `json:"hash"`
	PreviousHash string       `json:"previous_hash"`
	Timestamp    time.Time    `json:"timestamp"`
	State        *SystemState `json:"state"`
	Merkleroot   string       `json:"merkle_root"`
	Nonce        int64        `json:"nonce"`
	Signature    string       `json:"signature"`
}

// SystemState represents the system state stored in each block
type SystemState struct {
	SentinelNodes    map[string]*SentinelNodeState `json:"sentinel_nodes"`
	ThreatLevel      ThreatLevel                   `json:"threat_level"`
	SecurityEvents   []*SecurityEvent              `json:"security_events"`
	ConfigHash       string                        `json:"config_hash"`
	Timestamp        time.Time                     `json:"timestamp"`
	StateHash        string                        `json:"state_hash"`
	ValidationScore  float64                       `json:"validation_score"`
}

// SentinelNodeState represents the state of a sentinel node
type SentinelNodeState struct {
	NodeID          string                 `json:"node_id"`
	Status          NodeStatus             `json:"status"`
	HealthScore     float64                `json:"health_score"`
	LastSeen        time.Time              `json:"last_seen"`
	MetricSnapshot  *MetricSnapshot        `json:"metric_snapshot"`
	ThreatDetections int                   `json:"threat_detections"`
	Configuration   map[string]interface{} `json:"configuration"`
}

// SecurityEvent represents a security event in the system
type SecurityEvent struct {
	EventID     string    `json:"event_id"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	Description string    `json:"description"`
	Timestamp   time.Time `json:"timestamp"`
	Resolved    bool      `json:"resolved"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// MetricSnapshot represents system metrics at a point in time
type MetricSnapshot struct {
	CPUUsage       float64   `json:"cpu_usage"`
	MemoryUsage    float64   `json:"memory_usage"`
	NetworkRX      uint64    `json:"network_rx"`
	NetworkTX      uint64    `json:"network_tx"`
	DiskUsage      float64   `json:"disk_usage"`
	ProcessCount   int       `json:"process_count"`
	OpenFiles      int       `json:"open_files"`
	Timestamp      time.Time `json:"timestamp"`
}

// ThreatLevel represents the overall threat level
type ThreatLevel int

const (
	ThreatLevelLow ThreatLevel = iota
	ThreatLevelMedium
	ThreatLevelHigh
	ThreatLevelCritical
)

func (tl ThreatLevel) String() string {
	switch tl {
	case ThreatLevelLow:
		return "low"
	case ThreatLevelMedium:
		return "medium"
	case ThreatLevelHigh:
		return "high"
	case ThreatLevelCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// NodeStatus represents the status of a sentinel node
type NodeStatus int

const (
	NodeStatusOnline NodeStatus = iota
	NodeStatusOffline
	NodeStatusDegraded
	NodeStatusMaintenance
	NodeStatusSuspicious
)

func (ns NodeStatus) String() string {
	switch ns {
	case NodeStatusOnline:
		return "online"
	case NodeStatusOffline:
		return "offline"
	case NodeStatusDegraded:
		return "degraded"
	case NodeStatusMaintenance:
		return "maintenance"
	case NodeStatusSuspicious:
		return "suspicious"
	default:
		return "unknown"
	}
}

// NewBlockchain creates a new blockchain instance
func NewBlockchain(nodeID string, logger logger.Logger) (*Blockchain, error) {
	if nodeID == "" {
		return nil, fmt.Errorf("node ID is required")
	}

	bc := &Blockchain{
		chain:  make([]*Block, 0),
		nodeID: nodeID,
		logger: logger.WithField(logger.FieldComponent, "blockchain"),
	}

	// Create genesis block
	genesisBlock := bc.createGenesisBlock()
	bc.chain = append(bc.chain, genesisBlock)

	logger.Info("Blockchain initialized",
		"node_id", nodeID,
		"genesis_hash", genesisBlock.Hash,
	)

	return bc, nil
}

// CreateBlock creates a new block with the given system state
func (bc *Blockchain) CreateBlock(state *SystemState) (*Block, error) {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	if state == nil {
		return nil, fmt.Errorf("system state is required")
	}

	// Ensure state has proper timestamp and hash
	state.Timestamp = time.Now()
	state.StateHash = bc.calculateStateHash(state)

	// Get previous block
	var previousHash string
	var height int64
	if len(bc.chain) > 0 {
		lastBlock := bc.chain[len(bc.chain)-1]
		previousHash = lastBlock.Hash
		height = lastBlock.Height + 1
	}

	// Create new block
	block := &Block{
		Height:       height,
		PreviousHash: previousHash,
		Timestamp:    time.Now(),
		State:        state,
		Merkleroot:   bc.calculateMerkleRoot(state),
	}

	// Calculate block hash
	block.Hash = bc.calculateBlockHash(block)

	// Sign block (simplified)
	block.Signature = bc.signBlock(block)

	bc.logger.Debug("Block created",
		"height", block.Height,
		"hash", block.Hash,
		"state_hash", state.StateHash,
	)

	return block, nil
}

// AddBlock adds a validated block to the blockchain
func (bc *Blockchain) AddBlock(block *Block) error {
	bc.mu.Lock()
	defer bc.mu.Unlock()

	if block == nil {
		return fmt.Errorf("block cannot be nil")
	}

	// Validate block before adding
	if !bc.validateBlockInternal(block) {
		return fmt.Errorf("invalid block")
	}

	// Check if block already exists
	for _, existingBlock := range bc.chain {
		if existingBlock.Hash == block.Hash {
			bc.logger.Debug("Block already exists", "hash", block.Hash)
			return nil // Not an error, just ignore
		}
	}

	// Add block to chain
	bc.chain = append(bc.chain, block)

	bc.logger.Info("Block added to blockchain",
		"height", block.Height,
		"hash", block.Hash,
		"chain_length", len(bc.chain),
	)

	return nil
}

// ValidateBlock validates a block for consensus
func (bc *Blockchain) ValidateBlock(block *Block) bool {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	return bc.validateBlockInternal(block)
}

// validateBlockInternal performs internal block validation
func (bc *Blockchain) validateBlockInternal(block *Block) bool {
	// Basic validation
	if block == nil {
		bc.logger.Debug("Block validation failed: nil block")
		return false
	}

	if block.Hash == "" {
		bc.logger.Debug("Block validation failed: empty hash")
		return false
	}

	if block.State == nil {
		bc.logger.Debug("Block validation failed: nil state")
		return false
	}

	// Validate block hash
	expectedHash := bc.calculateBlockHash(block)
	if block.Hash != expectedHash {
		bc.logger.Debug("Block validation failed: hash mismatch",
			"expected", expectedHash,
			"actual", block.Hash,
		)
		return false
	}

	// Validate state hash
	expectedStateHash := bc.calculateStateHash(block.State)
	if block.State.StateHash != expectedStateHash {
		bc.logger.Debug("Block validation failed: state hash mismatch",
			"expected", expectedStateHash,
			"actual", block.State.StateHash,
		)
		return false
	}

	// Validate merkle root
	expectedMerkleRoot := bc.calculateMerkleRoot(block.State)
	if block.Merkleroot != expectedMerkleRoot {
		bc.logger.Debug("Block validation failed: merkle root mismatch",
			"expected", expectedMerkleRoot,
			"actual", block.Merkleroot,
		)
		return false
	}

	// Validate chain continuity
	if len(bc.chain) > 0 {
		lastBlock := bc.chain[len(bc.chain)-1]
		if block.Height != lastBlock.Height+1 {
			bc.logger.Debug("Block validation failed: height mismatch",
				"expected", lastBlock.Height+1,
				"actual", block.Height,
			)
			return false
		}

		if block.PreviousHash != lastBlock.Hash {
			bc.logger.Debug("Block validation failed: previous hash mismatch",
				"expected", lastBlock.Hash,
				"actual", block.PreviousHash,
			)
			return false
		}
	}

	// Validate timestamp (not too far in future or past)
	now := time.Now()
	if block.Timestamp.After(now.Add(5*time.Minute)) {
		bc.logger.Debug("Block validation failed: timestamp too far in future")
		return false
	}

	if block.Timestamp.Before(now.Add(-24*time.Hour)) {
		bc.logger.Debug("Block validation failed: timestamp too old")
		return false
	}

	return true
}

// GetHeight returns the current blockchain height
func (bc *Blockchain) GetHeight() int64 {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	if len(bc.chain) == 0 {
		return 0
	}

	return bc.chain[len(bc.chain)-1].Height
}

// GetLastBlock returns the last block in the chain
func (bc *Blockchain) GetLastBlock() *Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	if len(bc.chain) == 0 {
		return nil
	}

	return bc.chain[len(bc.chain)-1]
}

// GetLastBlockTime returns the timestamp of the last block
func (bc *Blockchain) GetLastBlockTime() time.Time {
	lastBlock := bc.GetLastBlock()
	if lastBlock == nil {
		return time.Time{}
	}
	return lastBlock.Timestamp
}

// GetBlock returns a block by height
func (bc *Blockchain) GetBlock(height int64) *Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	for _, block := range bc.chain {
		if block.Height == height {
			return block
		}
	}

	return nil
}

// GetBlockByHash returns a block by hash
func (bc *Blockchain) GetBlockByHash(hash string) *Block {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	for _, block := range bc.chain {
		if block.Hash == hash {
			return block
		}
	}

	return nil
}

// GetCurrentState returns the current system state from the last block
func (bc *Blockchain) GetCurrentState() *SystemState {
	lastBlock := bc.GetLastBlock()
	if lastBlock == nil {
		return nil
	}
	return lastBlock.State
}

// GetStateHistory returns the state history for the last n blocks
func (bc *Blockchain) GetStateHistory(count int) []*SystemState {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	var states []*SystemState
	startIndex := len(bc.chain) - count
	if startIndex < 0 {
		startIndex = 0
	}

	for i := startIndex; i < len(bc.chain); i++ {
		if bc.chain[i].State != nil {
			states = append(states, bc.chain[i].State)
		}
	}

	return states
}

// Helper methods

func (bc *Blockchain) createGenesisBlock() *Block {
	// Create initial system state
	state := &SystemState{
		SentinelNodes:   make(map[string]*SentinelNodeState),
		ThreatLevel:     ThreatLevelLow,
		SecurityEvents:  make([]*SecurityEvent, 0),
		ConfigHash:      bc.calculateConfigHash(),
		Timestamp:       time.Now(),
		ValidationScore: 1.0,
	}

	// Add self as initial node
	state.SentinelNodes[bc.nodeID] = &SentinelNodeState{
		NodeID:           bc.nodeID,
		Status:           NodeStatusOnline,
		HealthScore:      1.0,
		LastSeen:         time.Now(),
		ThreatDetections: 0,
		Configuration:    make(map[string]interface{}),
	}

	state.StateHash = bc.calculateStateHash(state)

	block := &Block{
		Height:       0,
		Hash:         "",
		PreviousHash: "",
		Timestamp:    time.Now(),
		State:        state,
		Merkleroot:   bc.calculateMerkleRoot(state),
		Nonce:        0,
	}

	block.Hash = bc.calculateBlockHash(block)
	block.Signature = bc.signBlock(block)

	return block
}

func (bc *Blockchain) calculateBlockHash(block *Block) string {
	// Create hash input without the hash field itself
	hashInput := fmt.Sprintf("%d:%s:%d:%s:%s:%d",
		block.Height,
		block.PreviousHash,
		block.Timestamp.Unix(),
		block.State.StateHash,
		block.Merkleroot,
		block.Nonce,
	)

	hash := sha256.Sum256([]byte(hashInput))
	return hex.EncodeToString(hash[:])
}

func (bc *Blockchain) calculateStateHash(state *SystemState) string {
	// Serialize state for hashing
	stateBytes, err := json.Marshal(state)
	if err != nil {
		bc.logger.Error("Failed to marshal state for hashing", logger.FieldError, err)
		return ""
	}

	hash := sha256.Sum256(stateBytes)
	return hex.EncodeToString(hash[:])
}

func (bc *Blockchain) calculateMerkleRoot(state *SystemState) string {
	// Simple merkle root calculation based on state components
	var components []string

	// Add node states
	for nodeID, nodeState := range state.SentinelNodes {
		nodeBytes, _ := json.Marshal(nodeState)
		nodeHash := sha256.Sum256(nodeBytes)
		components = append(components, nodeID+":"+hex.EncodeToString(nodeHash[:8]))
	}

	// Add security events
	for _, event := range state.SecurityEvents {
		eventBytes, _ := json.Marshal(event)
		eventHash := sha256.Sum256(eventBytes)
		components = append(components, event.EventID+":"+hex.EncodeToString(eventHash[:8]))
	}

	// Calculate merkle root
	if len(components) == 0 {
		return "empty"
	}

	// Simple merkle tree implementation
	for len(components) > 1 {
		var nextLevel []string
		for i := 0; i < len(components); i += 2 {
			var combined string
			if i+1 < len(components) {
				combined = components[i] + components[i+1]
			} else {
				combined = components[i] + components[i] // Duplicate if odd number
			}
			hash := sha256.Sum256([]byte(combined))
			nextLevel = append(nextLevel, hex.EncodeToString(hash[:8]))
		}
		components = nextLevel
	}

	return components[0]
}

func (bc *Blockchain) calculateConfigHash() string {
	// Simple config hash based on node ID and timestamp
	configData := fmt.Sprintf("%s:%d", bc.nodeID, time.Now().Unix())
	hash := sha256.Sum256([]byte(configData))
	return hex.EncodeToString(hash[:16])
}

func (bc *Blockchain) signBlock(block *Block) string {
	// Simplified block signing (in production, use proper cryptographic signatures)
	signatureData := fmt.Sprintf("%s:%s:%d", bc.nodeID, block.Hash, block.Timestamp.Unix())
	hash := sha256.Sum256([]byte(signatureData))
	return hex.EncodeToString(hash[:16])
}

// GetChainInfo returns information about the blockchain
func (bc *Blockchain) GetChainInfo() map[string]interface{} {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	var totalEvents int
	var totalNodes int
	currentState := bc.GetCurrentState()
	if currentState != nil {
		totalEvents = len(currentState.SecurityEvents)
		totalNodes = len(currentState.SentinelNodes)
	}

	return map[string]interface{}{
		"height":        bc.GetHeight(),
		"block_count":   len(bc.chain),
		"last_updated":  bc.GetLastBlockTime(),
		"total_events":  totalEvents,
		"total_nodes":   totalNodes,
		"current_threat_level": func() string {
			if currentState != nil {
				return currentState.ThreatLevel.String()
			}
			return "unknown"
		}(),
	}
}

// ValidateChain validates the entire blockchain integrity
func (bc *Blockchain) ValidateChain() error {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	for i, block := range bc.chain {
		if !bc.validateBlockInternal(block) {
			return fmt.Errorf("invalid block at height %d", i)
		}

		// Additional chain continuity checks
		if i > 0 {
			prevBlock := bc.chain[i-1]
			if block.PreviousHash != prevBlock.Hash {
				return fmt.Errorf("broken chain at height %d", i)
			}
			if block.Height != prevBlock.Height+1 {
				return fmt.Errorf("height mismatch at block %d", i)
			}
		}
	}

	return nil
}

// IsHealthy returns whether the blockchain is in a healthy state
func (bc *Blockchain) IsHealthy() bool {
	bc.mu.RLock()
	defer bc.mu.RUnlock()

	// Check basic health conditions
	if len(bc.chain) == 0 {
		return false
	}

	// Check if last block is recent
	lastBlock := bc.chain[len(bc.chain)-1]
	if time.Since(lastBlock.Timestamp) > 1*time.Hour {
		return false
	}

	// Validate chain integrity
	return bc.ValidateChain() == nil
}
