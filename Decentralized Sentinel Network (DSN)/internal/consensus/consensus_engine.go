package consensus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/dsn/decentralized-sentinel-network/pkg/config"
	"github.com/dsn/decentralized-sentinel-network/pkg/logger"
)

// ConsensusEngine implements distributed consensus for the DSN
type ConsensusEngine struct {
	config     *config.SentinelConfig
	logger     logger.Logger
	nodeID     string
	peers      map[string]*PeerNode
	blockchain *Blockchain
	validator  *StateValidator
	
	// Consensus state
	currentView   int64
	isPrimary     bool
	currentBlock  *Block
	proposals     map[string]*Proposal
	votes         map[string]map[string]*Vote
	
	// Communication channels
	proposalChan chan *Proposal
	voteChan     chan *Vote
	commitChan   chan *CommitMessage
	
	// Lifecycle
	mu      sync.RWMutex
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
}

// ConsensusState represents the current state of consensus
type ConsensusState struct {
	View         int64     `json:"view"`
	BlockHeight  int64     `json:"block_height"`
	PrimaryNode  string    `json:"primary_node"`
	ActivePeers  int       `json:"active_peers"`
	LastConsensus time.Time `json:"last_consensus"`
	Status       string    `json:"status"`
}

// Proposal represents a consensus proposal
type Proposal struct {
	ID        string          `json:"id"`
	View      int64           `json:"view"`
	Block     *Block          `json:"block"`
	ProposerID string         `json:"proposer_id"`
	Timestamp time.Time       `json:"timestamp"`
	Signature string          `json:"signature"`
}

// Vote represents a vote on a proposal
type Vote struct {
	ProposalID string    `json:"proposal_id"`
	VoterID    string    `json:"voter_id"`
	Decision   Decision  `json:"decision"`
	Timestamp  time.Time `json:"timestamp"`
	Signature  string    `json:"signature"`
}

// CommitMessage represents a commit decision
type CommitMessage struct {
	ProposalID string    `json:"proposal_id"`
	BlockHash  string    `json:"block_hash"`
	CommitterID string   `json:"committer_id"`
	Timestamp  time.Time `json:"timestamp"`
	Signature  string    `json:"signature"`
}

// Decision represents voting decisions
type Decision int

const (
	DecisionAccept Decision = iota
	DecisionReject
	DecisionAbstain
)

func (d Decision) String() string {
	switch d {
	case DecisionAccept:
		return "accept"
	case DecisionReject:
		return "reject"
	case DecisionAbstain:
		return "abstain"
	default:
		return "unknown"
	}
}

// NewConsensusEngine creates a new consensus engine
func NewConsensusEngine(cfg *config.SentinelConfig, log logger.Logger) (*ConsensusEngine, error) {
	if cfg == nil {
		return nil, fmt.Errorf("config is required")
	}
	if log == nil {
		return nil, fmt.Errorf("logger is required")
	}

	// Initialize blockchain
	blockchain, err := NewBlockchain(cfg.SentinelID, log)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize blockchain: %w", err)
	}

	// Initialize state validator
	validator := NewStateValidator(log)

	ctx, cancel := context.WithCancel(context.Background())

	return &ConsensusEngine{
		config:     cfg,
		logger:     log.WithField(logger.FieldComponent, "consensus"),
		nodeID:     cfg.SentinelID,
		peers:      make(map[string]*PeerNode),
		blockchain: blockchain,
		validator:  validator,
		proposals:  make(map[string]*Proposal),
		votes:      make(map[string]map[string]*Vote),
		
		proposalChan: make(chan *Proposal, 100),
		voteChan:     make(chan *Vote, 100),
		commitChan:   make(chan *CommitMessage, 100),
		
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

// Start initializes and starts the consensus engine
func (ce *ConsensusEngine) Start(ctx context.Context) error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if ce.running {
		return fmt.Errorf("consensus engine already running")
	}

	ce.logger.Info("Starting consensus engine",
		"node_id", ce.nodeID,
		"initial_view", ce.currentView,
	)

	// Initialize peer connections
	if err := ce.initializePeers(); err != nil {
		return fmt.Errorf("failed to initialize peers: %w", err)
	}

	// Start message processing goroutines
	go ce.processProposals()
	go ce.processVotes()
	go ce.processCommits()
	go ce.consensusLoop()

	// Start blockchain sync
	go ce.synchronizeBlockchain()

	ce.running = true
	ce.logger.Info("Consensus engine started successfully")

	return nil
}

// Stop gracefully stops the consensus engine
func (ce *ConsensusEngine) Stop() error {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	if !ce.running {
		return nil
	}

	ce.logger.Info("Stopping consensus engine")
	ce.cancel()
	ce.running = false

	return nil
}

// ProposeState proposes a new system state for consensus
func (ce *ConsensusEngine) ProposeState(state *SystemState) error {
	if !ce.running {
		return fmt.Errorf("consensus engine not running")
	}

	ce.mu.RLock()
	isPrimary := ce.isPrimary
	ce.mu.RUnlock()

	if !isPrimary {
		return fmt.Errorf("only primary node can propose states")
	}

	// Validate state before proposing
	if err := ce.validator.ValidateState(state); err != nil {
		return fmt.Errorf("invalid state: %w", err)
	}

	// Create new block with the state
	block, err := ce.blockchain.CreateBlock(state)
	if err != nil {
		return fmt.Errorf("failed to create block: %w", err)
	}

	// Create proposal
	proposal := &Proposal{
		ID:         ce.generateProposalID(block),
		View:       ce.currentView,
		Block:      block,
		ProposerID: ce.nodeID,
		Timestamp:  time.Now(),
	}

	// Sign proposal (simplified - in production use proper crypto)
	proposal.Signature = ce.signProposal(proposal)

	// Store proposal
	ce.mu.Lock()
	ce.proposals[proposal.ID] = proposal
	ce.votes[proposal.ID] = make(map[string]*Vote)
	ce.mu.Unlock()

	// Broadcast to peers
	ce.broadcastProposal(proposal)

	ce.logger.Info("State proposed for consensus",
		"proposal_id", proposal.ID,
		"view", proposal.View,
		"block_hash", block.Hash,
	)

	return nil
}

// consensusLoop handles the main consensus algorithm
func (ce *ConsensusEngine) consensusLoop() {
	ticker := time.NewTicker(10 * time.Second) // Consensus round every 10 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ce.ctx.Done():
			return
		case <-ticker.C:
			ce.performConsensusRound()
		}
	}
}

// performConsensusRound executes one round of consensus
func (ce *ConsensusEngine) performConsensusRound() {
	ce.mu.Lock()
	defer ce.mu.Unlock()

	// Check if we need to elect a new primary
	if ce.needsNewPrimary() {
		ce.electNewPrimary()
	}

	// Process pending proposals
	for proposalID, proposal := range ce.proposals {
		if ce.canCommitProposal(proposalID) {
			ce.commitProposal(proposal)
			delete(ce.proposals, proposalID)
			delete(ce.votes, proposalID)
		}
	}

	// Clean up old proposals
	ce.cleanupOldProposals()
}

// processProposals handles incoming proposals
func (ce *ConsensusEngine) processProposals() {
	for {
		select {
		case <-ce.ctx.Done():
			return
		case proposal := <-ce.proposalChan:
			ce.handleProposal(proposal)
		}
	}
}

// processVotes handles incoming votes
func (ce *ConsensusEngine) processVotes() {
	for {
		select {
		case <-ce.ctx.Done():
			return
		case vote := <-ce.voteChan:
			ce.handleVote(vote)
		}
	}
}

// processCommits handles incoming commit messages
func (ce *ConsensusEngine) processCommits() {
	for {
		select {
		case <-ce.ctx.Done():
			return
		case commit := <-ce.commitChan:
			ce.handleCommit(commit)
		}
	}
}

// handleProposal processes a received proposal
func (ce *ConsensusEngine) handleProposal(proposal *Proposal) {
	ce.logger.Debug("Received proposal",
		"proposal_id", proposal.ID,
		"proposer", proposal.ProposerID,
		"view", proposal.View,
	)

	// Validate proposal
	if !ce.validateProposal(proposal) {
		ce.logger.Warn("Invalid proposal received", "proposal_id", proposal.ID)
		return
	}

	// Store proposal
	ce.mu.Lock()
	ce.proposals[proposal.ID] = proposal
	if ce.votes[proposal.ID] == nil {
		ce.votes[proposal.ID] = make(map[string]*Vote)
	}
	ce.mu.Unlock()

	// Vote on proposal
	decision := ce.evaluateProposal(proposal)
	vote := &Vote{
		ProposalID: proposal.ID,
		VoterID:    ce.nodeID,
		Decision:   decision,
		Timestamp:  time.Now(),
	}
	vote.Signature = ce.signVote(vote)

	// Broadcast vote
	ce.broadcastVote(vote)

	// Store our own vote
	ce.mu.Lock()
	ce.votes[proposal.ID][ce.nodeID] = vote
	ce.mu.Unlock()
}

// handleVote processes a received vote
func (ce *ConsensusEngine) handleVote(vote *Vote) {
	ce.logger.Debug("Received vote",
		"proposal_id", vote.ProposalID,
		"voter", vote.VoterID,
		"decision", vote.Decision.String(),
	)

	// Validate vote
	if !ce.validateVote(vote) {
		ce.logger.Warn("Invalid vote received", "vote", vote)
		return
	}

	// Store vote
	ce.mu.Lock()
	if ce.votes[vote.ProposalID] == nil {
		ce.votes[vote.ProposalID] = make(map[string]*Vote)
	}
	ce.votes[vote.ProposalID][vote.VoterID] = vote
	ce.mu.Unlock()
}

// handleCommit processes a received commit message
func (ce *ConsensusEngine) handleCommit(commit *CommitMessage) {
	ce.logger.Debug("Received commit",
		"proposal_id", commit.ProposalID,
		"committer", commit.CommitterID,
		"block_hash", commit.BlockHash,
	)

	// Validate commit
	if !ce.validateCommit(commit) {
		ce.logger.Warn("Invalid commit received", "commit", commit)
		return
	}

	// Find corresponding proposal
	ce.mu.RLock()
	proposal, exists := ce.proposals[commit.ProposalID]
	ce.mu.RUnlock()

	if !exists {
		ce.logger.Warn("Commit for unknown proposal", "proposal_id", commit.ProposalID)
		return
	}

	// Apply the committed block
	if err := ce.blockchain.AddBlock(proposal.Block); err != nil {
		ce.logger.Error("Failed to add committed block", logger.FieldError, err)
		return
	}

	ce.logger.Info("Block committed to blockchain",
		"block_hash", proposal.Block.Hash,
		"height", proposal.Block.Height,
	)
}

// canCommitProposal checks if a proposal has enough votes to commit
func (ce *ConsensusEngine) canCommitProposal(proposalID string) bool {
	votes, exists := ce.votes[proposalID]
	if !exists {
		return false
	}

	totalPeers := len(ce.peers) + 1 // +1 for self
	requiredVotes := (totalPeers * 2 / 3) + 1 // Byzantine fault tolerance: 2f+1

	acceptVotes := 0
	for _, vote := range votes {
		if vote.Decision == DecisionAccept {
			acceptVotes++
		}
	}

	return acceptVotes >= requiredVotes
}

// commitProposal commits a proposal that has achieved consensus
func (ce *ConsensusEngine) commitProposal(proposal *Proposal) {
	ce.logger.Info("Committing proposal",
		"proposal_id", proposal.ID,
		"block_hash", proposal.Block.Hash,
	)

	// Add block to blockchain
	if err := ce.blockchain.AddBlock(proposal.Block); err != nil {
		ce.logger.Error("Failed to commit block", logger.FieldError, err)
		return
	}

	// Broadcast commit message
	commit := &CommitMessage{
		ProposalID:  proposal.ID,
		BlockHash:   proposal.Block.Hash,
		CommitterID: ce.nodeID,
		Timestamp:   time.Now(),
	}
	commit.Signature = ce.signCommit(commit)

	ce.broadcastCommit(commit)
}

// Helper methods

func (ce *ConsensusEngine) initializePeers() error {
	// Initialize peer connections from config
	for _, endpoint := range ce.config.Services.Consensus.Endpoints {
		peer, err := NewPeerNode(endpoint, ce.logger)
		if err != nil {
			ce.logger.Warn("Failed to connect to peer", "endpoint", endpoint, logger.FieldError, err)
			continue
		}
		ce.peers[peer.ID] = peer
	}

	ce.logger.Info("Initialized consensus peers", "peer_count", len(ce.peers))
	return nil
}

func (ce *ConsensusEngine) needsNewPrimary() bool {
	// Simple primary election: rotate based on view number
	expectedPrimary := ce.calculatePrimaryNode(ce.currentView)
	return expectedPrimary != ce.nodeID && ce.isPrimary
}

func (ce *ConsensusEngine) electNewPrimary() {
	ce.currentView++
	newPrimary := ce.calculatePrimaryNode(ce.currentView)
	ce.isPrimary = (newPrimary == ce.nodeID)
	
	ce.logger.Info("Primary election completed",
		"new_view", ce.currentView,
		"primary_node", newPrimary,
		"is_primary", ce.isPrimary,
	)
}

func (ce *ConsensusEngine) calculatePrimaryNode(view int64) string {
	// Simple round-robin primary selection
	nodes := []string{ce.nodeID}
	for nodeID := range ce.peers {
		nodes = append(nodes, nodeID)
	}
	
	if len(nodes) == 0 {
		return ce.nodeID
	}
	
	return nodes[view%int64(len(nodes))]
}

func (ce *ConsensusEngine) validateProposal(proposal *Proposal) bool {
	// Basic proposal validation
	if proposal.ID == "" || proposal.ProposerID == "" {
		return false
	}
	
	if proposal.Block == nil {
		return false
	}
	
	// Validate block
	return ce.blockchain.ValidateBlock(proposal.Block)
}

func (ce *ConsensusEngine) validateVote(vote *Vote) bool {
	// Basic vote validation
	return vote.ProposalID != "" && vote.VoterID != ""
}

func (ce *ConsensusEngine) validateCommit(commit *CommitMessage) bool {
	// Basic commit validation
	return commit.ProposalID != "" && commit.CommitterID != "" && commit.BlockHash != ""
}

func (ce *ConsensusEngine) evaluateProposal(proposal *Proposal) Decision {
	// Evaluate proposal based on state validation
	if err := ce.validator.ValidateState(proposal.Block.State); err != nil {
		ce.logger.Debug("Rejecting proposal due to invalid state", logger.FieldError, err)
		return DecisionReject
	}
	
	// Additional validation logic can be added here
	return DecisionAccept
}

func (ce *ConsensusEngine) cleanupOldProposals() {
	// Remove proposals older than 1 hour
	cutoff := time.Now().Add(-1 * time.Hour)
	
	for proposalID, proposal := range ce.proposals {
		if proposal.Timestamp.Before(cutoff) {
			delete(ce.proposals, proposalID)
			delete(ce.votes, proposalID)
		}
	}
}

func (ce *ConsensusEngine) generateProposalID(block *Block) string {
	data := fmt.Sprintf("%s:%s:%d", ce.nodeID, block.Hash, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:8])
}

// Simplified signing methods (in production, use proper cryptographic signatures)
func (ce *ConsensusEngine) signProposal(proposal *Proposal) string {
	data, _ := json.Marshal(proposal)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:16])
}

func (ce *ConsensusEngine) signVote(vote *Vote) string {
	data, _ := json.Marshal(vote)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:16])
}

func (ce *ConsensusEngine) signCommit(commit *CommitMessage) string {
	data, _ := json.Marshal(commit)
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:16])
}

// Broadcasting methods (simplified - in production, use proper network layer)
func (ce *ConsensusEngine) broadcastProposal(proposal *Proposal) {
	for _, peer := range ce.peers {
		go peer.SendProposal(proposal)
	}
}

func (ce *ConsensusEngine) broadcastVote(vote *Vote) {
	for _, peer := range ce.peers {
		go peer.SendVote(vote)
	}
}

func (ce *ConsensusEngine) broadcastCommit(commit *CommitMessage) {
	for _, peer := range ce.peers {
		go peer.SendCommit(commit)
	}
}

func (ce *ConsensusEngine) synchronizeBlockchain() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ce.ctx.Done():
			return
		case <-ticker.C:
			ce.syncWithPeers()
		}
	}
}

func (ce *ConsensusEngine) syncWithPeers() {
	// Simplified blockchain sync
	for _, peer := range ce.peers {
		go func(p *PeerNode) {
			peerHeight, err := p.GetBlockchainHeight()
			if err != nil {
				ce.logger.Debug("Failed to get peer blockchain height", logger.FieldError, err)
				return
			}
			
			if peerHeight > ce.blockchain.GetHeight() {
				ce.logger.Info("Syncing blockchain with peer",
					"peer", p.ID,
					"peer_height", peerHeight,
					"local_height", ce.blockchain.GetHeight(),
				)
				// In production, implement proper blockchain sync
			}
		}(peer)
	}
}

// GetState returns the current consensus state
func (ce *ConsensusEngine) GetState() *ConsensusState {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	
	return &ConsensusState{
		View:         ce.currentView,
		BlockHeight:  ce.blockchain.GetHeight(),
		PrimaryNode:  ce.calculatePrimaryNode(ce.currentView),
		ActivePeers:  len(ce.peers),
		LastConsensus: ce.blockchain.GetLastBlockTime(),
		Status:       ce.getConsensusStatus(),
	}
}

func (ce *ConsensusEngine) getConsensusStatus() string {
	if !ce.running {
		return "stopped"
	}
	if ce.isPrimary {
		return "primary"
	}
	return "follower"
}

// IsHealthy returns whether the consensus engine is healthy
func (ce *ConsensusEngine) IsHealthy() bool {
	ce.mu.RLock()
	defer ce.mu.RUnlock()
	
	if !ce.running {
		return false
	}
	
	// Check if we have enough peers for Byzantine fault tolerance
	totalNodes := len(ce.peers) + 1
	minNodes := 4 // Minimum for BFT: 3f+1 where f=1
	
	return totalNodes >= minNodes
}

// GetStatus returns detailed status information
func (ce *ConsensusEngine) GetStatus() interface{} {
	state := ce.GetState()
	
	return map[string]interface{}{
		"consensus_state":   state,
		"blockchain_height": ce.blockchain.GetHeight(),
		"pending_proposals": len(ce.proposals),
		"active_peers":      len(ce.peers),
		"is_healthy":        ce.IsHealthy(),
	}
}
