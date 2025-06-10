-- DSN Database Initialization Script
-- This script sets up the initial database schema for the DSN project

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create schemas
CREATE SCHEMA IF NOT EXISTS dsn_core;
CREATE SCHEMA IF NOT EXISTS dsn_metrics;
CREATE SCHEMA IF NOT EXISTS dsn_audit;

-- Set search path
SET search_path TO dsn_core, public;

-- Create sentinel nodes table
CREATE TABLE IF NOT EXISTS dsn_core.sentinel_nodes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sentinel_id VARCHAR(255) UNIQUE NOT NULL,
    region VARCHAR(100) NOT NULL,
    zone VARCHAR(100) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    last_heartbeat TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    version VARCHAR(50),
    capabilities JSONB,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create threat detections table
CREATE TABLE IF NOT EXISTS dsn_core.threat_detections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sentinel_id VARCHAR(255) NOT NULL,
    threat_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    confidence_score DECIMAL(3,2) NOT NULL,
    source_ip INET,
    target_ip INET,
    description TEXT,
    raw_data JSONB,
    status VARCHAR(50) NOT NULL DEFAULT 'detected',
    resolved_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    FOREIGN KEY (sentinel_id) REFERENCES dsn_core.sentinel_nodes(sentinel_id)
);

-- Create security events table
CREATE TABLE IF NOT EXISTS dsn_core.security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(100) NOT NULL,
    source VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    message TEXT NOT NULL,
    details JSONB,
    tags TEXT[],
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create consensus votes table
CREATE TABLE IF NOT EXISTS dsn_core.consensus_votes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    proposal_id UUID NOT NULL,
    voter_id VARCHAR(255) NOT NULL,
    vote VARCHAR(20) NOT NULL CHECK (vote IN ('approve', 'reject', 'abstain')),
    signature TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(proposal_id, voter_id)
);

-- Create metrics tables in dsn_metrics schema
CREATE TABLE IF NOT EXISTS dsn_metrics.system_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    sentinel_id VARCHAR(255) NOT NULL,
    metric_name VARCHAR(100) NOT NULL,
    metric_value DECIMAL(15,6) NOT NULL,
    labels JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    FOREIGN KEY (sentinel_id) REFERENCES dsn_core.sentinel_nodes(sentinel_id)
);

-- Create audit log table in dsn_audit schema
CREATE TABLE IF NOT EXISTS dsn_audit.audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id VARCHAR(255),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255),
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_sentinel_nodes_status ON dsn_core.sentinel_nodes(status);
CREATE INDEX IF NOT EXISTS idx_sentinel_nodes_region ON dsn_core.sentinel_nodes(region);
CREATE INDEX IF NOT EXISTS idx_threat_detections_sentinel_id ON dsn_core.threat_detections(sentinel_id);
CREATE INDEX IF NOT EXISTS idx_threat_detections_created_at ON dsn_core.threat_detections(created_at);
CREATE INDEX IF NOT EXISTS idx_threat_detections_severity ON dsn_core.threat_detections(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON dsn_core.security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON dsn_core.security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_consensus_votes_proposal_id ON dsn_core.consensus_votes(proposal_id);
CREATE INDEX IF NOT EXISTS idx_system_metrics_sentinel_id ON dsn_metrics.system_metrics(sentinel_id);
CREATE INDEX IF NOT EXISTS idx_system_metrics_timestamp ON dsn_metrics.system_metrics(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON dsn_audit.audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON dsn_audit.audit_log(user_id);

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
CREATE TRIGGER update_sentinel_nodes_updated_at 
    BEFORE UPDATE ON dsn_core.sentinel_nodes 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert sample data for development
INSERT INTO dsn_core.sentinel_nodes (sentinel_id, region, zone, version, capabilities) VALUES
('sentinel-dev-001', 'us-west-2', 'us-west-2a', '1.0.0', '{"threat_detection": true, "anomaly_detection": true}'),
('sentinel-dev-002', 'us-east-1', 'us-east-1b', '1.0.0', '{"threat_detection": true, "behavior_analysis": true}'),
('sentinel-dev-003', 'eu-west-1', 'eu-west-1c', '1.0.0', '{"threat_detection": true, "signature_scanning": true}')
ON CONFLICT (sentinel_id) DO NOTHING;

-- Grant permissions
GRANT USAGE ON SCHEMA dsn_core TO dsn_user;
GRANT USAGE ON SCHEMA dsn_metrics TO dsn_user;
GRANT USAGE ON SCHEMA dsn_audit TO dsn_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA dsn_core TO dsn_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA dsn_metrics TO dsn_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA dsn_audit TO dsn_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA dsn_core TO dsn_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA dsn_metrics TO dsn_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA dsn_audit TO dsn_user;

-- Create views for common queries
CREATE OR REPLACE VIEW dsn_core.active_sentinels AS
SELECT 
    sentinel_id,
    region,
    zone,
    status,
    last_heartbeat,
    version,
    capabilities
FROM dsn_core.sentinel_nodes 
WHERE status = 'active' 
AND last_heartbeat > NOW() - INTERVAL '5 minutes';

CREATE OR REPLACE VIEW dsn_core.recent_threats AS
SELECT 
    t.id,
    t.sentinel_id,
    t.threat_type,
    t.severity,
    t.confidence_score,
    t.description,
    t.created_at,
    s.region,
    s.zone
FROM dsn_core.threat_detections t
JOIN dsn_core.sentinel_nodes s ON t.sentinel_id = s.sentinel_id
WHERE t.created_at > NOW() - INTERVAL '24 hours'
ORDER BY t.created_at DESC;

-- Grant permissions on views
GRANT SELECT ON dsn_core.active_sentinels TO dsn_user;
GRANT SELECT ON dsn_core.recent_threats TO dsn_user;

COMMIT;