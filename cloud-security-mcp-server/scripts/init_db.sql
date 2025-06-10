-- Cloud Security MCP Server Database Schema
-- PostgreSQL database initialization script

-- Create database and user if running as superuser
-- This section will be skipped if user doesn't have sufficient privileges

DO $$ 
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'postgres' AND rolsuper = true) THEN
        -- Create user for the application
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cloud_security_user') THEN
            CREATE USER cloud_security_user WITH PASSWORD 'secure_password_change_me';
        END IF;
        
        -- Grant necessary privileges
        GRANT CONNECT ON DATABASE cloud_security TO cloud_security_user;
        GRANT USAGE ON SCHEMA public TO cloud_security_user;
        GRANT CREATE ON SCHEMA public TO cloud_security_user;
    END IF;
END $$;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "hstore";

-- Create custom types
CREATE TYPE severity_level AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
CREATE TYPE cloud_provider AS ENUM ('aws', 'azure', 'gcp', 'kubernetes', 'multi');
CREATE TYPE compliance_status AS ENUM ('compliant', 'non_compliant', 'partially_compliant', 'not_applicable');

-- Organizations table
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Cloud accounts table
CREATE TABLE cloud_accounts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    provider cloud_provider NOT NULL,
    account_id VARCHAR(255) NOT NULL,
    region VARCHAR(100),
    credentials_encrypted TEXT, -- Encrypted credentials
    settings JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT true,
    last_scan_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(provider, account_id, region)
);

-- Security scans table
CREATE TABLE security_scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    cloud_account_id UUID REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    scan_type VARCHAR(100) NOT NULL,
    tool_name VARCHAR(100) NOT NULL,
    tool_version VARCHAR(50),
    status scan_status DEFAULT 'pending',
    target VARCHAR(255),
    configuration JSONB DEFAULT '{}',
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    duration_seconds INTEGER,
    error_message TEXT,
    raw_output TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Security findings table
CREATE TABLE security_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id UUID REFERENCES security_scans(id) ON DELETE CASCADE,
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    cloud_account_id UUID REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    
    -- Finding identification
    finding_id VARCHAR(255) NOT NULL, -- Tool-specific finding ID
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity severity_level NOT NULL,
    
    -- Resource information
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    resource_arn TEXT,
    resource_region VARCHAR(100),
    resource_tags JSONB DEFAULT '{}',
    
    -- Finding details
    check_id VARCHAR(255),
    check_name VARCHAR(255),
    category VARCHAR(100),
    remediation TEXT,
    evidence JSONB DEFAULT '{}',
    references TEXT[],
    
    -- Compliance mapping
    compliance_frameworks JSONB DEFAULT '{}',
    
    -- Status tracking
    status VARCHAR(50) DEFAULT 'open', -- open, resolved, false_positive, risk_accepted
    first_detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    resolved_at TIMESTAMP WITH TIME ZONE,
    resolution_comment TEXT,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Constraints
    UNIQUE(scan_id, finding_id)
);

-- Compliance assessments table
CREATE TABLE compliance_assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    cloud_account_id UUID REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    
    -- Assessment details
    framework VARCHAR(100) NOT NULL,
    framework_version VARCHAR(50),
    assessment_date DATE NOT NULL,
    assessor VARCHAR(255),
    
    -- Scores and status
    overall_score DECIMAL(5,2),
    compliance_percentage DECIMAL(5,2),
    status compliance_status,
    
    -- Control results
    total_controls INTEGER DEFAULT 0,
    passed_controls INTEGER DEFAULT 0,
    failed_controls INTEGER DEFAULT 0,
    not_applicable_controls INTEGER DEFAULT 0,
    
    -- Assessment metadata
    scope_description TEXT,
    limitations TEXT,
    methodology TEXT,
    evidence_links TEXT[],
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(cloud_account_id, framework, assessment_date)
);

-- Compliance control results table
CREATE TABLE compliance_control_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID REFERENCES compliance_assessments(id) ON DELETE CASCADE,
    
    -- Control identification
    control_id VARCHAR(255) NOT NULL,
    control_title VARCHAR(500),
    control_description TEXT,
    control_category VARCHAR(255),
    
    -- Implementation details
    implementation_status compliance_status NOT NULL,
    implementation_description TEXT,
    evidence_description TEXT,
    evidence_links TEXT[],
    
    -- Testing information
    testing_procedure TEXT,
    testing_results TEXT,
    testing_frequency VARCHAR(100),
    last_tested_date DATE,
    
    -- Risk and remediation
    risk_rating severity_level,
    remediation_plan TEXT,
    remediation_timeline DATE,
    responsible_party VARCHAR(255),
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(assessment_id, control_id)
);

-- Security metrics table
CREATE TABLE security_metrics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    cloud_account_id UUID REFERENCES cloud_accounts(id),
    
    -- Metric identification
    metric_name VARCHAR(255) NOT NULL,
    metric_category VARCHAR(100),
    metric_value DECIMAL(10,4),
    metric_unit VARCHAR(50),
    
    -- Time and context
    measurement_time TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    time_period VARCHAR(50), -- e.g., 'daily', 'weekly', 'monthly'
    
    -- Dimensions and tags
    dimensions JSONB DEFAULT '{}',
    tags JSONB DEFAULT '{}',
    
    -- Metadata
    source VARCHAR(100),
    calculation_method TEXT,
    metadata JSONB DEFAULT '{}',
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Index for time-series queries
    UNIQUE(organization_id, cloud_account_id, metric_name, measurement_time)
);

-- Audit log table
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Event details
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(100),
    event_description TEXT,
    
    -- Actor information
    user_id VARCHAR(255),
    user_email VARCHAR(255),
    source_ip INET,
    user_agent TEXT,
    
    -- Resource information
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    
    -- Event data
    event_data JSONB DEFAULT '{}',
    
    -- Timestamp
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Session tracking
    session_id VARCHAR(255),
    request_id VARCHAR(255)
);

-- Configuration table
CREATE TABLE configurations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Configuration details
    config_key VARCHAR(255) NOT NULL,
    config_value JSONB,
    config_type VARCHAR(100), -- 'global', 'organization', 'account'
    
    -- Validation and constraints
    is_encrypted BOOLEAN DEFAULT false,
    is_sensitive BOOLEAN DEFAULT false,
    validation_schema JSONB,
    
    -- Metadata
    description TEXT,
    created_by VARCHAR(255),
    updated_by VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    UNIQUE(organization_id, config_key)
);

-- Scan schedules table
CREATE TABLE scan_schedules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    cloud_account_id UUID REFERENCES cloud_accounts(id) ON DELETE CASCADE,
    
    -- Schedule details
    name VARCHAR(255) NOT NULL,
    description TEXT,
    scan_type VARCHAR(100) NOT NULL,
    tool_name VARCHAR(100) NOT NULL,
    
    -- Schedule configuration
    cron_expression VARCHAR(100) NOT NULL,
    timezone VARCHAR(100) DEFAULT 'UTC',
    is_active BOOLEAN DEFAULT true,
    
    -- Scan configuration
    scan_configuration JSONB DEFAULT '{}',
    
    -- Execution tracking
    last_execution_at TIMESTAMP WITH TIME ZONE,
    next_execution_at TIMESTAMP WITH TIME ZONE,
    execution_count INTEGER DEFAULT 0,
    failure_count INTEGER DEFAULT 0,
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Notification rules table
CREATE TABLE notification_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    
    -- Rule details
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT true,
    
    -- Trigger conditions
    trigger_events TEXT[] NOT NULL, -- Array of event types
    severity_filter severity_level[],
    compliance_frameworks TEXT[],
    cloud_providers cloud_provider[],
    
    -- Filtering conditions
    conditions JSONB DEFAULT '{}', -- Additional filtering logic
    
    -- Notification settings
    notification_channels JSONB NOT NULL, -- Channel configurations
    message_template TEXT,
    
    -- Rate limiting
    rate_limit_minutes INTEGER DEFAULT 60,
    last_notification_at TIMESTAMP WITH TIME ZONE,
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_security_scans_org_account ON security_scans(organization_id, cloud_account_id);
CREATE INDEX idx_security_scans_status ON security_scans(status);
CREATE INDEX idx_security_scans_created_at ON security_scans(created_at);

CREATE INDEX idx_security_findings_scan_id ON security_findings(scan_id);
CREATE INDEX idx_security_findings_severity ON security_findings(severity);
CREATE INDEX idx_security_findings_status ON security_findings(status);
CREATE INDEX idx_security_findings_org_account ON security_findings(organization_id, cloud_account_id);
CREATE INDEX idx_security_findings_resource ON security_findings(resource_type, resource_id);
CREATE INDEX idx_security_findings_detected_at ON security_findings(first_detected_at);

CREATE INDEX idx_compliance_assessments_org_account ON compliance_assessments(organization_id, cloud_account_id);
CREATE INDEX idx_compliance_assessments_framework ON compliance_assessments(framework);
CREATE INDEX idx_compliance_assessments_date ON compliance_assessments(assessment_date);

CREATE INDEX idx_security_metrics_org_account ON security_metrics(organization_id, cloud_account_id);
CREATE INDEX idx_security_metrics_name_time ON security_metrics(metric_name, measurement_time);
CREATE INDEX idx_security_metrics_time ON security_metrics(measurement_time);

CREATE INDEX idx_audit_logs_org ON audit_logs(organization_id);
CREATE INDEX idx_audit_logs_event_type ON audit_logs(event_type);
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);

-- Create triggers for updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_organizations_updated_at BEFORE UPDATE ON organizations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_cloud_accounts_updated_at BEFORE UPDATE ON cloud_accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_security_scans_updated_at BEFORE UPDATE ON security_scans
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_security_findings_updated_at BEFORE UPDATE ON security_findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_compliance_assessments_updated_at BEFORE UPDATE ON compliance_assessments
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_compliance_control_results_updated_at BEFORE UPDATE ON compliance_control_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_configurations_updated_at BEFORE UPDATE ON configurations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_scan_schedules_updated_at BEFORE UPDATE ON scan_schedules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notification_rules_updated_at BEFORE UPDATE ON notification_rules
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Create views for common queries
CREATE VIEW findings_summary AS
SELECT 
    organization_id,
    cloud_account_id,
    severity,
    status,
    COUNT(*) as finding_count,
    MIN(first_detected_at) as earliest_detection,
    MAX(last_detected_at) as latest_detection
FROM security_findings
GROUP BY organization_id, cloud_account_id, severity, status;

CREATE VIEW compliance_summary AS
SELECT 
    ca.organization_id,
    ca.cloud_account_id,
    ca.framework,
    ca.compliance_percentage,
    ca.status,
    ca.assessment_date,
    COUNT(ccr.id) as total_controls,
    COUNT(CASE WHEN ccr.implementation_status = 'compliant' THEN 1 END) as compliant_controls,
    COUNT(CASE WHEN ccr.implementation_status = 'non_compliant' THEN 1 END) as non_compliant_controls
FROM compliance_assessments ca
LEFT JOIN compliance_control_results ccr ON ca.id = ccr.assessment_id
GROUP BY ca.id, ca.organization_id, ca.cloud_account_id, ca.framework, 
         ca.compliance_percentage, ca.status, ca.assessment_date;

CREATE VIEW scan_performance AS
SELECT 
    tool_name,
    scan_type,
    COUNT(*) as total_scans,
    COUNT(CASE WHEN status = 'completed' THEN 1 END) as successful_scans,
    COUNT(CASE WHEN status = 'failed' THEN 1 END) as failed_scans,
    AVG(duration_seconds) as avg_duration_seconds,
    MAX(completed_at) as last_scan_time
FROM security_scans
WHERE started_at >= NOW() - INTERVAL '30 days'
GROUP BY tool_name, scan_type;

-- Grant permissions to application user
DO $$ 
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cloud_security_user') THEN
        -- Grant table permissions
        GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO cloud_security_user;
        GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO cloud_security_user;
        
        -- Grant view permissions
        GRANT SELECT ON findings_summary TO cloud_security_user;
        GRANT SELECT ON compliance_summary TO cloud_security_user;
        GRANT SELECT ON scan_performance TO cloud_security_user;
        
        -- Grant default privileges for future objects
        ALTER DEFAULT PRIVILEGES IN SCHEMA public 
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO cloud_security_user;
        
        ALTER DEFAULT PRIVILEGES IN SCHEMA public 
        GRANT USAGE, SELECT ON SEQUENCES TO cloud_security_user;
    END IF;
END $$;

-- Insert default organization for single-tenant deployments
INSERT INTO organizations (id, name, description, settings) 
VALUES (
    '00000000-0000-0000-0000-000000000000'::UUID,
    'Default Organization',
    'Default organization for single-tenant deployments',
    '{"tenant_type": "single", "created_by": "system"}'
) ON CONFLICT (id) DO NOTHING;

-- Create default configuration entries
INSERT INTO configurations (organization_id, config_key, config_value, config_type, description) VALUES
('00000000-0000-0000-0000-000000000000'::UUID, 'scan_retention_days', '90', 'global', 'Number of days to retain scan results'),
('00000000-0000-0000-0000-000000000000'::UUID, 'max_concurrent_scans', '5', 'global', 'Maximum number of concurrent scans'),
('00000000-0000-0000-0000-000000000000'::UUID, 'default_compliance_frameworks', '["cis", "nist"]', 'global', 'Default compliance frameworks to check'),
('00000000-0000-0000-0000-000000000000'::UUID, 'notification_enabled', 'true', 'global', 'Enable notifications'),
('00000000-0000-0000-0000-000000000000'::UUID, 'metrics_retention_days', '365', 'global', 'Number of days to retain metrics data')
ON CONFLICT (organization_id, config_key) DO NOTHING;

-- Performance optimization settings
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET log_statement = 'all';
ALTER SYSTEM SET log_min_duration_statement = 1000;

-- Create materialized view for dashboard metrics (refresh periodically)
CREATE MATERIALIZED VIEW dashboard_metrics AS
SELECT 
    'findings_by_severity' as metric_type,
    severity::text as dimension,
    COUNT(*)::numeric as value,
    NOW() as last_updated
FROM security_findings
WHERE first_detected_at >= NOW() - INTERVAL '30 days'
GROUP BY severity

UNION ALL

SELECT 
    'findings_by_provider' as metric_type,
    ca.provider::text as dimension,
    COUNT(sf.id)::numeric as value,
    NOW() as last_updated
FROM security_findings sf
JOIN cloud_accounts ca ON sf.cloud_account_id = ca.id
WHERE sf.first_detected_at >= NOW() - INTERVAL '30 days'
GROUP BY ca.provider

UNION ALL

SELECT 
    'scans_by_status' as metric_type,
    status::text as dimension,
    COUNT(*)::numeric as value,
    NOW() as last_updated
FROM security_scans
WHERE started_at >= NOW() - INTERVAL '7 days'
GROUP BY status;

-- Create index on materialized view
CREATE INDEX idx_dashboard_metrics_type_dimension ON dashboard_metrics(metric_type, dimension);

-- Set up automatic refresh of materialized view (requires pg_cron extension)
-- SELECT cron.schedule('refresh-dashboard-metrics', '*/15 * * * *', 'REFRESH MATERIALIZED VIEW dashboard_metrics;');

COMMIT;
