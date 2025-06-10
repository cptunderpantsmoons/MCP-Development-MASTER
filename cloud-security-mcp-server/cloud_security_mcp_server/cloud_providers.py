#!/usr/bin/env python3
"""
Cloud Provider Integrations
Direct integrations with AWS, Azure, and GCP security APIs
"""

import boto3
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import asyncio
import aiohttp
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.security import SecurityCenter
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.network import NetworkManagementClient
from google.cloud import securitycenter
from google.cloud import asset_v1
from google.cloud import compute_v1
import json

logger = logging.getLogger(__name__)

class AWSSecurityIntegration:
    """AWS Security services integration"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = None
        self._initialize_session()
    
    def _initialize_session(self):
        """Initialize AWS session with credentials"""
        try:
            if self.config.get("aws_profile"):
                self.session = boto3.Session(profile_name=self.config["aws_profile"])
            elif self.config.get("aws_access_key_id"):
                self.session = boto3.Session(
                    aws_access_key_id=self.config["aws_access_key_id"],
                    aws_secret_access_key=self.config["aws_secret_access_key"],
                    aws_session_token=self.config.get("aws_session_token"),
                    region_name=self.config.get("aws_region", "us-east-1")
                )
            else:
                # Use default credential chain
                self.session = boto3.Session(region_name=self.config.get("aws_region", "us-east-1"))
        except Exception as e:
            logger.error(f"Failed to initialize AWS session: {e}")
    
    async def get_security_hub_findings(self, severity_filter: List[str] = None) -> List[Dict[str, Any]]:
        """Get findings from AWS Security Hub"""
        if not self.session:
            raise RuntimeError("AWS session not initialized")
        
        security_hub = self.session.client('securityhub')
        findings = []
        
        try:
            # Build filters
            filters = {}
            if severity_filter:
                filters['SeverityLabel'] = [{'Value': sev.upper(), 'Comparison': 'EQUALS'} for sev in severity_filter]
            
            # Get findings
            paginator = security_hub.get_paginator('get_findings')
            
            for page in paginator.paginate(Filters=filters):
                for finding in page['Findings']:
                    findings.append({
                        "id": finding.get("Id", ""),
                        "title": finding.get("Title", ""),
                        "description": finding.get("Description", ""),
                        "severity": finding.get("Severity", {}).get("Label", "").lower(),
                        "compliance_status": finding.get("Compliance", {}).get("Status", ""),
                        "resource_id": finding.get("Resources", [{}])[0].get("Id", ""),
                        "resource_type": finding.get("Resources", [{}])[0].get("Type", ""),
                        "region": finding.get("Resources", [{}])[0].get("Region", ""),
                        "remediation": finding.get("Remediation", {}).get("Recommendation", {}).get("Text", ""),
                        "first_observed": finding.get("FirstObservedAt", ""),
                        "last_observed": finding.get("LastObservedAt", ""),
                        "workflow_state": finding.get("WorkflowState", ""),
                        "source_url": finding.get("SourceUrl", "")
                    })
            
        except Exception as e:
            logger.error(f"Error getting Security Hub findings: {e}")
            raise
        
        return findings
    
    async def get_config_compliance_summary(self) -> Dict[str, Any]:
        """Get AWS Config compliance summary"""
        if not self.session:
            raise RuntimeError("AWS session not initialized")
        
        config_client = self.session.client('config')
        
        try:
            # Get compliance summary
            response = config_client.get_compliance_summary_by_config_rule()
            summary = response.get('ComplianceSummary', {})
            
            # Get detailed compliance by rules
            rules_response = config_client.describe_compliance_by_config_rule()
            rules_compliance = []
            
            for rule in rules_response.get('ComplianceByConfigRules', []):
                rules_compliance.append({
                    "rule_name": rule.get('ConfigRuleName', ''),
                    "compliance_type": rule.get('Compliance', {}).get('ComplianceType', ''),
                    "compliance_contributor_count": rule.get('Compliance', {}).get('ComplianceContributorCount', {})
                })
            
            return {
                "summary": {
                    "compliant_rule_count": summary.get('ComplianceByConfigRule', {}).get('CompliantRuleCount', 0),
                    "non_compliant_rule_count": summary.get('ComplianceByConfigRule', {}).get('NonCompliantRuleCount', 0),
                    "total_rule_count": summary.get('ComplianceByConfigRule', {}).get('TotalRuleCount', 0)
                },
                "rules_compliance": rules_compliance,
                "last_updated": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting Config compliance: {e}")
            raise
    
    async def get_cloudtrail_insights(self, hours_back: int = 24) -> List[Dict[str, Any]]:
        """Get CloudTrail insights for security events"""
        if not self.session:
            raise RuntimeError("AWS session not initialized")
        
        cloudtrail = self.session.client('cloudtrail')
        insights = []
        
        try:
            start_time = datetime.now() - timedelta(hours=hours_back)
            
            # Look up security-related events
            security_events = [
                'AssumeRole', 'CreateRole', 'DeleteRole', 'AttachRolePolicy',
                'DetachRolePolicy', 'CreateUser', 'DeleteUser', 'CreateAccessKey',
                'DeleteAccessKey', 'CreateBucket', 'DeleteBucket', 'PutBucketPolicy'
            ]
            
            for event_name in security_events:
                response = cloudtrail.lookup_events(
                    LookupAttributes=[
                        {
                            'AttributeKey': 'EventName',
                            'AttributeValue': event_name
                        }
                    ],
                    StartTime=start_time,
                    MaxItems=50
                )
                
                for event in response.get('Events', []):
                    insights.append({
                        "event_name": event.get('EventName', ''),
                        "event_time": event.get('EventTime', '').isoformat() if event.get('EventTime') else '',
                        "username": event.get('Username', ''),
                        "source_ip": event.get('SourceIPAddress', ''),
                        "user_agent": event.get('UserAgent', ''),
                        "aws_region": event.get('AwsRegion', ''),
                        "resources": event.get('Resources', []),
                        "event_id": event.get('EventId', ''),
                        "cloud_trail_event": json.loads(event.get('CloudTrailEvent', '{}'))
                    })
            
        except Exception as e:
            logger.error(f"Error getting CloudTrail insights: {e}")
            raise
        
        return insights
    
    async def analyze_iam_security(self) -> Dict[str, Any]:
        """Analyze IAM security posture"""
        if not self.session:
            raise RuntimeError("AWS session not initialized")
        
        iam = self.session.client('iam')
        analysis = {
            "users": [],
            "roles": [],
            "policies": [],
            "security_issues": []
        }
        
        try:
            # Analyze users
            users_response = iam.list_users()
            for user in users_response.get('Users', []):
                user_name = user['UserName']
                
                # Check for access keys
                keys_response = iam.list_access_keys(UserName=user_name)
                access_keys = keys_response.get('AccessKeyMetadata', [])
                
                # Check for MFA
                mfa_devices = iam.list_mfa_devices(UserName=user_name)
                has_mfa = len(mfa_devices.get('MFADevices', [])) > 0
                
                # Check for console access
                try:
                    login_profile = iam.get_login_profile(UserName=user_name)
                    has_console_access = True
                except iam.exceptions.NoSuchEntityException:
                    has_console_access = False
                
                user_analysis = {
                    "username": user_name,
                    "creation_date": user.get('CreateDate', '').isoformat() if user.get('CreateDate') else '',
                    "last_used": user.get('PasswordLastUsed', '').isoformat() if user.get('PasswordLastUsed') else '',
                    "access_keys_count": len(access_keys),
                    "has_mfa": has_mfa,
                    "has_console_access": has_console_access,
                    "security_score": self._calculate_user_security_score(access_keys, has_mfa, has_console_access)
                }
                
                analysis["users"].append(user_analysis)
                
                # Flag security issues
                if not has_mfa and has_console_access:
                    analysis["security_issues"].append({
                        "type": "no_mfa",
                        "severity": "high",
                        "resource": user_name,
                        "description": "User has console access but no MFA enabled"
                    })
                
                # Check for old access keys
                for key in access_keys:
                    key_age = datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']
                    if key_age.days > 90:
                        analysis["security_issues"].append({
                            "type": "old_access_key",
                            "severity": "medium",
                            "resource": f"{user_name}:{key['AccessKeyId']}",
                            "description": f"Access key is {key_age.days} days old"
                        })
            
            # Analyze roles
            roles_response = iam.list_roles()
            for role in roles_response.get('Roles', []):
                role_analysis = {
                    "role_name": role['RoleName'],
                    "creation_date": role.get('CreateDate', '').isoformat() if role.get('CreateDate') else '',
                    "assume_role_policy": role.get('AssumeRolePolicyDocument', ''),
                    "max_session_duration": role.get('MaxSessionDuration', 3600)
                }
                analysis["roles"].append(role_analysis)
            
        except Exception as e:
            logger.error(f"Error analyzing IAM security: {e}")
            raise
        
        return analysis
    
    def _calculate_user_security_score(self, access_keys: List[Dict], has_mfa: bool, has_console_access: bool) -> int:
        """Calculate security score for IAM user"""
        score = 100
        
        if has_console_access and not has_mfa:
            score -= 30
        
        if len(access_keys) > 1:
            score -= 20
        
        # Check key age
        for key in access_keys:
            key_age = datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']
            if key_age.days > 90:
                score -= 15
            elif key_age.days > 180:
                score -= 25
        
        return max(score, 0)

class AzureSecurityIntegration:
    """Azure Security Center integration"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.credential = None
        self.subscription_id = config.get("azure_subscription_id")
        self._initialize_credential()
    
    def _initialize_credential(self):
        """Initialize Azure credentials"""
        try:
            if self.config.get("azure_client_id") and self.config.get("azure_client_secret"):
                self.credential = ClientSecretCredential(
                    tenant_id=self.config["azure_tenant_id"],
                    client_id=self.config["azure_client_id"],
                    client_secret=self.config["azure_client_secret"]
                )
            else:
                self.credential = DefaultAzureCredential()
        except Exception as e:
            logger.error(f"Failed to initialize Azure credentials: {e}")
    
    async def get_security_center_alerts(self, severity_filter: List[str] = None) -> List[Dict[str, Any]]:
        """Get alerts from Azure Security Center"""
        if not self.credential or not self.subscription_id:
            raise RuntimeError("Azure credentials not properly configured")
        
        security_client = SecurityCenter(self.credential, self.subscription_id)
        alerts = []
        
        try:
            # Get security alerts
            alerts_list = security_client.alerts.list()
            
            for alert in alerts_list:
                alert_severity = alert.severity.lower() if alert.severity else "medium"
                
                if severity_filter and alert_severity not in [s.lower() for s in severity_filter]:
                    continue
                
                alerts.append({
                    "id": alert.id,
                    "name": alert.name,
                    "type": alert.type,
                    "severity": alert_severity,
                    "status": alert.status,
                    "description": alert.description,
                    "compromised_entity": alert.compromised_entity,
                    "remediation_steps": alert.remediation_steps,
                    "start_time": alert.start_time_utc.isoformat() if alert.start_time_utc else '',
                    "end_time": alert.end_time_utc.isoformat() if alert.end_time_utc else '',
                    "resource_identifiers": [ri.azure_resource_id for ri in alert.resource_identifiers] if alert.resource_identifiers else [],
                    "entities": [entity.type for entity in alert.entities] if alert.entities else []
                })
                
        except Exception as e:
            logger.error(f"Error getting Azure Security Center alerts: {e}")
            raise
        
        return alerts
    
    async def get_security_assessments(self) -> List[Dict[str, Any]]:
        """Get security assessments from Azure Security Center"""
        if not self.credential or not self.subscription_id:
            raise RuntimeError("Azure credentials not properly configured")
        
        security_client = SecurityCenter(self.credential, self.subscription_id)
        assessments = []
        
        try:
            # Get security assessments
            assessments_list = security_client.assessments.list(scope=f'/subscriptions/{self.subscription_id}')
            
            for assessment in assessments_list:
                assessments.append({
                    "id": assessment.id,
                    "name": assessment.name,
                    "type": assessment.type,
                    "status": assessment.status.code if assessment.status else '',
                    "display_name": assessment.display_name,
                    "description": assessment.description,
                    "remediation_description": assessment.remediation_description,
                    "severity": assessment.severity,
                    "assessment_type": assessment.assessment_type,
                    "user_impact": assessment.user_impact,
                    "implementation_effort": assessment.implementation_effort
                })
                
        except Exception as e:
            logger.error(f"Error getting Azure security assessments: {e}")
            raise
        
        return assessments
    
    async def analyze_network_security_groups(self) -> List[Dict[str, Any]]:
        """Analyze Network Security Groups for security issues"""
        if not self.credential or not self.subscription_id:
            raise RuntimeError("Azure credentials not properly configured")
        
        network_client = NetworkManagementClient(self.credential, self.subscription_id)
        nsg_analysis = []
        
        try:
            # Get all NSGs
            nsgs = network_client.network_security_groups.list_all()
            
            for nsg in nsgs:
                nsg_issues = []
                
                # Analyze security rules
                for rule in nsg.security_rules:
                    # Check for overly permissive rules
                    if rule.access == 'Allow' and rule.direction == 'Inbound':
                        if rule.source_address_prefix == '*' and rule.destination_port_range == '*':
                            nsg_issues.append({
                                "type": "overly_permissive_rule",
                                "severity": "high",
                                "rule_name": rule.name,
                                "description": "Rule allows all traffic from any source"
                            })
                        elif rule.source_address_prefix == '*' and rule.destination_port_range in ['22', '3389']:
                            nsg_issues.append({
                                "type": "public_admin_access",
                                "severity": "critical",
                                "rule_name": rule.name,
                                "description": f"Rule allows public access to port {rule.destination_port_range}"
                            })
                
                nsg_analysis.append({
                    "nsg_name": nsg.name,
                    "resource_group": nsg.id.split('/')[4] if nsg.id else '',
                    "location": nsg.location,
                    "rules_count": len(nsg.security_rules),
                    "security_issues": nsg_issues,
                    "risk_score": len([issue for issue in nsg_issues if issue["severity"] in ["high", "critical"]]) * 20
                })
                
        except Exception as e:
            logger.error(f"Error analyzing NSGs: {e}")
            raise
        
        return nsg_analysis

class GCPSecurityIntegration:
    """Google Cloud Platform Security Command Center integration"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.project_id = config.get("gcp_project_id")
        
        # Set up authentication
        if config.get("gcp_credentials_file"):
            import os
            os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = config["gcp_credentials_file"]
    
    async def get_security_findings(self, severity_filter: List[str] = None) -> List[Dict[str, Any]]:
        """Get findings from Security Command Center"""
        if not self.project_id:
            raise RuntimeError("GCP project ID not configured")
        
        client = securitycenter.SecurityCenterClient()
        findings = []
        
        try:
            # Build the organization/project name
            org_name = f"projects/{self.project_id}/sources/-"
            
            # Create filter
            filter_str = ""
            if severity_filter:
                severity_conditions = [f'severity="{sev.upper()}"' for sev in severity_filter]
                filter_str = " OR ".join(severity_conditions)
            
            # List findings
            request = securitycenter.ListFindingsRequest(
                parent=org_name,
                filter=filter_str
            )
            
            page_result = client.list_findings(request=request)
            
            for response in page_result:
                finding = response.finding
                findings.append({
                    "name": finding.name,
                    "parent": finding.parent,
                    "resource_name": finding.resource_name,
                    "state": finding.state.name,
                    "category": finding.category,
                    "external_uri": finding.external_uri,
                    "source_properties": dict(finding.source_properties),
                    "security_marks": dict(finding.security_marks.marks) if finding.security_marks else {},
                    "event_time": finding.event_time.isoformat() if finding.event_time else '',
                    "create_time": finding.create_time.isoformat() if finding.create_time else '',
                    "severity": finding.severity.name.lower() if finding.severity else 'medium'
                })
                
        except Exception as e:
            logger.error(f"Error getting GCP security findings: {e}")
            raise
        
        return findings
    
    async def get_asset_inventory(self) -> List[Dict[str, Any]]:
        """Get asset inventory from Cloud Asset API"""
        if not self.project_id:
            raise RuntimeError("GCP project ID not configured")
        
        client = asset_v1.AssetServiceClient()
        assets = []
        
        try:
            # Build the project name
            parent = f"projects/{self.project_id}"
            
            # List assets
            request = asset_v1.ListAssetsRequest(
                parent=parent,
                content_type=asset_v1.ContentType.RESOURCE
            )
            
            page_result = client.list_assets(request=request)
            
            for asset in page_result:
                assets.append({
                    "name": asset.name,
                    "asset_type": asset.asset_type,
                    "resource": {
                        "version": asset.resource.version,
                        "discovery_document_uri": asset.resource.discovery_document_uri,
                        "discovery_name": asset.resource.discovery_name,
                        "resource_url": asset.resource.resource_url,
                        "parent": asset.resource.parent,
                        "data": dict(asset.resource.data) if asset.resource.data else {}
                    },
                    "iam_policy": dict(asset.iam_policy.bindings) if asset.iam_policy else {},
                    "org_policy": [policy.constraint for policy in asset.org_policy] if asset.org_policy else [],
                    "access_policy": asset.access_policy.name if asset.access_policy else "",
                    "access_level": asset.access_level.name if asset.access_level else "",
                    "service_perimeter": asset.service_perimeter.name if asset.service_perimeter else ""
                })
                
        except Exception as e:
            logger.error(f"Error getting GCP asset inventory: {e}")
            raise
        
        return assets
    
    async def analyze_compute_security(self) -> List[Dict[str, Any]]:
        """Analyze Compute Engine security configuration"""
        if not self.project_id:
            raise RuntimeError("GCP project ID not configured")
        
        client = compute_v1.InstancesClient()
        security_analysis = []
        
        try:
            # List all zones first
            zones_client = compute_v1.ZonesClient()
            zones_list = zones_client.list(project=self.project_id)
            
            for zone in zones_list:
                # List instances in each zone
                request = compute_v1.ListInstancesRequest(
                    project=self.project_id,
                    zone=zone.name
                )
                
                instances = client.list(request=request)
                
                for instance in instances:
                    security_issues = []
                    
                    # Check for public IP
                    has_public_ip = False
                    for interface in instance.network_interfaces:
                        if interface.access_configs:
                            has_public_ip = True
                            break
                    
                    # Check for SSH keys
                    has_ssh_keys = False
                    if instance.metadata and instance.metadata.items:
                        for item in instance.metadata.items:
                            if item.key == "ssh-keys":
                                has_ssh_keys = True
                                break
                    
                    # Check service account
                    service_account_email = ""
                    wide_scopes = False
                    if instance.service_accounts:
                        service_account = instance.service_accounts[0]
                        service_account_email = service_account.email
                        
                        # Check for overly broad scopes
                        for scope in service_account.scopes:
                            if "cloud-platform" in scope:
                                wide_scopes = True
                                security_issues.append({
                                    "type": "wide_service_account_scope",
                                    "severity": "medium",
                                    "description": "Instance has cloud-platform scope which grants broad access"
                                })
                                break
                    
                    # Check firewall tags
                    firewall_tags = instance.tags.items if instance.tags else []
                    
                    if has_public_ip and not firewall_tags:
                        security_issues.append({
                            "type": "public_instance_no_firewall_tags",
                            "severity": "high",
                            "description": "Instance has public IP but no firewall tags for network security"
                        })
                    
                    security_analysis.append({
                        "instance_name": instance.name,
                        "zone": zone.name,
                        "machine_type": instance.machine_type.split('/')[-1] if instance.machine_type else '',
                        "status": instance.status,
                        "has_public_ip": has_public_ip,
                        "has_ssh_keys": has_ssh_keys,
                        "service_account_email": service_account_email,
                        "firewall_tags": firewall_tags,
                        "security_issues": security_issues,
                        "risk_score": len([issue for issue in security_issues if issue["severity"] in ["high", "critical"]]) * 25
                    })
                    
        except Exception as e:
            logger.error(f"Error analyzing GCP compute security: {e}")
            raise
        
        return security_analysis

class MultiCloudSecurityManager:
    """Manages security integrations across multiple cloud providers"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.aws_integration = None
        self.azure_integration = None
        self.gcp_integration = None
        
        # Initialize available integrations
        try:
            if config.get("aws_access_key_id") or config.get("aws_profile"):
                self.aws_integration = AWSSecurityIntegration(config)
        except Exception as e:
            logger.warning(f"AWS integration not available: {e}")
        
        try:
            if config.get("azure_subscription_id"):
                self.azure_integration = AzureSecurityIntegration(config)
        except Exception as e:
            logger.warning(f"Azure integration not available: {e}")
        
        try:
            if config.get("gcp_project_id"):
                self.gcp_integration = GCPSecurityIntegration(config)
        except Exception as e:
            logger.warning(f"GCP integration not available: {e}")
    
    async def get_multi_cloud_security_summary(self) -> Dict[str, Any]:
        """Get security summary across all configured cloud providers"""
        summary = {
            "timestamp": datetime.now().isoformat(),
            "providers": {},
            "overall_findings": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "total": 0
            }
        }
        
        # AWS findings
        if self.aws_integration:
            try:
                aws_findings = await self.aws_integration.get_security_hub_findings()
                aws_summary = self._summarize_findings(aws_findings)
                summary["providers"]["aws"] = aws_summary
                self._aggregate_findings(summary["overall_findings"], aws_summary)
            except Exception as e:
                logger.error(f"Error getting AWS findings: {e}")
                summary["providers"]["aws"] = {"error": str(e)}
        
        # Azure findings
        if self.azure_integration:
            try:
                azure_alerts = await self.azure_integration.get_security_center_alerts()
                azure_summary = self._summarize_findings(azure_alerts)
                summary["providers"]["azure"] = azure_summary
                self._aggregate_findings(summary["overall_findings"], azure_summary)
            except Exception as e:
                logger.error(f"Error getting Azure findings: {e}")
                summary["providers"]["azure"] = {"error": str(e)}
        
        # GCP findings
        if self.gcp_integration:
            try:
                gcp_findings = await self.gcp_integration.get_security_findings()
                gcp_summary = self._summarize_findings(gcp_findings)
                summary["providers"]["gcp"] = gcp_summary
                self._aggregate_findings(summary["overall_findings"], gcp_summary)
            except Exception as e:
                logger.error(f"Error getting GCP findings: {e}")
                summary["providers"]["gcp"] = {"error": str(e)}
        
        return summary
    
    def _summarize_findings(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize findings by severity"""
        summary = {
            "total_findings": len(findings),
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0
            }
        }
        
        for finding in findings:
            severity = finding.get("severity", "medium").lower()
            if severity in summary["by_severity"]:
                summary["by_severity"][severity] += 1
        
        return summary
    
    def _aggregate_findings(self, overall: Dict[str, int], provider_summary: Dict[str, Any]):
        """Aggregate findings into overall summary"""
        if "by_severity" in provider_summary:
            for severity, count in provider_summary["by_severity"].items():
                if severity in overall:
                    overall[severity] += count
            overall["total"] += provider_summary.get("total_findings", 0)
