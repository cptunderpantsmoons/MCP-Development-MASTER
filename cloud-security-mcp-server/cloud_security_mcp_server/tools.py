#!/usr/bin/env python3
"""
Cloud Security Tool Integrations
Handles integration with various cloud security tools and scanners
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import docker
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime
import aiofiles
import aiohttp

logger = logging.getLogger(__name__)

class SecurityToolIntegration:
    """Base class for security tool integrations"""
    
    def __init__(self, tool_name: str, docker_image: str, config: Dict[str, Any] = None):
        self.tool_name = tool_name
        self.docker_image = docker_image
        self.config = config or {}
        self.docker_client = None
        
        try:
            self.docker_client = docker.from_env()
        except Exception as e:
            logger.warning(f"Docker not available for {tool_name}: {e}")
    
    async def run_scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Execute the security scan"""
        raise NotImplementedError("Subclasses must implement run_scan method")
    
    def _prepare_docker_command(self, base_cmd: List[str], volumes: Dict[str, str] = None, env_vars: Dict[str, str] = None) -> List[str]:
        """Prepare Docker command with common options"""
        cmd = ["docker", "run", "--rm"]
        
        # Add volume mounts
        if volumes:
            for host_path, container_path in volumes.items():
                cmd.extend(["-v", f"{host_path}:{container_path}"])
        
        # Add environment variables
        if env_vars:
            for key, value in env_vars.items():
                cmd.extend(["-e", f"{key}={value}"])
        
        cmd.extend(base_cmd)
        return cmd

class ProwlerIntegration(SecurityToolIntegration):
    """Prowler AWS security assessment integration"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("prowler", "toniblyx/prowler:latest", config)
    
    async def run_scan(self, target: str = None, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run Prowler AWS security assessment"""
        options = options or {}
        output_dir = Path(tempfile.mkdtemp(prefix="prowler_"))
        
        # Prepare environment variables
        env_vars = {}
        if self.config.get("aws_access_key_id"):
            env_vars["AWS_ACCESS_KEY_ID"] = self.config["aws_access_key_id"]
            env_vars["AWS_SECRET_ACCESS_KEY"] = self.config["aws_secret_access_key"]
            if self.config.get("aws_session_token"):
                env_vars["AWS_SESSION_TOKEN"] = self.config["aws_session_token"]
        
        env_vars["AWS_DEFAULT_REGION"] = self.config.get("aws_region", "us-east-1")
        
        # Prepare volumes
        volumes = {str(output_dir): "/output"}
        
        # Build command
        cmd = [self.docker_image]
        
        # Add compliance framework
        framework = options.get("compliance_framework", "cis")
        cmd.extend(["-g", framework])
        
        # Output format
        cmd.extend(["-M", "json", "-q", "-z"])
        
        # Add target filters
        if target and target != "all":
            cmd.extend(["-f", target])
        
        # Add output directory
        cmd.extend(["-o", "/output"])
        
        docker_cmd = self._prepare_docker_command(cmd, volumes, env_vars)
        
        try:
            # Execute Prowler
            process = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=options.get("timeout", 1800)
            )
            
            # Parse results
            results = await self._parse_prowler_results(output_dir)
            
            return {
                "tool": "prowler",
                "status": "completed" if process.returncode == 0 else "failed",
                "findings": results.get("findings", []),
                "summary": results.get("summary", {}),
                "metadata": {
                    "framework": framework,
                    "target": target,
                    "scan_time": datetime.now().isoformat(),
                    "output_directory": str(output_dir)
                },
                "raw_output": stdout.decode('utf-8') if options.get("include_raw") else None
            }
            
        except asyncio.TimeoutError:
            raise RuntimeError(f"Prowler scan timed out")
        except Exception as e:
            raise RuntimeError(f"Prowler scan failed: {str(e)}")
    
    async def _parse_prowler_results(self, output_dir: Path) -> Dict[str, Any]:
        """Parse Prowler output files"""
        findings = []
        summary = {}
        
        # Look for JSON output files
        json_files = list(output_dir.glob("*.json"))
        
        for json_file in json_files:
            try:
                async with aiofiles.open(json_file, 'r') as f:
                    content = await f.read()
                    
                # Prowler may output JSONL (one JSON object per line)
                for line in content.strip().split('\n'):
                    if line.strip():
                        try:
                            finding = json.loads(line)
                            findings.append({
                                "check_id": finding.get("Check_ID", ""),
                                "title": finding.get("Check_Title", ""),
                                "severity": finding.get("Severity", "medium").lower(),
                                "status": finding.get("Status", ""),
                                "resource": finding.get("Resource_Id", ""),
                                "region": finding.get("Region", ""),
                                "service": finding.get("Service_Name", ""),
                                "description": finding.get("Check_Description", ""),
                                "remediation": finding.get("Remediation", ""),
                                "compliance": finding.get("Compliance", {})
                            })
                        except json.JSONDecodeError:
                            continue
                            
            except Exception as e:
                logger.error(f"Error parsing Prowler output file {json_file}: {e}")
        
        # Calculate summary
        if findings:
            summary = {
                "total_checks": len(findings),
                "passed": len([f for f in findings if f["status"] == "PASS"]),
                "failed": len([f for f in findings if f["status"] == "FAIL"]),
                "by_severity": {}
            }
            
            for severity in ["critical", "high", "medium", "low"]:
                summary["by_severity"][severity] = len([f for f in findings if f["severity"] == severity])
        
        return {"findings": findings, "summary": summary}

class CheckovIntegration(SecurityToolIntegration):
    """Checkov Infrastructure as Code security scanning"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("checkov", "bridgecrew/checkov:latest", config)
    
    async def run_scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run Checkov IaC scan"""
        options = options or {}
        output_dir = Path(tempfile.mkdtemp(prefix="checkov_"))
        
        # Prepare volumes
        volumes = {
            target: "/tf",
            str(output_dir): "/output"
        }
        
        # Build command
        cmd = [
            self.docker_image,
            "--directory", "/tf",
            "--output", "json",
            "--output-file-path", "/output/checkov_results.json"
        ]
        
        # Add framework filter
        if options.get("framework"):
            cmd.extend(["--framework", options["framework"]])
        
        docker_cmd = self._prepare_docker_command(cmd, volumes)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=options.get("timeout", 1800)
            )
            
            # Parse results
            results = await self._parse_checkov_results(output_dir)
            
            return {
                "tool": "checkov",
                "status": "completed" if process.returncode == 0 else "failed",
                "findings": results.get("findings", []),
                "summary": results.get("summary", {}),
                "metadata": {
                    "target_path": target,
                    "scan_time": datetime.now().isoformat(),
                    "framework": options.get("framework", "all")
                }
            }
            
        except asyncio.TimeoutError:
            raise RuntimeError("Checkov scan timed out")
        except Exception as e:
            raise RuntimeError(f"Checkov scan failed: {str(e)}")
    
    async def _parse_checkov_results(self, output_dir: Path) -> Dict[str, Any]:
        """Parse Checkov results"""
        findings = []
        summary = {}
        
        results_file = output_dir / "checkov_results.json"
        
        if results_file.exists():
            try:
                async with aiofiles.open(results_file, 'r') as f:
                    content = await f.read()
                    data = json.loads(content)
                
                # Parse failed checks
                for result in data.get("results", {}).get("failed_checks", []):
                    findings.append({
                        "check_id": result.get("check_id", ""),
                        "title": result.get("check_name", ""),
                        "severity": self._map_checkov_severity(result.get("severity", "MEDIUM")),
                        "status": "failed",
                        "resource": result.get("resource", ""),
                        "file_path": result.get("file_path", ""),
                        "line_range": result.get("file_line_range", []),
                        "description": result.get("description", ""),
                        "guideline": result.get("guideline", "")
                    })
                
                # Calculate summary
                summary = {
                    "total_checks": len(data.get("results", {}).get("failed_checks", [])) + 
                                  len(data.get("results", {}).get("passed_checks", [])),
                    "failed": len(data.get("results", {}).get("failed_checks", [])),
                    "passed": len(data.get("results", {}).get("passed_checks", [])),
                    "skipped": len(data.get("results", {}).get("skipped_checks", []))
                }
                
            except Exception as e:
                logger.error(f"Error parsing Checkov results: {e}")
        
        return {"findings": findings, "summary": summary}
    
    def _map_checkov_severity(self, severity: str) -> str:
        """Map Checkov severity to standard levels"""
        mapping = {
            "CRITICAL": "critical",
            "HIGH": "high", 
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info"
        }
        return mapping.get(severity.upper(), "medium")

class TrivyIntegration(SecurityToolIntegration):
    """Trivy container vulnerability scanning"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("trivy", "aquasec/trivy:latest", config)
    
    async def run_scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run Trivy vulnerability scan"""
        options = options or {}
        scan_type = options.get("scan_type", "image")
        output_dir = Path(tempfile.mkdtemp(prefix="trivy_"))
        
        # Prepare volumes
        volumes = {
            "/var/run/docker.sock": "/var/run/docker.sock",
            str(output_dir): "/output"
        }
        
        # Build command based on scan type
        cmd = [self.docker_image]
        
        if scan_type == "image":
            cmd.extend(["image", "--format", "json", "--output", "/output/trivy_results.json", target])
        elif scan_type == "filesystem":
            volumes[target] = "/target"
            cmd.extend(["filesystem", "--format", "json", "--output", "/output/trivy_results.json", "/target"])
        elif scan_type == "repo":
            cmd.extend(["repo", "--format", "json", "--output", "/output/trivy_results.json", target])
        
        # Add severity filter
        if options.get("severity"):
            cmd.extend(["--severity", options["severity"]])
        
        docker_cmd = self._prepare_docker_command(cmd, volumes)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=options.get("timeout", 1800)
            )
            
            # Parse results
            results = await self._parse_trivy_results(output_dir)
            
            return {
                "tool": "trivy",
                "status": "completed" if process.returncode == 0 else "failed",
                "findings": results.get("findings", []),
                "summary": results.get("summary", {}),
                "metadata": {
                    "target": target,
                    "scan_type": scan_type,
                    "scan_time": datetime.now().isoformat()
                }
            }
            
        except asyncio.TimeoutError:
            raise RuntimeError("Trivy scan timed out")
        except Exception as e:
            raise RuntimeError(f"Trivy scan failed: {str(e)}")
    
    async def _parse_trivy_results(self, output_dir: Path) -> Dict[str, Any]:
        """Parse Trivy results"""
        findings = []
        summary = {}
        
        results_file = output_dir / "trivy_results.json"
        
        if results_file.exists():
            try:
                async with aiofiles.open(results_file, 'r') as f:
                    content = await f.read()
                    data = json.loads(content)
                
                # Parse vulnerabilities
                for result in data.get("Results", []):
                    for vulnerability in result.get("Vulnerabilities", []):
                        findings.append({
                            "vulnerability_id": vulnerability.get("VulnerabilityID", ""),
                            "title": vulnerability.get("Title", ""),
                            "severity": vulnerability.get("Severity", "unknown").lower(),
                            "package": vulnerability.get("PkgName", ""),
                            "version": vulnerability.get("InstalledVersion", ""),
                            "fixed_version": vulnerability.get("FixedVersion", ""),
                            "description": vulnerability.get("Description", ""),
                            "references": vulnerability.get("References", [])
                        })
                
                # Calculate summary
                if findings:
                    summary = {
                        "total_vulnerabilities": len(findings),
                        "by_severity": {}
                    }
                    
                    for severity in ["critical", "high", "medium", "low", "unknown"]:
                        summary["by_severity"][severity] = len([f for f in findings if f["severity"] == severity])
                
            except Exception as e:
                logger.error(f"Error parsing Trivy results: {e}")
        
        return {"findings": findings, "summary": summary}

class KubeHunterIntegration(SecurityToolIntegration):
    """Kube-hunter Kubernetes security scanning"""
    
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__("kube_hunter", "aquasec/kube-hunter:latest", config)
    
    async def run_scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run Kube-hunter scan"""
        options = options or {}
        scan_type = options.get("scan_type", "remote")
        output_dir = Path(tempfile.mkdtemp(prefix="kube_hunter_"))
        
        # Prepare volumes
        volumes = {str(output_dir): "/output"}
        
        # Build command based on scan type
        cmd = [self.docker_image]
        
        if scan_type == "remote":
            cmd.extend(["--remote", target])
        elif scan_type == "internal":
            cmd.extend(["--internal"])
        elif scan_type == "network":
            cmd.extend(["--cidr", target])
        
        # Output format
        cmd.extend(["--report", "json", "--log", "none"])
        
        docker_cmd = self._prepare_docker_command(cmd, volumes)
        
        try:
            process = await asyncio.create_subprocess_exec(
                *docker_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=options.get("timeout", 1800)
            )
            
            # Parse results from stdout (Kube-hunter outputs JSON to stdout)
            results = await self._parse_kube_hunter_results(stdout.decode('utf-8'))
            
            return {
                "tool": "kube_hunter",
                "status": "completed" if process.returncode == 0 else "failed",
                "findings": results.get("findings", []),
                "summary": results.get("summary", {}),
                "metadata": {
                    "target": target,
                    "scan_type": scan_type,
                    "scan_time": datetime.now().isoformat()
                }
            }
            
        except asyncio.TimeoutError:
            raise RuntimeError("Kube-hunter scan timed out")
        except Exception as e:
            raise RuntimeError(f"Kube-hunter scan failed: {str(e)}")
    
    async def _parse_kube_hunter_results(self, output: str) -> Dict[str, Any]:
        """Parse Kube-hunter results"""
        findings = []
        summary = {}
        
        try:
            if output.strip():
                data = json.loads(output)
                
                # Parse vulnerabilities
                for vulnerability in data.get("vulnerabilities", []):
                    findings.append({
                        "vulnerability_id": vulnerability.get("vid", ""),
                        "title": vulnerability.get("vulnerability", ""),
                        "severity": self._map_kube_hunter_severity(vulnerability.get("severity", "medium")),
                        "category": vulnerability.get("category", ""),
                        "description": vulnerability.get("description", ""),
                        "evidence": vulnerability.get("evidence", ""),
                        "hunter": vulnerability.get("hunter", "")
                    })
                
                # Calculate summary
                if findings:
                    summary = {
                        "total_vulnerabilities": len(findings),
                        "by_severity": {}
                    }
                    
                    for severity in ["high", "medium", "low"]:
                        summary["by_severity"][severity] = len([f for f in findings if f["severity"] == severity])
            
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Kube-hunter output: {e}")
        
        return {"findings": findings, "summary": summary}
    
    def _map_kube_hunter_severity(self, severity: str) -> str:
        """Map Kube-hunter severity to standard levels"""
        mapping = {
            "high": "high",
            "medium": "medium",
            "low": "low"
        }
        return mapping.get(severity.lower(), "medium")

class SecurityToolManager:
    """Manages all security tool integrations"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.tools = {
            "prowler": ProwlerIntegration(config),
            "checkov": CheckovIntegration(config),
            "trivy": TrivyIntegration(config),
            "kube_hunter": KubeHunterIntegration(config)
        }
    
    async def run_tool(self, tool_name: str, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run a specific security tool"""
        if tool_name not in self.tools:
            raise ValueError(f"Unknown tool: {tool_name}")
        
        tool = self.tools[tool_name]
        return await tool.run_scan(target, options)
    
    def get_available_tools(self) -> List[str]:
        """Get list of available security tools"""
        return list(self.tools.keys())
    
    async def run_comprehensive_scan(self, targets: Dict[str, str], options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run comprehensive security scan across multiple tools"""
        options = options or {}
        results = {}
        
        # Define tool-target mappings
        scan_tasks = []
        
        # AWS scans
        if targets.get("aws"):
            scan_tasks.append(("prowler", targets["aws"], {"cloud_provider": "aws"}))
        
        # IaC scans
        if targets.get("iac_path"):
            scan_tasks.append(("checkov", targets["iac_path"], {"framework": "terraform"}))
        
        # Container scans
        if targets.get("container_image"):
            scan_tasks.append(("trivy", targets["container_image"], {"scan_type": "image"}))
        
        # Kubernetes scans
        if targets.get("kubernetes_cluster"):
            scan_tasks.append(("kube_hunter", targets["kubernetes_cluster"], {"scan_type": "remote"}))
        
        # Execute scans concurrently
        scan_results = await asyncio.gather(
            *[self.run_tool(tool, target, opts) for tool, target, opts in scan_tasks],
            return_exceptions=True
        )
        
        # Compile results
        for i, (tool_name, target, opts) in enumerate(scan_tasks):
            result = scan_results[i]
            if isinstance(result, Exception):
                results[tool_name] = {"status": "failed", "error": str(result)}
            else:
                results[tool_name] = result
        
        return {
            "comprehensive_scan": True,
            "scan_time": datetime.now().isoformat(),
            "tools_executed": len(scan_tasks),
            "results": results,
            "summary": self._generate_comprehensive_summary(results)
        }
    
    def _generate_comprehensive_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary across all scan results"""
        total_findings = 0
        total_critical = 0
        total_high = 0
        tools_succeeded = 0
        
        for tool_name, result in results.items():
            if result.get("status") == "completed":
                tools_succeeded += 1
                findings = result.get("findings", [])
                total_findings += len(findings)
                
                for finding in findings:
                    severity = finding.get("severity", "medium")
                    if severity == "critical":
                        total_critical += 1
                    elif severity == "high":
                        total_high += 1
        
        return {
            "total_findings": total_findings,
            "critical_findings": total_critical,
            "high_findings": total_high,
            "tools_succeeded": tools_succeeded,
            "tools_total": len(results),
            "overall_risk": "high" if total_critical > 0 else "medium" if total_high > 0 else "low"
        }
