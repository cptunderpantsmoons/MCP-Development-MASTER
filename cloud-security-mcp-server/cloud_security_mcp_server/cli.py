#!/usr/bin/env python3
"""
Cloud Security MCP Server CLI
Command-line interface for managing and running cloud security scans
"""

import asyncio
import click
import json
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich.tree import Tree
from rich import print as rprint
from datetime import datetime

from cloud_security_mcp_server.config import CloudSecurityMCPConfig, load_config
from cloud_security_mcp_server.tools import SecurityToolManager
from cloud_security_mcp_server.cloud_providers import MultiCloudSecurityManager
from cloud_security_mcp_server.main import CloudSecurityMCPServer

console = Console()

@click.group()
@click.option('--config', '-c', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.pass_context
def cli(ctx, config, verbose):
    """Cloud Security MCP Server - Comprehensive cloud security analysis and scanning"""
    ctx.ensure_object(dict)
    ctx.obj['config_path'] = config
    ctx.obj['verbose'] = verbose
    
    # Load configuration
    try:
        ctx.obj['config'] = load_config(config)
    except Exception as e:
        console.print(f"[red]Error loading configuration: {e}[/red]")
        sys.exit(1)

@cli.command()
@click.pass_context
def server(ctx):
    """Start the MCP server"""
    config = ctx.obj['config']
    
    console.print(Panel.fit(
        "[bold blue]Starting Cloud Security MCP Server[/bold blue]\n"
        f"Version: 1.0.0\n"
        f"Config: {ctx.obj.get('config_path', 'default')}"
    ))
    
    try:
        asyncio.run(main_server())
    except KeyboardInterrupt:
        console.print("\n[yellow]Server stopped by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Server error: {e}[/red]")
        sys.exit(1)

async def main_server():
    """Main server entry point"""
    server_instance = CloudSecurityMCPServer()
    await server_instance.server.run_stdio()

@cli.group()
def scan():
    """Security scanning commands"""
    pass

@scan.command()
@click.option('--target', '-t', required=True, help='Scan target (AWS account, file path, etc.)')
@click.option('--tool', help='Specific tool to use', 
              type=click.Choice(['prowler', 'checkov', 'trivy', 'kube_hunter']))
@click.option('--output', '-o', help='Output file path')
@click.option('--format', 'output_format', default='json', 
              type=click.Choice(['json', 'table', 'html']))
@click.pass_context
def run(ctx, target, tool, output, output_format):
    """Run a security scan"""
    config = ctx.obj['config']
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Running security scan...", total=None)
        
        try:
            result = asyncio.run(run_security_scan(config, target, tool))
            progress.remove_task(task)
            
            if output_format == 'table':
                display_scan_results_table(result)
            elif output_format == 'html':
                generate_html_report(result, output)
            else:
                if output:
                    with open(output, 'w') as f:
                        json.dump(result, f, indent=2)
                    console.print(f"[green]Results saved to {output}[/green]")
                else:
                    console.print_json(data=result)
                    
        except Exception as e:
            progress.remove_task(task)
            console.print(f"[red]Scan failed: {e}[/red]")
            sys.exit(1)

async def run_security_scan(config: CloudSecurityMCPConfig, target: str, tool: Optional[str]) -> Dict:
    """Run security scan with specified tool"""
    tool_manager = SecurityToolManager(config.to_dict())
    
    if tool:
        return await tool_manager.run_tool(tool, target)
    else:
        # Run comprehensive scan
        targets = {"general": target}
        return await tool_manager.run_comprehensive_scan(targets)

def display_scan_results_table(result: Dict):
    """Display scan results in a table format"""
    table = Table(title="Security Scan Results")
    table.add_column("Finding", style="cyan")
    table.add_column("Severity", style="magenta")
    table.add_column("Resource", style="green")
    table.add_column("Description", style="yellow")
    
    findings = result.get('findings', [])
    for finding in findings[:20]:  # Limit to first 20
        severity = finding.get('severity', 'medium')
        severity_color = {
            'critical': '[red]',
            'high': '[orange1]',
            'medium': '[yellow]',
            'low': '[blue]',
            'info': '[green]'
        }.get(severity, '[white]')
        
        table.add_row(
            finding.get('title', finding.get('check_id', 'Unknown')),
            f"{severity_color}{severity}[/{severity_color.strip('[]')}]",
            finding.get('resource', 'N/A'),
            finding.get('description', 'No description')[:80] + "..." if len(finding.get('description', '')) > 80 else finding.get('description', '')
        )
    
    console.print(table)
    
    # Summary
    summary = result.get('summary', {})
    if summary:
        console.print(f"\n[bold]Summary:[/bold]")
        console.print(f"Total findings: {summary.get('total_findings', len(findings))}")
        for severity, count in summary.get('by_severity', {}).items():
            if count > 0:
                console.print(f"{severity.capitalize()}: {count}")

@scan.command()
@click.option('--providers', default='aws,azure,gcp', help='Cloud providers to scan (comma-separated)')
@click.option('--output', '-o', help='Output directory')
@click.pass_context
def multi_cloud(ctx, providers, output):
    """Run multi-cloud security assessment"""
    config = ctx.obj['config']
    provider_list = [p.strip() for p in providers.split(',')]
    
    console.print(f"[blue]Starting multi-cloud scan for: {', '.join(provider_list)}[/blue]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Scanning cloud environments...", total=None)
        
        try:
            result = asyncio.run(run_multi_cloud_scan(config, provider_list))
            progress.remove_task(task)
            
            display_multi_cloud_results(result)
            
            if output:
                output_path = Path(output)
                output_path.mkdir(exist_ok=True)
                
                # Save overall results
                with open(output_path / "multi_cloud_results.json", 'w') as f:
                    json.dump(result, f, indent=2)
                
                console.print(f"[green]Results saved to {output_path}[/green]")
                
        except Exception as e:
            progress.remove_task(task)
            console.print(f"[red]Multi-cloud scan failed: {e}[/red]")
            sys.exit(1)

async def run_multi_cloud_scan(config: CloudSecurityMCPConfig, providers: List[str]) -> Dict:
    """Run multi-cloud security scan"""
    manager = MultiCloudSecurityManager(config.to_dict())
    return await manager.get_multi_cloud_security_summary()

def display_multi_cloud_results(result: Dict):
    """Display multi-cloud scan results"""
    tree = Tree("[bold blue]Multi-Cloud Security Summary[/bold blue]")
    
    providers = result.get('providers', {})
    overall = result.get('overall_findings', {})
    
    # Overall summary
    overall_branch = tree.add("[bold]Overall Findings[/bold]")
    overall_branch.add(f"Total: {overall.get('total', 0)}")
    overall_branch.add(f"[red]Critical: {overall.get('critical', 0)}[/red]")
    overall_branch.add(f"[orange1]High: {overall.get('high', 0)}[/orange1]")
    overall_branch.add(f"[yellow]Medium: {overall.get('medium', 0)}[/yellow]")
    overall_branch.add(f"[blue]Low: {overall.get('low', 0)}[/blue]")
    
    # Provider-specific results
    for provider_name, provider_data in providers.items():
        if 'error' in provider_data:
            provider_branch = tree.add(f"[red]{provider_name.upper()} (Error)[/red]")
            provider_branch.add(f"Error: {provider_data['error']}")
        else:
            provider_branch = tree.add(f"[green]{provider_name.upper()}[/green]")
            provider_branch.add(f"Total findings: {provider_data.get('total_findings', 0)}")
            
            by_severity = provider_data.get('by_severity', {})
            for severity, count in by_severity.items():
                if count > 0:
                    severity_color = {
                        'critical': 'red',
                        'high': 'orange1',
                        'medium': 'yellow',
                        'low': 'blue'
                    }.get(severity, 'white')
                    provider_branch.add(f"[{severity_color}]{severity.capitalize()}: {count}[/{severity_color}]")
    
    console.print(tree)

@cli.group()
def compliance():
    """Compliance checking commands"""
    pass

@compliance.command()
@click.option('--framework', '-f', required=True,
              type=click.Choice(['cis', 'nist', 'soc2', 'pci_dss', 'gdpr', 'hipaa']),
              help='Compliance framework to check')
@click.option('--provider', '-p', required=True,
              type=click.Choice(['aws', 'azure', 'gcp']),
              help='Cloud provider')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def check(ctx, framework, provider, output):
    """Check compliance against security frameworks"""
    config = ctx.obj['config']
    
    console.print(f"[blue]Checking {framework.upper()} compliance for {provider.upper()}[/blue]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Running compliance check...", total=None)
        
        try:
            result = asyncio.run(run_compliance_check(config, framework, provider))
            progress.remove_task(task)
            
            display_compliance_results(result, framework)
            
            if output:
                with open(output, 'w') as f:
                    json.dump(result, f, indent=2)
                console.print(f"[green]Compliance report saved to {output}[/green]")
                
        except Exception as e:
            progress.remove_task(task)
            console.print(f"[red]Compliance check failed: {e}[/red]")
            sys.exit(1)

async def run_compliance_check(config: CloudSecurityMCPConfig, framework: str, provider: str) -> Dict:
    """Run compliance check"""
    # This would integrate with the compliance checking functionality
    # For now, return a mock result
    return {
        "framework": framework,
        "provider": provider,
        "compliance_percentage": 75.5,
        "total_checks": 150,
        "passed_checks": 113,
        "failed_checks": 37,
        "status": "non_compliant" if 75.5 < 80 else "compliant",
        "scan_time": datetime.now().isoformat()
    }

def display_compliance_results(result: Dict, framework: str):
    """Display compliance check results"""
    compliance_pct = result.get('compliance_percentage', 0)
    status = result.get('status', 'unknown')
    
    status_color = 'green' if status == 'compliant' else 'red'
    
    panel = Panel(
        f"[bold]{framework.upper()} Compliance Report[/bold]\n\n"
        f"Status: [{status_color}]{status.replace('_', ' ').title()}[/{status_color}]\n"
        f"Compliance: {compliance_pct:.1f}%\n"
        f"Passed: {result.get('passed_checks', 0)}/{result.get('total_checks', 0)} checks\n"
        f"Failed: {result.get('failed_checks', 0)} checks\n"
        f"Scan Time: {result.get('scan_time', 'Unknown')}",
        title=f"{result.get('provider', '').upper()} Compliance",
        border_style=status_color
    )
    
    console.print(panel)

@cli.group()
def config():
    """Configuration management commands"""
    pass

@config.command()
@click.option('--output', '-o', default='config.yaml', help='Output configuration file')
def init(output):
    """Initialize default configuration"""
    try:
        config = CloudSecurityMCPConfig()
        config.save_to_file(output)
        console.print(f"[green]Default configuration created: {output}[/green]")
        console.print("[yellow]Please edit the configuration file to add your cloud credentials[/yellow]")
    except Exception as e:
        console.print(f"[red]Failed to create configuration: {e}[/red]")
        sys.exit(1)

@config.command()
@click.argument('config_file')
def validate(config_file):
    """Validate configuration file"""
    try:
        config = CloudSecurityMCPConfig.from_file(config_file)
        console.print(f"[green]✅ Configuration file '{config_file}' is valid[/green]")
        
        # Show enabled providers
        providers = config.get_enabled_cloud_providers()
        if providers:
            console.print(f"[blue]Enabled cloud providers: {', '.join(providers)}[/blue]")
        else:
            console.print("[yellow]⚠️  No cloud provider credentials configured[/yellow]")
            
    except Exception as e:
        console.print(f"[red]❌ Configuration validation failed: {e}[/red]")
        sys.exit(1)

@config.command()
@click.pass_context
def show(ctx):
    """Show current configuration"""
    config = ctx.obj['config']
    
    tree = Tree("[bold blue]Current Configuration[/bold blue]")
    
    # Cloud providers
    cloud_branch = tree.add("[bold]Cloud Providers[/bold]")
    providers = config.get_enabled_cloud_providers()
    if providers:
        for provider in providers:
            cloud_branch.add(f"[green]✅ {provider.upper()}[/green]")
    else:
        cloud_branch.add("[red]❌ No providers configured[/red]")
    
    # Security tools
    tools_branch = tree.add("[bold]Security Tools[/bold]")
    tools_branch.add(f"Container Scanning: {'✅' if config.security_tools.enable_container_scanning else '❌'}")
    tools_branch.add(f"IaC Scanning: {'✅' if config.security_tools.enable_iac_scanning else '❌'}")
    tools_branch.add(f"Compliance Checks: {'✅' if config.security_tools.enable_compliance_checks else '❌'}")
    
    # Compliance frameworks
    compliance_branch = tree.add("[bold]Compliance Frameworks[/bold]")
    for framework in config.compliance.frameworks:
        compliance_branch.add(f"📋 {framework.upper()}")
    
    console.print(tree)

@cli.command()
def version():
    """Show version information"""
    console.print(Panel.fit(
        "[bold blue]Cloud Security MCP Server[/bold blue]\n"
        "Version: 1.0.0\n"
        "Model Context Protocol Server for Cloud Security\n\n"
        "[dim]Features:[/dim]\n"
        "• Multi-cloud security scanning (AWS, Azure, GCP)\n"
        "• Infrastructure as Code analysis\n"
        "• Container vulnerability scanning\n"
        "• Kubernetes security assessment\n"
        "• Compliance framework checking\n"
        "• Continuous security monitoring"
    ))

def generate_html_report(result: Dict, output_path: Optional[str]):
    """Generate HTML report from scan results"""
    if not output_path:
        output_path = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cloud Security Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background-color: #f0f8ff; padding: 20px; border-radius: 5px; }}
            .critical {{ color: #dc3545; }}
            .high {{ color: #fd7e14; }}
            .medium {{ color: #ffc107; }}
            .low {{ color: #17a2b8; }}
            .info {{ color: #28a745; }}
            table {{ border-collapse: collapse; width: 100%; margin-top: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Cloud Security Scan Report</h1>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <h2>Summary</h2>
        <p>Total findings: {len(result.get('findings', []))}</p>
        
        <h2>Findings</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Resource</th>
                <th>Description</th>
            </tr>
    """
    
    for finding in result.get('findings', []):
        severity = finding.get('severity', 'medium')
        html_content += f"""
            <tr>
                <td class="{severity}">{severity.upper()}</td>
                <td>{finding.get('title', 'Unknown')}</td>
                <td>{finding.get('resource', 'N/A')}</td>
                <td>{finding.get('description', 'No description')}</td>
            </tr>
        """
    
    html_content += """
        </table>
    </body>
    </html>
    """
    
    with open(output_path, 'w') as f:
        f.write(html_content)
    
    console.print(f"[green]HTML report generated: {output_path}[/green]")

if __name__ == '__main__':
    cli()
