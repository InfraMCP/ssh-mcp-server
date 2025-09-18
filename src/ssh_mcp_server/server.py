#!/usr/bin/env python3
"""SSH MCP Server - Main server implementation."""

import paramiko
from typing import Dict, Any
from mcp.server.fastmcp import FastMCP

from .credentials import credential_manager

# Create MCP server
mcp = FastMCP("SSH Server")

# SSH connection timeout
SSH_TIMEOUT = 30


@mcp.tool()
def execute_ssh(hostname: str, command: str) -> Dict[str, Any]:
    """Execute command on remote Linux host via SSH"""
    
    domain = credential_manager.get_domain_from_hostname(hostname)
    
    # Check if credentials are available
    if not credential_manager.test_credentials_available(domain):
        return {
            "error": f"No credentials found for {domain}",
            "help": f"Use authenticate_domain('{domain}') to store credentials securely first"
        }
    
    try:
        # Get credentials
        credentials = credential_manager.get_credentials(domain)
        if not credentials:
            return {"error": f"Failed to retrieve credentials for {domain}"}
            
        username, password = credentials
        
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect with timeout
        ssh.connect(
            hostname=hostname,
            username=username,
            password=password,
            timeout=SSH_TIMEOUT,
            auth_timeout=SSH_TIMEOUT
        )
        
        # Execute command
        stdin, stdout, stderr = ssh.exec_command(command, timeout=SSH_TIMEOUT)
        
        # Get results
        stdout_data = stdout.read().decode('utf-8')
        stderr_data = stderr.read().decode('utf-8')
        exit_code = stdout.channel.recv_exit_status()
        
        ssh.close()
        
        # Clear password from memory immediately
        password = None
        
        return {
            "status": exit_code,
            "stdout": stdout_data,
            "stderr": stderr_data
        }
        
    except Exception as e:
        # Clear password from memory on error
        password = None
        return {"error": f"SSH connection failed: {str(e)}"}


@mcp.tool()
def execute_sudo(hostname: str, command: str) -> Dict[str, Any]:
    """Execute command with sudo on remote Linux host"""
    
    domain = credential_manager.get_domain_from_hostname(hostname)
    
    # Check if credentials are available
    if not credential_manager.test_credentials_available(domain):
        return {
            "error": f"No credentials found for {domain}",
            "help": f"Use authenticate_domain('{domain}') to store credentials securely first"
        }
    
    try:
        # Get credentials
        credentials = credential_manager.get_credentials(domain)
        if not credentials:
            return {"error": f"Failed to retrieve credentials for {domain}"}
            
        username, password = credentials
        
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect
        ssh.connect(
            hostname=hostname,
            username=username,
            password=password,
            timeout=SSH_TIMEOUT,
            auth_timeout=SSH_TIMEOUT
        )
        
        # Execute with sudo - secure method using stdin
        sudo_command = f"sudo -S {command}"
        stdin, stdout, stderr = ssh.exec_command(sudo_command, timeout=SSH_TIMEOUT)
        
        # Send password securely via stdin (not visible in process list)
        stdin.write(password + '\n')
        stdin.flush()
        
        # Get results
        stdout_data = stdout.read().decode('utf-8')
        stderr_data = stderr.read().decode('utf-8')
        exit_code = stdout.channel.recv_exit_status()
        
        ssh.close()
        
        # Clean up sudo password prompt from stderr
        if stderr_data.startswith('[sudo] password for'):
            stderr_lines = stderr_data.split('\n')
            stderr_data = '\n'.join(stderr_lines[1:])
        
        # Clear password from memory immediately
        password = None
        
        return {
            "status": exit_code,
            "stdout": stdout_data,
            "stderr": stderr_data
        }
        
    except Exception as e:
        # Clear password from memory on error
        password = None
        return {"error": f"SSH connection failed: {str(e)}"}


@mcp.tool()
def authenticate_domain(domain: str) -> Dict[str, Any]:
    """Authenticate and securely store credentials for a domain"""
    try:
        success = credential_manager.authenticate_domain(domain)
        if success:
            return {
                "success": True,
                "message": f"Credentials stored securely for {domain}"
            }
        else:
            return {
                "success": False,
                "error": f"Failed to authenticate for {domain}"
            }
    except Exception as e:
        return {
            "success": False,
            "error": f"Authentication failed: {str(e)}"
        }


@mcp.tool()
def ssh_get_system_info(hostname: str) -> Dict[str, Any]:
    """Get basic system information from Linux host"""
    command = "uname -a && cat /etc/os-release | head -5 && free -h && df -h /"
    return execute_ssh(hostname, command)


@mcp.tool()
def get_running_processes(hostname: str) -> Dict[str, Any]:
    """Get running processes from Linux host"""
    command = "ps aux --sort=-%cpu | head -10"
    return execute_ssh(hostname, command)


@mcp.tool()
def get_disk_usage(hostname: str) -> Dict[str, Any]:
    """Get disk usage information from Linux host"""
    command = "df -h"
    return execute_ssh(hostname, command)


@mcp.tool()
def get_services(hostname: str) -> Dict[str, Any]:
    """Get systemd services status from Linux host"""
    command = "systemctl list-units --type=service --state=running --no-pager | head -20"
    return execute_ssh(hostname, command)


@mcp.tool()
def ssh_puppet_noop(hostname: str) -> Dict[str, Any]:
    """Run Puppet agent in no-op mode (dry run) with verbose output"""
    # Check if puppet is already running by looking for lock file
    lock_check = execute_sudo(hostname, "ls -la /var/lib/puppet/state/agent_catalog_run.lock 2>/dev/null")
    
    if lock_check.get("status") == 0:
        return {
            "error": "Puppet agent is already running",
            "details": "Lock file exists: /var/lib/puppet/state/agent_catalog_run.lock",
            "suggestion": "Wait for puppet to complete, or remove lock file if stuck: sudo rm /var/lib/puppet/state/agent_catalog_run.lock"
        }
    
    # No lock file, proceed with noop
    command = "puppet agent -vt --noop"
    return execute_sudo(hostname, command)


def main():
    """Main entry point for the SSH MCP server."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
