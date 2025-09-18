#!/usr/bin/env python3
"""SSH MCP Server - Main server implementation."""

import paramiko
import sys
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
    
    # Check if credentials are available
    if not credential_manager.test_credentials_available(hostname):
        domain = credential_manager.get_domain_from_hostname(hostname)
        return {
            "error": f"No credentials found for {domain}",
            "help": f"Set SSH_USERNAME_{domain.upper().replace('.', '_')} and SSH_PASSWORD_{domain.upper().replace('.', '_')} environment variables"
        }
    
    try:
        # Get credentials
        domain = credential_manager.get_domain_from_hostname(hostname)
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
        stdin, stdout, stderr = ssh.exec_command(command)
        
        # Get output
        output = stdout.read().decode('utf-8')
        error = stderr.read().decode('utf-8')
        exit_code = stdout.channel.recv_exit_status()
        
        # Close connection
        ssh.close()
        
        return {
            "hostname": hostname,
            "command": command,
            "exit_code": exit_code,
            "stdout": output,
            "stderr": error,
            "success": exit_code == 0
        }
        
    except Exception as e:
        return {
            "error": f"SSH connection failed: {str(e)}",
            "hostname": hostname,
            "command": command
        }


@mcp.tool()
def execute_sudo(hostname: str, command: str) -> Dict[str, Any]:
    """Execute command with sudo on remote Linux host via SSH"""
    sudo_command = f"sudo {command}"
    return execute_ssh(hostname, sudo_command)


@mcp.tool()
def get_system_info(hostname: str) -> Dict[str, Any]:
    """Get basic system information from remote Linux host"""
    command = "uname -a && uptime && df -h / && free -h"
    return execute_ssh(hostname, command)


@mcp.tool()
def get_running_processes(hostname: str) -> Dict[str, Any]:
    """Get top running processes from remote Linux host"""
    command = "ps aux --sort=-%cpu | head -20"
    return execute_ssh(hostname, command)


@mcp.tool()
def get_disk_usage(hostname: str) -> Dict[str, Any]:
    """Get disk usage information from remote Linux host"""
    command = "df -h"
    return execute_ssh(hostname, command)


@mcp.tool()
def get_services(hostname: str) -> Dict[str, Any]:
    """Get running systemd services from remote Linux host"""
    command = "systemctl list-units --type=service --state=running"
    return execute_ssh(hostname, command)


def main():
    """Main entry point for the SSH MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
