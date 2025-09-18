#!/usr/bin/env python3

import paramiko
import sys
import os
from mcp.server.fastmcp import FastMCP

# Add scripts directory to path for shared credentials
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'scripts'))

try:
    from domain_credentials import get_credentials_from_keychain, get_domain_from_hostname, test_credentials_available
except ImportError as e:
    print(f"Error importing credentials module: {e}", file=sys.stderr)
    sys.exit(1)

# Create MCP server
mcp = FastMCP("SSH Server")

# SSH connection timeout
SSH_TIMEOUT = 30

@mcp.tool()
def execute_ssh(hostname: str, command: str) -> dict:
    """Execute command on remote Linux host via SSH"""
    
    # Check if credentials are available
    if not test_credentials_available(hostname):
        domain = get_domain_from_hostname(hostname)
        return {
            "error": f"No credentials found for {domain}",
            "help": f"Run 'python3 ~/.aws/amazonq/scripts/domain_auth.py {domain}' to authenticate first"
        }
    
    try:
        # Get credentials
        username, password = get_credentials_from_keychain(get_domain_from_hostname(hostname))
        
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
        return {"error": "SSH connection or authentication failed"}

@mcp.tool()
def execute_sudo(hostname: str, command: str) -> dict:
    """Execute command with sudo on remote Linux host"""
    
    # Check if credentials are available
    if not test_credentials_available(hostname):
        domain = get_domain_from_hostname(hostname)
        return {
            "error": f"No credentials found for {domain}",
            "help": f"Run 'python3 ~/.aws/amazonq/scripts/domain_auth.py {domain}' to authenticate first"
        }
    
    try:
        # Get credentials
        username, password = get_credentials_from_keychain(get_domain_from_hostname(hostname))
        
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
        return {"error": "SSH connection or authentication failed"}

@mcp.tool()
def ssh_get_system_info(hostname: str) -> dict:
    """Get basic system information from Linux host"""
    command = "uname -a && cat /etc/os-release | head -5 && free -h && df -h /"
    return execute_ssh(hostname, command)

@mcp.tool()
def get_running_processes(hostname: str) -> dict:
    """Get running processes from Linux host"""
    command = "ps aux --sort=-%cpu | head -10"
    return execute_ssh(hostname, command)

@mcp.tool()
def get_disk_usage(hostname: str) -> dict:
    """Get disk usage information from Linux host"""
    command = "df -h"
    return execute_ssh(hostname, command)

@mcp.tool()
def get_services(hostname: str) -> dict:
    """Get systemd services status from Linux host"""
    command = "systemctl list-units --type=service --state=running --no-pager | head -20"
    return execute_ssh(hostname, command)

@mcp.tool()
def ssh_puppet_noop(hostname: str) -> dict:
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

if __name__ == "__main__":
    mcp.run(transport="stdio")
