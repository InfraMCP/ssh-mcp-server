#!/usr/bin/env python3
"""SSH MCP Server - Main server implementation."""

import paramiko
import subprocess
from typing import Dict, Any
from mcp.server.fastmcp import FastMCP

from .credentials import get_credentials, clear_cached_credentials, get_domain_from_hostname, test_credentials_available, get_username_suggestion

# Create MCP server
mcp = FastMCP("SSH Server")

# SSH connection timeout
SSH_TIMEOUT = 30


@mcp.tool()
def ssh_execute_ssh(hostname: str, command: str) -> Dict[str, Any]:
    """Execute command on remote Linux host via SSH"""
    
    try:
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Check if we have cached credentials to get the correct username
        cached_username = None
        try:
            service = "ssh-mcp"
            account_result = subprocess.run([
                'security', 'find-generic-password',
                '-s', service
            ], capture_output=True, text=True)
            
            if account_result.returncode == 0:
                for line in account_result.stdout.split('\n'):
                    if 'acct' in line and hostname in line:
                        parts = line.split('"')
                        if len(parts) >= 4:
                            account = parts[3]
                            if '@' in account and hostname in account:
                                cached_username = account.split('@')[0]
                                break
        except:
            pass
        
        # Use cached username if available, otherwise current user
        ssh_username = cached_username if cached_username else get_username_suggestion()
        
        # First try key-based authentication
        try:
            ssh.connect(
                hostname=hostname,
                username=ssh_username,
                timeout=SSH_TIMEOUT,
                look_for_keys=True,
                allow_agent=True
            )
        except paramiko.AuthenticationException:
            # Key auth failed, try password authentication
            try:
                username, password = get_credentials(hostname)
                ssh.connect(
                    hostname=hostname,
                    username=username,
                    password=password,
                    timeout=SSH_TIMEOUT,
                    look_for_keys=False,
                    allow_agent=False
                )
                # Clear password from memory
                password = None
            except RuntimeError as e:
                error_msg = str(e)
                if "cancelled" in error_msg.lower():
                    return {
                        "error": "Authentication cancelled by user",
                        "details": error_msg,
                        "troubleshooting": [
                            "User clicked Cancel in authentication dialog",
                            "Authentication dialog may have timed out"
                        ],
                        "suggested_action": f"Try again: ssh_setup_credentials('{hostname}')"
                    }
                else:
                    return {
                        "error": "Credential setup failed", 
                        "details": error_msg,
                        "troubleshooting": [
                            "SSH key authentication failed",
                            "Password authentication setup failed",
                            "Check if hostname is correct"
                        ]
                    }
        
        # Execute command
        stdin, stdout, stderr = ssh.exec_command(command)
        
        # Get results
        exit_status = stdout.channel.recv_exit_status()
        stdout_text = stdout.read().decode('utf-8', errors='replace')
        stderr_text = stderr.read().decode('utf-8', errors='replace')
        
        # Close connection
        ssh.close()
        
        return {
            "status": exit_status,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "hostname": hostname,
            "command": command
        }
        
    except paramiko.SSHException as e:
        return {
            "error": "SSH connection failed",
            "details": str(e),
            "troubleshooting": [
                "Host may be unreachable or offline",
                "SSH service may not be running on target host",
                "Firewall may be blocking SSH port (22)",
                "Host key verification may have failed"
            ],
            "suggested_action": f"Check connectivity: ping {hostname} && nc -zv {hostname} 22"
        }
    except Exception as e:
        return {
            "error": "SSH execution failed",
            "details": str(e),
            "troubleshooting": [
                "Network connectivity issues",
                "SSH service configuration problems",
                "Command execution timeout",
                "Resource constraints on target host"
            ],
            "suggested_action": "Try a simple command first: ssh_get_system_info"
        }


@mcp.tool()
def ssh_execute_sudo(hostname: str, command: str) -> Dict[str, Any]:
    """Execute command with sudo on remote Linux host"""
    
    try:
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # First try key-based authentication
        username = get_username_suggestion()
        password = None
        
        try:
            ssh.connect(
                hostname=hostname,
                username=username,
                timeout=SSH_TIMEOUT,
                look_for_keys=True,
                allow_agent=True
            )
        except paramiko.AuthenticationException:
            # Key auth failed, get password credentials
            username, password = get_credentials(hostname)
            ssh.connect(
                hostname=hostname,
                username=username,
                password=password,
                timeout=SSH_TIMEOUT,
                look_for_keys=False,
                allow_agent=False
            )
        
        # For sudo, we need a password - get it if we don't have one
        if password is None:
            # We connected with keys, but need password for sudo
            username, password = get_credentials(hostname)
        
        # Execute sudo command with password input
        sudo_command = f"echo '{password}' | sudo -S {command}"
        stdin, stdout, stderr = ssh.exec_command(sudo_command)
        
        # Get results
        exit_status = stdout.channel.recv_exit_status()
        stdout_text = stdout.read().decode('utf-8', errors='replace')
        stderr_text = stderr.read().decode('utf-8', errors='replace')
        
        # Clean up sudo password prompt from stderr
        if stderr_text.startswith('[sudo] password for'):
            lines = stderr_text.split('\n')
            stderr_text = '\n'.join(lines[1:])
        
        # Close connection
        ssh.close()
        
        # Clear password from memory
        password = None
        
        return {
            "status": exit_status,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "hostname": hostname,
            "command": f"sudo {command}"
        }
        
    except RuntimeError as e:
        error_msg = str(e)
        if "cancelled" in error_msg.lower():
            return {
                "error": "Authentication cancelled by user",
                "details": error_msg,
                "troubleshooting": [
                    "User clicked Cancel in authentication dialog",
                    "Password required for sudo operations"
                ],
                "suggested_action": f"Try again: ssh_setup_credentials('{hostname}')"
            }
        else:
            return {
                "error": "Credential setup failed", 
                "details": error_msg
            }
    except paramiko.AuthenticationException:
        return {
            "error": "SSH authentication failed",
            "details": "Invalid username or password",
            "suggested_action": f"Clear and re-enter credentials: ssh_clear_credentials() then ssh_setup_credentials('{hostname}')"
        }
    except Exception as e:
        return {
            "error": "SSH sudo execution failed",
            "details": str(e),
            "troubleshooting": [
                "User may not have sudo privileges",
                "Sudo may require different password",
                "Command may require interactive input",
                "Network or SSH connection issues"
            ]
        }


@mcp.tool()
def ssh_setup_credentials(hostname: str) -> Dict[str, Any]:
    """Setup credentials for a Linux host using GUI prompts"""
    try:
        username, password = get_credentials(hostname)
        # Clear password from memory immediately
        password = None
        return {
            "status": "success",
            "message": f"Credentials configured for {username}@{hostname}",
            "details": f"Cached for 4 hours, used for password authentication and sudo operations",
            "next_steps": [
                f"Try: ssh_execute_ssh('{hostname}', 'uname -a')",
                f"Or: ssh_get_system_info('{hostname}')",
                "Note: SSH will try key authentication first, then fall back to password"
            ]
        }
    except Exception as e:
        error_msg = str(e)
        if "cancelled" in error_msg.lower():
            return {
                "error": "Authentication cancelled by user",
                "details": error_msg,
                "troubleshooting": [
                    "User clicked Cancel in authentication dialog",
                    "Authentication dialog may have timed out",
                    "System may be locked or user not present"
                ],
                "suggested_action": f"Try again: ssh_setup_credentials('{hostname}')"
            }
        elif "empty" in error_msg.lower():
            return {
                "error": "Empty password not allowed",
                "details": error_msg,
                "troubleshooting": [
                    "Password field was left blank",
                    "Password is required for sudo operations",
                    "Dialog input may have failed"
                ],
                "suggested_action": "Ensure password is entered in the dialog"
            }
        else:
            return {
                "error": "Credential setup failed",
                "details": error_msg,
                "troubleshooting": [
                    "macOS Keychain access may be denied",
                    "System security settings may block keychain access",
                    "Hostname format may be invalid"
                ],
                "suggested_action": f"Check hostname format: '{hostname}' should be a valid hostname or FQDN"
            }


@mcp.tool()
def ssh_clear_credentials() -> Dict[str, Any]:
    """Clear all cached SSH credentials"""
    try:
        if clear_cached_credentials():
            return {
                "status": "success", 
                "message": "All cached SSH credentials cleared",
                "details": "All SSH password credentials have been removed from keychain",
                "next_steps": [
                    "Use ssh_setup_credentials(hostname) to set up password authentication for specific hosts",
                    "SSH key authentication will still work if configured"
                ]
            }
        else:
            return {
                "status": "info", 
                "message": "No cached SSH credentials found",
                "details": "No SSH password credentials were stored in keychain",
                "suggested_action": "Use ssh_setup_credentials(hostname) to set up password authentication"
            }
    except Exception as e:
        return {
            "error": "Failed to clear credentials",
            "details": str(e),
            "troubleshooting": [
                "macOS Keychain access may be restricted",
                "Keychain may be locked",
                "System security settings may prevent access"
            ],
            "suggested_action": "Check macOS Keychain Access app for any restrictions"
        }


@mcp.tool()
def ssh_get_system_info(hostname: str) -> Dict[str, Any]:
    """Get basic system information from Linux host"""
    command = "uname -a && cat /etc/os-release 2>/dev/null || cat /etc/redhat-release 2>/dev/null || echo 'OS info not available'"
    return ssh_execute_ssh(hostname, command)


@mcp.tool()
def ssh_get_running_processes(hostname: str) -> Dict[str, Any]:
    """Get running processes from Linux host"""
    command = "ps aux --sort=-%cpu | head -20"
    return ssh_execute_ssh(hostname, command)


@mcp.tool()
def ssh_get_disk_usage(hostname: str) -> Dict[str, Any]:
    """Get disk usage information from Linux host"""
    command = "df -h"
    return ssh_execute_ssh(hostname, command)


@mcp.tool()
def ssh_get_services(hostname: str) -> Dict[str, Any]:
    """Get systemd services status from Linux host"""
    command = "systemctl list-units --type=service --state=running --no-pager"
    return ssh_execute_ssh(hostname, command)


@mcp.tool()
def ssh_puppet_noop(hostname: str) -> Dict[str, Any]:
    """Run Puppet agent in no-op mode (dry run) with verbose output"""
    command = "puppet agent --test --noop --verbose"
    return ssh_execute_sudo(hostname, command)


# Legacy compatibility functions
@mcp.tool()
def execute_ssh(hostname: str, command: str) -> Dict[str, Any]:
    """Legacy compatibility - Execute command on remote Linux host via SSH"""
    return ssh_execute_ssh(hostname, command)


@mcp.tool()
def execute_sudo(hostname: str, command: str) -> Dict[str, Any]:
    """Legacy compatibility - Execute command with sudo on remote Linux host"""
    return ssh_execute_sudo(hostname, command)


@mcp.tool()
def cache_credentials(domain: str) -> Dict[str, Any]:
    """Legacy compatibility - Pre-cache credentials"""
    hostname = f"host.{domain}"
    return ssh_setup_credentials(hostname)


@mcp.tool()
def get_running_processes(hostname: str) -> Dict[str, Any]:
    """Legacy compatibility - Get running processes from Linux host"""
    return ssh_get_running_processes(hostname)


@mcp.tool()
def get_disk_usage(hostname: str) -> Dict[str, Any]:
    """Legacy compatibility - Get disk usage information from Linux host"""
    return ssh_get_disk_usage(hostname)


@mcp.tool()
def get_services(hostname: str) -> Dict[str, Any]:
    """Legacy compatibility - Get systemd services status from Linux host"""
    return ssh_get_services(hostname)


def main():
    """Main entry point for the SSH MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
