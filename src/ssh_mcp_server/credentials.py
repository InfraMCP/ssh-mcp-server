#!/usr/bin/env python3
"""Secure credential management for SSH connections."""

import getpass
import os
import subprocess
import sys
import time
from typing import Optional, Tuple


def get_username_suggestion() -> str:
    """Get suggested username (current user)."""
    return getpass.getuser()


def keychain_get_password(service: str, account: str) -> Optional[str]:
    """Get password from macOS Keychain."""
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        return None


def keychain_set_password(
    service: str, account: str, password: str, ttl_hours: int = 4
):
    """Store password in macOS Keychain with TTL."""
    # Delete existing entry if present
    subprocess.run(
        ["security", "delete-generic-password", "-s", service, "-a", account],
        capture_output=True,
    )

    # Add new entry with comment containing expiration time
    expiry_time = int(time.time()) + (ttl_hours * 3600)

    subprocess.run(
        [
            "security",
            "add-generic-password",
            "-s",
            service,
            "-a",
            account,
            "-w",
            password,
            "-j",
            f"expires:{expiry_time}",
        ],
        check=True,
    )


def keychain_check_expired(service: str, account: str) -> bool:
    """Check if keychain entry is expired."""
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-j"],
            capture_output=True,
            text=True,
            check=True,
        )

        # Parse comment for expiry time
        comment = result.stdout.strip()
        if comment.startswith("expires:"):
            expiry_time = int(comment.split(":")[1])
            return time.time() > expiry_time
    except (subprocess.CalledProcessError, ValueError, IndexError):
        pass

    return True  # Assume expired if we can't determine


def prompt_credentials_gui(hostname: str, suggested_username: str) -> Tuple[str, str]:
    """Prompt for credentials using macOS GUI dialogs."""
    username_script = f'''
    display dialog "Enter username for SSH to {hostname}:" ¬
    with title "SSH Authentication" ¬
    with icon note ¬
    default answer "{suggested_username}" ¬
    buttons {{"Cancel", "OK"}} ¬
    default button "OK"
    '''
    
    try:
        result = subprocess.run(['osascript', '-e', username_script], 
                              capture_output=True, text=True, check=True)
        username = result.stdout.strip().split('text returned:')[1].strip()
        
        if not username:
            username = suggested_username
            
    except (subprocess.CalledProcessError, IndexError):
        raise RuntimeError("Username input cancelled")
    
    # Prompt for password (hidden)
    password_script = f'''
    display dialog "Enter password for {username}@{hostname}:" ¬
    with title "SSH Authentication" ¬
    with icon note ¬
    default answer "" ¬
    with hidden answer ¬
    buttons {{"Cancel", "OK"}} ¬
    default button "OK"
    '''
    
    try:
        result = subprocess.run(['osascript', '-e', password_script], 
                              capture_output=True, text=True, check=True)
        password = result.stdout.strip().split('text returned:')[1].strip()
    except (subprocess.CalledProcessError, IndexError):
        raise RuntimeError("Password input cancelled")
    
    if not password:
        raise RuntimeError("Password cannot be empty")
    
    return username, password


def get_credentials(hostname: str) -> Tuple[str, str]:
    """Get credentials for hostname with GUI prompting and caching."""
    service = "ssh-mcp"
    suggested_username = get_username_suggestion()
    
    # Check for cached credentials for this specific hostname
    try:
        # Get all accounts for this service
        account_result = subprocess.run([
            'security', 'find-generic-password',
            '-s', service
        ], capture_output=True, text=True)
        
        if account_result.returncode == 0:
            for line in account_result.stdout.split('\n'):
                if 'acct' in line and hostname in line:
                    # Extract account name
                    parts = line.split('"')
                    if len(parts) >= 4:
                        account = parts[3]
                        
                        # Account format: username@hostname
                        if '@' in account and hostname in account:
                            username = account.split('@')[0]
                            # Get password for this specific account
                            password = keychain_get_password(service, account)
                            if password:
                                return username, password
    except subprocess.CalledProcessError:
        pass
    
    # No cached credentials found, prompt using GUI
    username, password = prompt_credentials_gui(hostname, suggested_username)
    
    # Store in keychain using username@hostname format
    account = f"{username}@{hostname}"
    try:
        keychain_set_password(service, account, password)
    except subprocess.CalledProcessError as e:
        print(f"Warning: Could not cache credentials: {e}", file=sys.stderr)
    
    return username, password


def clear_cached_credentials(hostname: str = None) -> bool:
    """Clear all cached SSH credentials."""
    service = "ssh-mcp"
    cleared = False
    
    try:
        # Get all accounts for this service
        result = subprocess.run([
            'security', 'find-generic-password',
            '-s', service
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'acct' in line:
                    # Extract account name - it's at index 3
                    parts = line.split('"')
                    if len(parts) >= 4:
                        account = parts[3]  # Account is at index 3
                        # Delete any account for this service
                        try:
                            subprocess.run([
                                'security', 'delete-generic-password',
                                '-s', service,
                                '-a', account
                            ], capture_output=True, check=True)
                            cleared = True
                        except subprocess.CalledProcessError:
                            pass
    except subprocess.CalledProcessError:
        pass
    
    return cleared


def test_credentials_available(hostname: str) -> bool:
    """Test if valid credentials are available for hostname."""
    service = "ssh-mcp"
    
    try:
        result = subprocess.run([
            'security', 'find-generic-password',
            '-s', service,
            '-g'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            for line in result.stderr.split('\n'):
                if 'acct' in line and hostname in line:
                    # Handle username@hostname format
                    if f'@{hostname}' in line:
                        parts = line.split('"')
                        if len(parts) >= 2:
                            account_match = parts[1]
                            if not keychain_check_expired(service, account_match):
                                return True
    except subprocess.CalledProcessError:
        pass
    
    return False


# Legacy compatibility functions for domain-based systems
def get_domain_from_hostname(hostname: str) -> str:
    """Extract domain from FQDN - for compatibility only."""
    parts = hostname.split(".")
    if len(parts) > 1:
        return ".".join(parts[1:])
    return f"{hostname}.local"


def get_credential_manager():
    """Legacy compatibility - returns a simple object with the new functions."""
    class CredentialManager:
        @staticmethod
        def get_credentials(domain: str) -> Optional[Tuple[str, str]]:
            # For legacy compatibility, treat domain as hostname
            try:
                return get_credentials(domain)
            except RuntimeError:
                return None
        
        @staticmethod
        def get_domain_from_hostname(hostname: str) -> str:
            return get_domain_from_hostname(hostname)
        
        @staticmethod
        def test_credentials_available(domain: str) -> bool:
            return test_credentials_available(domain)
    
    return CredentialManager()


def authenticate_domain(hostname_or_domain: str) -> bool:
    """Authenticate and store credentials for a hostname."""
    try:
        get_credentials(hostname_or_domain)
        return True
    except RuntimeError:
        return False


def get_credentials_from_keychain(domain: str) -> Optional[Tuple[str, str]]:
    """Legacy function for backward compatibility."""
    try:
        return get_credentials(domain)
    except RuntimeError:
        return None
