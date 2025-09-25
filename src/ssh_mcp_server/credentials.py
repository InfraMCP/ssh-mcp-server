#!/usr/bin/env python3
"""Secure credential management for SSH connections."""

import getpass
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
            check=False,
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
        check=False,
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
        check=False,
    )


def keychain_check_expired(service: str, account: str) -> bool:
    """Check if keychain entry is expired."""
    try:
        result = subprocess.run(
            ["security", "find-generic-password", "-s", service, "-a", account, "-j"],
            capture_output=True,
            text=True,
            check=False,
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

    except (subprocess.CalledProcessError, IndexError) as exc:
        raise RuntimeError("Username input cancelled") from exc

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
    except (subprocess.CalledProcessError, IndexError) as exc:
        raise RuntimeError("Password input cancelled") from exc

    if not password:
        raise RuntimeError("Password cannot be empty")

    return username, password


def get_domain_from_hostname(hostname: str) -> str:
    """Extract domain from FQDN."""
    parts = hostname.split(".")
    if len(parts) > 1:
        # Extract domain from FQDN (e.g., server.domain.local -> domain.local)
        return ".".join(parts[1:])
    # Fallback: use hostname.local
    return f"{hostname}.local"


def get_credentials(hostname: str) -> Tuple[str, str]:
    """Get credentials for hostname with GUI prompting and caching."""
    domain = get_domain_from_hostname(hostname)
    service = "ssh-mcp"

    # Check for cached credentials for this domain
    try:
        # Get all accounts for this service
        account_result = subprocess.run([
            'security', 'find-generic-password',
            '-s', service
        ], capture_output=True, text=True, check=False)

        if account_result.returncode == 0:
            for line in account_result.stdout.split('\n'):
                if 'acct' in line and domain in line:
                    # Extract account name
                    parts = line.split('"')
                    if len(parts) >= 4:
                        account = parts[3]

                        # Account format: username@domain
                        if '@' in account and domain in account:
                            username = account.split('@')[0]
                            # Get password for this specific account
                            password = keychain_get_password(service, account)
                            if password:
                                return username, password
    except subprocess.CalledProcessError:
        pass

    # No cached credentials found, prompt using GUI
    username, password = prompt_credentials_gui(hostname, get_username_suggestion())

    # Store in keychain using username@domain format
    account = f"{username}@{domain}"
    try:
        keychain_set_password(service, account, password)
    except subprocess.CalledProcessError as e:
        print(f"Warning: Could not cache credentials: {e}", file=sys.stderr)

    return username, password


def clear_cached_credentials(_hostname: str = None) -> bool:
    """Clear all cached SSH credentials."""
    service = "ssh-mcp"
    cleared = False

    try:
        # Get all accounts for this service
        result = subprocess.run([
            'security', 'find-generic-password',
            '-s', service
        ], capture_output=True, text=True, check=False)

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
                            ], capture_output=True, check=False)
                            cleared = True
                        except subprocess.CalledProcessError:
                            pass
    except subprocess.CalledProcessError:
        pass

    return cleared


def test_credentials_available(hostname: str) -> bool:
    """Test if valid credentials are available for hostname."""
    domain = get_domain_from_hostname(hostname)
    service = "ssh-mcp"

    try:
        result = subprocess.run([
            'security', 'find-generic-password',
            '-s', service,
            '-g'
        ], capture_output=True, text=True, check=False)

        if result.returncode == 0:
            for line in result.stderr.split('\n'):
                if 'acct' in line and domain in line:
                    # Handle username@domain format
                    if f'@{domain}' in line:
                        parts = line.split('"')
                        if len(parts) >= 2:
                            account_match = parts[1]
                            if not keychain_check_expired(service, account_match):
                                return True
    except subprocess.CalledProcessError:
        pass

    return False


def get_credential_manager():
    """Legacy compatibility - returns a simple object with the new functions."""
    class CredentialManager:
        """Legacy credential manager for backward compatibility."""

        @staticmethod
        def get_credentials(domain: str) -> Optional[Tuple[str, str]]:
            """Get credentials for a domain."""
            # For legacy compatibility, treat domain as hostname
            try:
                return get_credentials(domain)
            except RuntimeError:
                return None

        @staticmethod
        def get_domain_from_hostname(hostname: str) -> str:
            """Extract domain from hostname."""
            return get_domain_from_hostname(hostname)

        @staticmethod
        def test_credentials_available(domain: str) -> bool:
            """Test if credentials are available for domain."""
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
