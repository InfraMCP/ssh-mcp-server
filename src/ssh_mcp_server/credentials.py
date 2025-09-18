"""Credential management for SSH MCP Server."""

import os
import platform
from typing import Optional, Tuple
from abc import ABC, abstractmethod


class CredentialProvider(ABC):
    """Abstract base class for credential providers."""
    
    @abstractmethod
    def get_credentials(self, domain: str) -> Optional[Tuple[str, str]]:
        """Get username and password for a domain."""
        pass
    
    @abstractmethod
    def test_credentials_available(self, hostname: str) -> bool:
        """Test if credentials are available for a hostname."""
        pass


class MacOSKeychainProvider(CredentialProvider):
    """macOS Keychain credential provider."""
    
    def get_credentials(self, domain: str) -> Optional[Tuple[str, str]]:
        """Get credentials from macOS Keychain."""
        try:
            import subprocess
            
            # Get username
            username_cmd = [
                "security", "find-generic-password",
                "-s", f"domain-{domain}",
                "-w"
            ]
            username_result = subprocess.run(username_cmd, capture_output=True, text=True)
            
            if username_result.returncode != 0:
                return None
                
            username = username_result.stdout.strip()
            
            # Get password (triggers TouchID)
            password_cmd = [
                "security", "find-generic-password",
                "-s", f"domain-{domain}",
                "-a", username,
                "-w"
            ]
            password_result = subprocess.run(password_cmd, capture_output=True, text=True)
            
            if password_result.returncode != 0:
                return None
                
            password = password_result.stdout.strip()
            return username, password
            
        except Exception:
            return None
    
    def test_credentials_available(self, hostname: str) -> bool:
        """Test if credentials are available for hostname."""
        domain = self.get_domain_from_hostname(hostname)
        return self.get_credentials(domain) is not None
    
    @staticmethod
    def get_domain_from_hostname(hostname: str) -> str:
        """Extract domain from hostname."""
        if '.' in hostname:
            parts = hostname.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
        return hostname


class EnvironmentProvider(CredentialProvider):
    """Environment variable credential provider."""
    
    def get_credentials(self, domain: str) -> Optional[Tuple[str, str]]:
        """Get credentials from environment variables."""
        username = os.getenv(f"SSH_USERNAME_{domain.upper().replace('.', '_')}")
        password = os.getenv(f"SSH_PASSWORD_{domain.upper().replace('.', '_')}")
        
        if username and password:
            return username, password
        return None
    
    def test_credentials_available(self, hostname: str) -> bool:
        """Test if credentials are available for hostname."""
        domain = MacOSKeychainProvider.get_domain_from_hostname(hostname)
        return self.get_credentials(domain) is not None


class CredentialManager:
    """Manages multiple credential providers."""
    
    def __init__(self):
        self.providers = []
        
        # Add providers based on platform
        if platform.system() == "Darwin":  # macOS
            self.providers.append(MacOSKeychainProvider())
        
        # Always add environment provider as fallback
        self.providers.append(EnvironmentProvider())
    
    def get_credentials(self, domain: str) -> Optional[Tuple[str, str]]:
        """Get credentials from the first available provider."""
        for provider in self.providers:
            credentials = provider.get_credentials(domain)
            if credentials:
                return credentials
        return None
    
    def test_credentials_available(self, hostname: str) -> bool:
        """Test if credentials are available from any provider."""
        for provider in self.providers:
            if provider.test_credentials_available(hostname):
                return True
        return False
    
    @staticmethod
    def get_domain_from_hostname(hostname: str) -> str:
        """Extract domain from hostname."""
        return MacOSKeychainProvider.get_domain_from_hostname(hostname)


# Global credential manager instance
credential_manager = CredentialManager()


def get_credentials_from_keychain(domain: str) -> Optional[Tuple[str, str]]:
    """Legacy function for backward compatibility."""
    return credential_manager.get_credentials(domain)


def test_credentials_available(hostname: str) -> bool:
    """Legacy function for backward compatibility."""
    return credential_manager.test_credentials_available(hostname)


def get_domain_from_hostname(hostname: str) -> str:
    """Legacy function for backward compatibility."""
    return credential_manager.get_domain_from_hostname(hostname)
