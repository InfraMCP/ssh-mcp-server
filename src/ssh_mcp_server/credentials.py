"""Secure credential management for SSH MCP Server."""

import os
import platform
import subprocess
import getpass
from typing import Optional, Tuple, Dict
from abc import ABC, abstractmethod


class CredentialProvider(ABC):
    """Abstract base class for credential providers."""
    
    @abstractmethod
    def get_credentials(self, domain: str) -> Optional[Tuple[str, str]]:
        """Get username and password for a domain."""
        pass
    
    @abstractmethod
    def store_credentials(self, domain: str, username: str, password: str) -> bool:
        """Store credentials securely."""
        pass
    
    @abstractmethod
    def test_credentials_available(self, domain: str) -> bool:
        """Test if credentials are available for a domain."""
        pass


class MacOSKeychainProvider(CredentialProvider):
    """macOS Keychain credential provider with TouchID protection."""
    
    def get_credentials(self, domain: str) -> Optional[Tuple[str, str]]:
        """Get credentials from macOS Keychain (triggers TouchID)."""
        try:
            service = f"ssh-mcp-{domain}"
            
            # Get account name
            cmd = ["security", "find-generic-password", "-s", service, "-w"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return None
            
            username = result.stdout.strip()
            
            # Get password (triggers TouchID/password prompt)
            cmd = ["security", "find-generic-password", "-s", service, "-a", username, "-w"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return None
                
            password = result.stdout.strip()
            return username, password
            
        except Exception:
            return None
    
    def store_credentials(self, domain: str, username: str, password: str) -> bool:
        """Store credentials in macOS Keychain."""
        try:
            service = f"ssh-mcp-{domain}"
            
            # Delete existing entry if it exists
            subprocess.run(["security", "delete-generic-password", "-s", service], 
                         capture_output=True)
            
            # Add new entry
            cmd = [
                "security", "add-generic-password",
                "-s", service,
                "-a", username,
                "-w", password,
                "-T", "",  # Allow all applications
                "-U"       # Update if exists
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            return result.returncode == 0
            
        except Exception:
            return False
    
    def test_credentials_available(self, domain: str) -> bool:
        """Test if credentials are available."""
        return self.get_credentials(domain) is not None


class MemoryProvider(CredentialProvider):
    """In-memory credential provider (session-only)."""
    
    def __init__(self):
        self._credentials: Dict[str, Tuple[str, str]] = {}
    
    def get_credentials(self, domain: str) -> Optional[Tuple[str, str]]:
        """Get credentials from memory."""
        return self._credentials.get(domain)
    
    def store_credentials(self, domain: str, username: str, password: str) -> bool:
        """Store credentials in memory."""
        self._credentials[domain] = (username, password)
        return True
    
    def test_credentials_available(self, domain: str) -> bool:
        """Test if credentials are available."""
        return domain in self._credentials


class InteractiveProvider(CredentialProvider):
    """Interactive prompt provider (fallback)."""
    
    def get_credentials(self, domain: str) -> Optional[Tuple[str, str]]:
        """Prompt user for credentials."""
        try:
            print(f"SSH credentials required for domain: {domain}")
            username = input("Username: ").strip()
            if not username:
                return None
            
            password = getpass.getpass("Password: ")
            if not password:
                return None
                
            return username, password
            
        except (KeyboardInterrupt, EOFError):
            return None
    
    def store_credentials(self, domain: str, username: str, password: str) -> bool:
        """Interactive provider doesn't store credentials."""
        return False
    
    def test_credentials_available(self, domain: str) -> bool:
        """Interactive provider always available as fallback."""
        return True


class CredentialManager:
    """Manages multiple credential providers with security focus."""
    
    def __init__(self):
        self.providers = []
        self.memory_provider = MemoryProvider()
        
        # Add platform-specific secure providers
        if platform.system() == "Darwin":  # macOS
            self.providers.append(MacOSKeychainProvider())
        
        # Add memory provider for session caching
        self.providers.append(self.memory_provider)
        
        # Interactive as last resort
        self.providers.append(InteractiveProvider())
    
    def get_credentials(self, domain: str) -> Optional[Tuple[str, str]]:
        """Get credentials from first available provider."""
        for provider in self.providers:
            try:
                credentials = provider.get_credentials(domain)
                if credentials:
                    # Cache in memory for session
                    if provider != self.memory_provider:
                        self.memory_provider.store_credentials(domain, *credentials)
                    return credentials
            except Exception:
                continue
        return None
    
    def store_credentials(self, domain: str, username: str, password: str) -> bool:
        """Store credentials in the most secure available provider."""
        # Try secure providers first
        for provider in self.providers[:-2]:  # Exclude memory and interactive
            try:
                if provider.store_credentials(domain, username, password):
                    # Also cache in memory
                    self.memory_provider.store_credentials(domain, username, password)
                    return True
            except Exception:
                continue
        
        # Fallback to memory only
        return self.memory_provider.store_credentials(domain, username, password)
    
    def test_credentials_available(self, domain: str) -> bool:
        """Test if credentials are available from any provider."""
        for provider in self.providers:
            try:
                if provider.test_credentials_available(domain):
                    return True
            except Exception:
                continue
        return False
    
    @staticmethod
    def get_domain_from_hostname(hostname: str) -> str:
        """Extract domain from hostname."""
        if '.' in hostname:
            parts = hostname.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
        return hostname
    
    def authenticate_domain(self, domain: str) -> bool:
        """Interactive authentication for a domain."""
        print(f"Authenticating for domain: {domain}")
        
        username = input("Username: ").strip()
        if not username:
            return False
        
        password = getpass.getpass("Password: ")
        if not password:
            return False
        
        # Store in secure provider
        success = self.store_credentials(domain, username, password)
        
        # Clear password from memory immediately
        password = None
        
        if success:
            print(f"Credentials stored securely for {domain}")
        else:
            print(f"Failed to store credentials for {domain}")
        
        return success


# Global credential manager instance
credential_manager = CredentialManager()


def authenticate_domain(hostname_or_domain: str) -> bool:
    """Authenticate and store credentials for a domain."""
    domain = credential_manager.get_domain_from_hostname(hostname_or_domain)
    return credential_manager.authenticate_domain(domain)


def get_credentials_from_keychain(domain: str) -> Optional[Tuple[str, str]]:
    """Legacy function for backward compatibility."""
    return credential_manager.get_credentials(domain)


def test_credentials_available(hostname: str) -> bool:
    """Legacy function for backward compatibility."""
    domain = credential_manager.get_domain_from_hostname(hostname)
    return credential_manager.test_credentials_available(domain)


def get_domain_from_hostname(hostname: str) -> str:
    """Legacy function for backward compatibility."""
    return credential_manager.get_domain_from_hostname(hostname)
