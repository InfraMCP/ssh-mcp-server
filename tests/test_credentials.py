"""Tests for credential management."""

import os
import pytest
from unittest.mock import patch, MagicMock
from ssh_mcp_server.credentials import (
    EnvironmentProvider,
    MacOSKeychainProvider,
    CredentialManager
)


class TestEnvironmentProvider:
    """Test environment variable credential provider."""
    
    def test_get_credentials_success(self):
        """Test successful credential retrieval from environment."""
        provider = EnvironmentProvider()
        
        with patch.dict(os.environ, {
            'SSH_USERNAME_VOCUS_LOCAL': 'testuser',
            'SSH_PASSWORD_VOCUS_LOCAL': 'testpass'
        }):
            credentials = provider.get_credentials('vocus.local')
            assert credentials == ('testuser', 'testpass')
    
    def test_get_credentials_missing(self):
        """Test credential retrieval when variables are missing."""
        provider = EnvironmentProvider()
        credentials = provider.get_credentials('nonexistent.domain')
        assert credentials is None
    
    def test_test_credentials_available(self):
        """Test credential availability check."""
        provider = EnvironmentProvider()
        
        with patch.dict(os.environ, {
            'SSH_USERNAME_VOCUS_LOCAL': 'testuser',
            'SSH_PASSWORD_VOCUS_LOCAL': 'testpass'
        }):
            assert provider.test_credentials_available('host.vocus.local') is True
            assert provider.test_credentials_available('host.other.domain') is False


class TestMacOSKeychainProvider:
    """Test macOS Keychain credential provider."""
    
    def test_get_domain_from_hostname(self):
        """Test domain extraction from hostname."""
        assert MacOSKeychainProvider.get_domain_from_hostname('host.vocus.local') == 'vocus.local'
        assert MacOSKeychainProvider.get_domain_from_hostname('server.retail.local') == 'retail.local'
        assert MacOSKeychainProvider.get_domain_from_hostname('simple') == 'simple'
    
    @patch('subprocess.run')
    def test_get_credentials_success(self, mock_run):
        """Test successful credential retrieval from keychain."""
        provider = MacOSKeychainProvider()
        
        # Mock successful subprocess calls
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout='testuser\n'),  # username
            MagicMock(returncode=0, stdout='testpass\n')   # password
        ]
        
        credentials = provider.get_credentials('vocus.local')
        assert credentials == ('testuser', 'testpass')
    
    @patch('subprocess.run')
    def test_get_credentials_failure(self, mock_run):
        """Test credential retrieval failure."""
        provider = MacOSKeychainProvider()
        
        # Mock failed subprocess call
        mock_run.return_value = MagicMock(returncode=1)
        
        credentials = provider.get_credentials('vocus.local')
        assert credentials is None


class TestCredentialManager:
    """Test credential manager."""
    
    def test_initialization(self):
        """Test credential manager initialization."""
        manager = CredentialManager()
        assert len(manager.providers) >= 1  # At least environment provider
    
    @patch.dict(os.environ, {
        'SSH_USERNAME_VOCUS_LOCAL': 'testuser',
        'SSH_PASSWORD_VOCUS_LOCAL': 'testpass'
    })
    def test_get_credentials(self):
        """Test credential retrieval through manager."""
        manager = CredentialManager()
        credentials = manager.get_credentials('vocus.local')
        assert credentials == ('testuser', 'testpass')
    
    def test_get_credentials_none_available(self):
        """Test credential retrieval when none available."""
        manager = CredentialManager()
        credentials = manager.get_credentials('nonexistent.domain')
        assert credentials is None
