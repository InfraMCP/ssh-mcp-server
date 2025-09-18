"""Tests for SSH MCP server functionality."""

import pytest
from unittest.mock import patch, MagicMock
from ssh_mcp_server.server import execute_ssh, get_system_info


class TestSSHServer:
    """Test SSH server functionality."""
    
    @patch('ssh_mcp_server.server.credential_manager')
    @patch('paramiko.SSHClient')
    def test_execute_ssh_success(self, mock_ssh_client, mock_credential_manager):
        """Test successful SSH command execution."""
        # Mock credential manager
        mock_credential_manager.test_credentials_available.return_value = True
        mock_credential_manager.get_domain_from_hostname.return_value = 'vocus.local'
        mock_credential_manager.get_credentials.return_value = ('testuser', 'testpass')
        
        # Mock SSH client
        mock_ssh = MagicMock()
        mock_ssh_client.return_value = mock_ssh
        
        # Mock command execution
        mock_stdout = MagicMock()
        mock_stdout.read.return_value = b'command output'
        mock_stdout.channel.recv_exit_status.return_value = 0
        
        mock_stderr = MagicMock()
        mock_stderr.read.return_value = b''
        
        mock_ssh.exec_command.return_value = (None, mock_stdout, mock_stderr)
        
        # Execute test
        result = execute_ssh('test.vocus.local', 'ls -la')
        
        # Verify result
        assert result['success'] is True
        assert result['exit_code'] == 0
        assert result['stdout'] == 'command output'
        assert result['hostname'] == 'test.vocus.local'
        assert result['command'] == 'ls -la'
    
    @patch('ssh_mcp_server.server.credential_manager')
    def test_execute_ssh_no_credentials(self, mock_credential_manager):
        """Test SSH execution when no credentials available."""
        mock_credential_manager.test_credentials_available.return_value = False
        mock_credential_manager.get_domain_from_hostname.return_value = 'vocus.local'
        
        result = execute_ssh('test.vocus.local', 'ls -la')
        
        assert 'error' in result
        assert 'No credentials found' in result['error']
    
    @patch('ssh_mcp_server.server.credential_manager')
    @patch('paramiko.SSHClient')
    def test_execute_ssh_connection_failure(self, mock_ssh_client, mock_credential_manager):
        """Test SSH execution with connection failure."""
        # Mock credential manager
        mock_credential_manager.test_credentials_available.return_value = True
        mock_credential_manager.get_domain_from_hostname.return_value = 'vocus.local'
        mock_credential_manager.get_credentials.return_value = ('testuser', 'testpass')
        
        # Mock SSH client to raise exception
        mock_ssh = MagicMock()
        mock_ssh_client.return_value = mock_ssh
        mock_ssh.connect.side_effect = Exception('Connection failed')
        
        result = execute_ssh('test.vocus.local', 'ls -la')
        
        assert 'error' in result
        assert 'SSH connection failed' in result['error']
    
    @patch('ssh_mcp_server.server.execute_ssh')
    def test_get_system_info(self, mock_execute_ssh):
        """Test system info retrieval."""
        mock_execute_ssh.return_value = {
            'success': True,
            'stdout': 'Linux test 5.4.0 x86_64'
        }
        
        result = get_system_info('test.vocus.local')
        
        assert result['success'] is True
        mock_execute_ssh.assert_called_once_with(
            'test.vocus.local',
            'uname -a && uptime && df -h / && free -h'
        )
