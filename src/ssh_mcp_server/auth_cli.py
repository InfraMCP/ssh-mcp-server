#!/usr/bin/env python3
"""SSH MCP Server Authentication CLI."""

import sys
import argparse
from .credentials import credential_manager


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="SSH MCP Server Authentication Management",
        prog="ssh-mcp-auth"
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Add domain authentication
    auth_parser = subparsers.add_parser('add', help='Add domain credentials')
    auth_parser.add_argument('domain', help='Domain to authenticate (e.g., vocus.local)')
    
    # Test domain credentials
    test_parser = subparsers.add_parser('test', help='Test domain credentials')
    test_parser.add_argument('domain', help='Domain to test')
    
    # List available domains
    list_parser = subparsers.add_parser('list', help='List stored domains')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    if args.command == 'add':
        success = credential_manager.authenticate_domain(args.domain)
        return 0 if success else 1
    
    elif args.command == 'test':
        available = credential_manager.test_credentials_available(args.domain)
        if available:
            print(f"✓ Credentials available for {args.domain}")
            return 0
        else:
            print(f"✗ No credentials found for {args.domain}")
            return 1
    
    elif args.command == 'list':
        print("Available credential providers:")
        for i, provider in enumerate(credential_manager.providers):
            print(f"  {i+1}. {provider.__class__.__name__}")
        return 0
    
    return 1


if __name__ == "__main__":
    sys.exit(main())
