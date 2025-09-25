#!/usr/bin/env python3
"""SSH MCP Server Authentication CLI."""

import sys
import argparse
from .credentials import authenticate_domain, test_credentials_available


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
    _ = subparsers.add_parser('list', help='List stored domains')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if args.command == 'add':
        success = authenticate_domain(args.domain)
        return 0 if success else 1
    if args.command == 'test':
        available = test_credentials_available(args.domain)
        if available:
            print(f"✓ Credentials available for {args.domain}")
            return 0
        print(f"✗ No credentials found for {args.domain}")
        return 1
    if args.command == 'list':
        print("Available credential providers:")
        print("  1. macOS Keychain")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
