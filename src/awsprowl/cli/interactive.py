#!/usr/bin/env python3
"""Interactive CLI shell for awsProwl - Following Prowl's main.py patterns."""

from __future__ import annotations

import asyncio
import copy
import importlib
import json
import os
import readline
import re
import shlex
import subprocess
import sys
import time
import traceback
import argparse
import uuid
from pathlib import Path
from typing import List, Optional, Any, Dict, Union, Tuple, Callable

from rich.console import Console

from awsprowl.core.config import AWSConfig, get_config, load_config, save_config
from awsprowl.core.auth import AWSAuthManager, create_auth_manager, AWSCredentials
from awsprowl.core.logging import get_logger, setup_logging
from awsprowl.analysis.findings import FindingCollection, Finding, Severity, FindingCategory, ResourceType

log = get_logger(__name__)

# Arbitrary number for history length
readline.set_history_length(200)

# History file location
HISTORY_FILE = Path.home() / ".awsprowl_history"
if HISTORY_FILE.exists() and os.access(HISTORY_FILE, os.R_OK):
    try:
        readline.read_history_file(str(HISTORY_FILE))
    except (OSError, IOError) as e:
        # Ignore readline history errors (common in headless/CI environments)
        pass


def load_categories() -> set:
    """Load categories from available scanner modules."""
    categories = set()
    # Scan modules in awsprowl.aws and analysis
    for scanner_dir in [Path(__file__).parent.parent / "aws", Path(__file__).parent.parent.parent / "analysis"]:
        if scanner_dir.exists():
            for file in scanner_dir.glob("*.py"):
                if file.name not in ("__init__.py", "base.py", "orchestrator.py"):
                    module_name = file.stem
                    categories.add(module_name)
    # Add cross-service modules
    cross_modules = ['search_encryption', 'search_public', 'search_privesc', 'search_secrets']
    for mod in cross_modules:
        categories.add(mod)
    return categories


def display_awsprowl_help():
    """Display the main help text."""
    print("""
    awsProwl - AWS Security Research Tool for CTFs and Authorized Testing
    Stalk the Cloud 🔍

    This is the interactive shell for awsProwl. It provides a command-line interface
    for running security scans, managing AWS credentials, and exploring findings.

    Commands:
        run/exec/use <module>       Execute a scanner module
        list/ls                     List all available modules
        modules                     Show ALL modules across all services
        modules <service>           Show modules for specific service (e.g., 'modules iam')
        search <term>               Search modules by name or category
        info <module>               Show detailed information about a module
        help                        Display this help page
        help <module>               Display help for a specific module
        whoami                      Display current AWS caller identity
        data                        Display all collected data in this session
        data <service>              Display data for a specific service
        services                    Display services with collected data
        regions                     Display all valid AWS regions
        set_regions <region>...     Set default regions for this session
        update_regions              Update regions database from AWS
        set_ua_suffix [<suffix>]    Set user agent suffix for API calls
        unset_ua_suffix             Remove user agent suffix
        set_keys                    Add/set AWS keys for this session
        swap_keys                   Switch to different AWS keys
        assume_role <role_arn>      Assume an IAM role
        export_keys                 Export active keys to AWS CLI config
        sessions                    List all saved sessions
        swap_session <name>         Switch to a different session
        delete_session              Delete a session
        aws <command>               Run AWS CLI command with current credentials
        console                     Generate AWS Console login URL
        clear                       Clear the terminal
        history                     Show command history
        exit/quit                   Exit awsProwl

    Module Examples:
        run iam                     # Run IAM scanner
        run ec2                     # Run EC2 scanner
        run s3                      # Run S3 scanner
        run lambda                  # Run Lambda scanner
        run sts                     # Run STS scanner
        run iam_check_mfa           # Run IAM MFA check (analysis)
        run ec2_check_public_ips    # Run EC2 public IP check (analysis)
        run s3_check_encryption     # Run S3 encryption check (analysis)
        run search_encryption       # Search for unencrypted resources
        run search_public           # Search for publicly accessible resources
        run search_privesc          # Search for privilege escalation paths
        run search_secrets          # Search for exposed secrets

    Keyboard Shortcuts:
        Ctrl+C                      Stop current module, return to prompt
        Ctrl+C (twice at prompt)    Exit awsProwl
        Tab                         Auto-complete commands and modules
    """)


def import_module_by_name(module_name: str, include: List[str] = []) -> Any:
    """Import a module by name, following Prowl's pattern."""
    # Try analysis modules first
    for base_path in ["awsprowl.analysis", "awsprowl.aws"]:
        try:
            module_path = f"{base_path}.{module_name}"
            module = __import__(module_path, globals(), locals(), include, 0)
            importlib.reload(module)
            return module
        except ImportError:
            continue
    return None


class InteractiveShell:
    """Main interactive shell class following Prowl's Main class patterns."""

    COMMANDS = [
        'assume_role', 'aws', 'console', 'data', 'delete_session', 'exec', 'exit',
        'export_keys', 'help', 'history', 'info', 'list', 'list_sessions', 'ls', 'modules', 'quit',
        'regions', 'run', 'search', 'services', 'sessions', 'set_keys', 'set_regions',
        'set_ua_suffix', 'swap_keys', 'swap_session', 'unset_ua_suffix', 'update_regions',
        'use', 'whoami', 'clear', 'load_commands_file'
    ]

    INTERRUPT_TIMEOUT = 2.0

    def __init__(self):
        self.config = get_config()
        self.auth_manager: Optional[AWSAuthManager] = None
        self.current_session_name = "default"
        self.running_module_names: List[str] = []
        self.CATEGORIES: set = load_categories()
        self.session_data: Dict[str, Any] = {}
        self.session_regions: List[str] = ["all"]
        self.user_agent_suffix: Optional[str] = None
        self.boto_user_agent: Optional[str] = None

        # Keyboard interrupt handling state
        self._module_running: bool = False
        self._interrupt_count: int = 0
        self._last_interrupt_time: float = 0.0

        # Module categories mapping - keys match actual module file names
        self.MODULE_CATEGORIES = {
            # AWS service scanners (match file names in awsprowl/aws/)
            'iam': 'aws_service',
            'ec2': 'aws_service',
            's3': 'aws_service',
            'lambda_': 'aws_service',  # file is lambda_.py
            'ecs': 'aws_service',
            'secrets': 'aws_service',  # file is secrets.py (for secretsmanager)
            'sns': 'aws_service',
            'beanstalk': 'aws_service',
            'cognito': 'aws_service',
            'sts': 'aws_service',
            'rds': 'aws_service',
            'dynamodb': 'aws_service',
            'cloudfront': 'aws_service',
            'kms': 'aws_service',
            'eks': 'aws_service',
            'organizations': 'aws_service',
            # Analysis modules (match file names in awsprowl/analysis/)
            'privesc': 'analysis',
            'attack_path': 'analysis',
            'compliance': 'analysis',
            'network_analyzer': 'analysis',
            'secret_hunter': 'analysis',
            'cicd_scanner': 'analysis',
            'analytics_scanner': 'analysis',
            # Cross-service search modules
            'search_encryption': 'cross_service',
            'search_public': 'cross_service',
            'search_privesc': 'cross_service',
            'search_secrets': 'cross_service',
        }

    def _reset_interrupt_state(self) -> None:
        self._interrupt_count = 0
        self._last_interrupt_time = 0.0

    def _record_interrupt(self) -> int:
        current_time = time.time()
        if current_time - self._last_interrupt_time > self.INTERRUPT_TIMEOUT:
            self._interrupt_count = 1
        else:
            self._interrupt_count += 1
        self._last_interrupt_time = current_time
        return self._interrupt_count

    def log_error(self, text: str, exception_info: str = None, local_data: List = None, global_data: List = None) -> None:
        """Write an error to the log file."""
        timestamp = time.strftime('%F %T', time.gmtime())
        session_tag = f'({self.current_session_name})'

        try:
            log_file_path = self.config.get_data_dir() / "error_log.txt"
            log_file_path.parent.mkdir(parents=True, exist_ok=True)

            print(f'\n[{timestamp}] awsProwl encountered an error. Check {log_file_path} for details.')

            formatted_text = f'[{timestamp}] {session_tag}: {text}\n'

            if local_data is not None and global_data is not None:
                formatted_text += f'\nLAST TWO FRAMES LOCALS DATA:\n    {chr(10) + "    ".join(local_data[:2])}\n'
                formatted_text += f'\nLAST TWO FRAMES GLOBALS DATA:\n    {chr(10) + "    ".join(global_data[:2])}\n'

            formatted_text += '\n'

            with open(log_file_path, 'a+') as log_file:
                log_file.write(formatted_text)

        except Exception as error:
            print(f'Error while saving exception information: {error}')
            raise

    def read_log_file(self):
        """Read and display the error log file."""
        log_file_path = self.config.get_data_dir() / "error_log.txt"
        if log_file_path.exists():
            with open(log_file_path, 'r') as log_file:
                print(log_file.read())
        else:
            print('No error log file found.')

    def print(self, message: Union[dict, list, str, Exception] = '', output='both', output_type='plain', is_cmd=False) -> bool:
        """Print to screen and/or log file with module prefix."""
        # Indent output from a command
        if is_cmd is False:
            if isinstance(message, dict):
                if 'SecretAccessKey' in message:
                    message = copy.deepcopy(message)
                    truncated_key = message['SecretAccessKey'][0:int(len(message['SecretAccessKey']) / 2)]
                    message['SecretAccessKey'] = f'{truncated_key}{"*" * int(len(message["SecretAccessKey"]) / 2)}'
                message = json.dumps(message, indent=2, default=str)
            elif isinstance(message, list):
                message = json.dumps(message, indent=2, default=str)

        # Prepend running module name
        if len(self.running_module_names) > 0 and isinstance(message, str):
            split_message = message.split('\n')
            for index, fragment in enumerate(split_message):
                if re.sub(r'\s', '', fragment):
                    split_message[index] = f'[{self.running_module_names[-1]}] {fragment}'
                    break
            message = '\n'.join(split_message)

        if output == 'both' or output == 'file':
            if output_type == 'plain':
                log_file_path = self.config.get_data_dir() / "cmd_log.txt"
                log_file_path.parent.mkdir(parents=True, exist_ok=True)
                with open(log_file_path, 'a+') as text_file:
                    text_file.write(f'{message}\n')

        if output == 'both' or output == 'screen':
            print(message)

        return True

    def input(self, message: str, output='both', output_type='plain') -> str:
        """Get input from user with logging."""
        if len(self.running_module_names) > 0 and isinstance(message, str):
            split_message = message.split('\n')
            for index, fragment in enumerate(split_message):
                if re.sub(r'\s', '', fragment):
                    split_message[index] = f'[{self.running_module_names[-1]}] {fragment}'
                    break
            message = '\n'.join(split_message)

        res = input(message)
        if output == 'both':
            if output_type == 'plain':
                log_file_path = self.config.get_data_dir() / "cmd_log.txt"
                log_file_path.parent.mkdir(parents=True, exist_ok=True)
                with open(log_file_path, 'a+') as file:
                    file.write(f'{message} {res}\n')
        return res

    def validate_region(self, region: str) -> bool:
        """Validate if region is in the allowed list."""
        if region in self.get_regions('all'):
            return True
        return False

    def get_regions(self, service: str, check_session: bool = True) -> List[Optional[str]]:
        """Get valid regions for a service."""
        service = service.lower()

        # Try to get regions from boto3
        try:
            if self.auth_manager:
                session = self.auth_manager.get_session()
                regions = session.get_available_regions(service)
                if regions:
                    valid_regions = regions
                else:
                    valid_regions = self._get_default_regions()
            else:
                valid_regions = self._get_default_regions()
        except Exception:
            valid_regions = self._get_default_regions()

        if 'all' not in self.session_regions:
            if check_session:
                return [region for region in valid_regions if region in self.session_regions]
            else:
                return self.session_regions
        else:
            return valid_regions

    def _get_default_regions(self) -> List[str]:
        """Get default AWS regions."""
        return [
            "us-east-1", "us-east-2", "us-west-1", "us-west-2",
            "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
            "ap-southeast-1", "ap-southeast-2", "ap-northeast-1", "ap-northeast-2", "ap-south-1",
            "ca-central-1", "sa-east-1"
        ]

    def display_history(self):
        """Display command history."""
        for i in range(readline.get_current_history_length()):
            print(f"{i+1:>3}: {readline.get_history_item(i + 1)}")

    def display_all_regions(self):
        """Display all valid AWS regions."""
        for region in sorted(self.get_regions('all')):
            print(f'  {region}')

    def get_boto_session(self, region: str = None):
        """Get a boto3 session with current credentials."""
        if self.auth_manager is None:
            self.auth_manager = create_auth_manager(self.config.aws)
        return self.auth_manager.get_session()

    def get_boto3_client(self, service: str, region: Optional[str] = None):
        """Get a boto3 client."""
        if self.auth_manager is None:
            self.auth_manager = create_auth_manager(self.config.aws)
        return self.auth_manager.get_client(service, region=region)

    def print_web_console_url(self) -> None:
        """Generate and print AWS Console login URL."""
        try:
            if self.auth_manager is None:
                self.auth_manager = create_auth_manager(self.config.aws)

            sts = self.auth_manager.get_client('sts')
            creds = self.auth_manager.load_credentials()

            if creds.session_token:
                res = {
                    'Credentials': {
                        'AccessKeyId': creds.access_key,
                        'SecretAccessKey': creds.secret_key,
                        'SessionToken': creds.session_token
                    }
                }
            else:
                res = sts.get_federation_token(
                    Name=self.current_session_name,
                    Policy=json.dumps({
                        'Version': '2012-10-17',
                        'Statement': [{
                            'Effect': 'Allow',
                            'Action': '*',
                            'Resource': '*'
                        }]
                    })
                )

            params = {
                'Action': 'getSigninToken',
                'Session': json.dumps({
                    'sessionId': res['Credentials']['AccessKeyId'],
                    'sessionKey': res['Credentials']['SecretAccessKey'],
                    'sessionToken': res['Credentials']['SessionToken']
                })
            }

            import requests
            fed_resp = requests.get(url='https://signin.aws.amazon.com/federation', params=params)
            signin_token = fed_resp.json()['SigninToken']

            params = {
                'Action': 'login',
                'Issuer': self.current_session_name,
                'Destination': 'https://console.aws.amazon.com/console/home',
                'SigninToken': signin_token
            }

            import urllib.parse
            url = 'https://signin.aws.amazon.com/federation?' + urllib.parse.urlencode(params)

            print(f'Paste the following URL into a web browser to login as session {self.current_session_name}...\n')
            print(url)

        except Exception as e:
            self.print(f'Error generating console URL: {e}')

    def fetch_data(self, data: List[str], module: str, args: str, force=False) -> bool:
        """Fetch prerequisite data by running a module."""
        # Simplified - just return True for now
        return True

    def parse_command(self, command: str) -> None:
        """Parse and execute a command."""
        command = command.strip()

        if not command:
            return

        # Handle aws command specially
        if command.split(' ')[0] == 'aws':
            self.run_aws_cli_command(command)
            return

        try:
            cmd_parts = shlex.split(command)
        except ValueError:
            self.print('  Error: Unbalanced quotes in command')
            return

        if not cmd_parts or cmd_parts[0] == '':
            return

        cmd = cmd_parts[0].lower()

        # Command routing
        if cmd == 'data':
            self.parse_data_command(cmd_parts)
        elif cmd in ['sessions', 'list_sessions']:
            self.list_sessions()
        elif cmd == 'swap_session':
            self.check_sessions(cmd_parts)
        elif cmd == 'delete_session':
            self.delete_session()
        elif cmd == 'export_keys':
            self.export_keys(cmd_parts)
        elif cmd == 'help':
            self.parse_help_command(cmd_parts)
        elif cmd == 'info':
            self.parse_info_command(cmd_parts)
        elif cmd in ('modules', 'all-modules', 'list-modules'):
            self.parse_modules_command(cmd_parts)
        elif cmd in ['console', 'open_console']:
            self.print_web_console_url()
        elif cmd == 'assume_role':
            self.assume_role(cmd_parts)
        elif cmd in ['list', 'ls']:
            self.parse_list_command(cmd_parts)
        elif cmd == 'load_commands_file':
            self.parse_commands_from_file(cmd_parts)
        elif cmd == 'regions':
            self.display_all_regions()
        elif cmd == 'history':
            self.display_history()
        elif cmd in ['run', 'exec', 'use']:
            self.parse_exec_module_command(cmd_parts)
        elif cmd == 'search':
            self.parse_search_command(cmd_parts)
        elif cmd == 'services':
            self.print_all_service_data()
        elif cmd == 'set_keys':
            self.set_keys()
        elif cmd == 'set_regions':
            self.parse_set_regions_command(cmd_parts)
        elif cmd == 'swap_keys':
            self.swap_keys(cmd_parts[1] if len(cmd_parts) > 1 else None)
        elif cmd == 'update_regions':
            self.update_regions()
        elif cmd == 'set_ua_suffix':
            self.parse_set_ua_suffix_command(cmd_parts)
        elif cmd == 'unset_ua_suffix':
            self.unset_user_agent_suffix()
        elif cmd == 'whoami':
            self.parse_whoami_command(cmd_parts)
        elif cmd == 'caller-identity':
            self.parse_whoami_command(cmd_parts)
        elif cmd == 'clear':
            os.system("cls" if sys.platform == "win32" else "clear")
        elif cmd == 'debug':
            self.read_log_file()
        elif cmd in ['exit', 'quit']:
            readline.write_history_file(str(HISTORY_FILE))
            self.exit()
        else:
            print('  Error: Unrecognized command')

    def parse_commands_from_file(self, command: List[str]) -> None:
        """Load and execute commands from a file."""
        if len(command) == 1:
            self.display_command_help('load_commands_file')
            return

        commands_file = command[1]
        if not os.path.isfile(commands_file):
            self.display_command_help('load_commands_file')
            return

        with open(commands_file, 'r') as f:
            commands = f.readlines()
            for cmd in commands:
                cmd = cmd.strip()
                if cmd:
                    self.print(f"Executing: {cmd}")
                    self.parse_command(cmd)

    def parse_data_command(self, command: List[str]) -> None:
        """Parse and execute data command."""
        if len(command) == 1:
            self.print('\nSession data:')
            for key, value in self.session_data.items():
                if value:
                    self.print(f'  {key}: {json.dumps(value, indent=2, default=str)}')
        else:
            service = command[1].upper()
            if service in self.session_data:
                self.print(json.dumps(self.session_data[service], indent=2, default=str))
            else:
                self.print(f'  Service {service} not found.')

    def parse_help_command(self, command: List[str]) -> None:
        """Parse and execute help command."""
        if len(command) <= 1:
            display_awsprowl_help()
        elif command[1] in self.COMMANDS:
            self.display_command_help(command[1])
        else:
            self.display_module_help(command[1])

    def parse_info_command(self, command: List[str]) -> None:
        """Parse and execute info command to show module details."""
        if len(command) < 2:
            print('  Usage: info <module_name>')
            print('  Example: info iam_enum_users, info check-mfa, info iam_exploit_create_user')
            return

        module_name = command[1]
        
        # Import the module registry
        try:
            from awsprowl.modules import get_module, ModuleCategory, ModuleRisk, MODULE_REGISTRY
            from awsprowl.cli.ui.tui import SERVICE_MODULES, ATTACK_MODULES
        except ImportError:
            print('  Error: Could not import module registry')
            return
        
        module_meta = get_module(module_name)
        
        if not module_meta:
            # Search in SERVICE_MODULES (like check-mfa)
            found_action = None
            found_service = None
            for service, modules in SERVICE_MODULES.items():
                for m in modules:
                    if m.name == module_name:
                        found_action = m
                        found_service = service
                        break
                if found_action:
                    break
            
            # Also check ATTACK_MODULES
            if not found_action:
                for service, modules in ATTACK_MODULES.items():
                    for m in modules:
                        if m.name == module_name:
                            found_action = m
                            found_service = service
                            break
                    if found_action:
                        break
            
            if found_action:
                self.display_module_info_from_action(found_service, found_action)
                return
            
            # Search in MODULE_REGISTRY for partial matches
            matches = [m for m in MODULE_REGISTRY.keys() if module_name.lower() in m.lower()]
            if matches:
                print(f'  Module not found: {module_name}')
                print(f'  Did you mean: {", ".join(matches[:5])}')
            else:
                print(f'  Module not found: {module_name}')
                print('  Use "list" or "search" to find available modules')
            return
        
        self.display_module_info(module_meta)

    def parse_modules_command(self, command: List[str]) -> None:
        """Parse and execute modules command to list all modules across all services.
        
        Usage:
            modules                    # List all modules
            modules iam                # List only IAM modules
            modules ec2                # List only EC2 modules
        """
        try:
            from awsprowl.modules import get_module, MODULE_REGISTRY
            from awsprowl.cli.ui.tui import SERVICE_MODULES, ATTACK_MODULES, CATEGORY_MARKERS
        except ImportError:
            print('  Error: Could not import module registry')
            return
        
        # Check if a service filter was provided
        service_filter = None
        if len(command) >= 2:
            service_filter = command[1].lower()
        
        # Get all modules from both SERVICE_MODULES and ATTACK_MODULES
        all_modules = []
        
        # Add SERVICE_MODULES
        for service, modules in SERVICE_MODULES.items():
            if service_filter and service.lower() != service_filter:
                continue
            for m in modules:
                all_modules.append({
                    'name': m.name,
                    'service': service,
                    'category': m.category,
                    'description': m.description,
                    'type': 'service'
                })
        
        # Add ATTACK_MODULES
        for service, modules in ATTACK_MODULES.items():
            if service_filter and service.lower() != service_filter:
                continue
            for m in modules:
                meta = get_module(m.name)
                category = meta.category.value if meta else m.category
                risk = meta.risk.value if meta else getattr(m, 'risk_level', 'unknown')
                destructive = meta.destructive if meta else getattr(m, 'destructive', False)
                all_modules.append({
                    'name': m.name,
                    'service': service,
                    'category': category,
                    'description': m.description,
                    'type': 'attack',
                    'risk': risk,
                    'destructive': destructive
                })
        
        if not all_modules:
            if service_filter:
                print(f'  No modules found for service: {service_filter}')
                available = ", ".join(sorted(set(list(SERVICE_MODULES.keys()) + list(ATTACK_MODULES.keys()))))
                print(f'  Available services: {available}')
            else:
                print('  No modules found')
            return
        
        # Sort by service, then category, then name
        all_modules.sort(key=lambda x: (x['service'], x['category'], x['name']))
        
        # Print summary
        if service_filter:
            print(f'\n  Modules for {service_filter.upper()} ({len(all_modules)} total)\n')
        else:
            print(f'\n  All Modules ({len(all_modules)} total)\n')
        
        # Group by service
        from collections import defaultdict
        by_service = defaultdict(list)
        for m in all_modules:
            by_service[m['service']].append(m)
        
        for service in sorted(by_service.keys()):
            modules = by_service[service]
            print(f'  {service.upper()} ({len(modules)} modules)')
            
            for m in modules:
                cat_marker = CATEGORY_MARKERS.get(m['category'], '[MOD]')
                category_display = f"{cat_marker} {m['category']}"
                
                if m.get('type') == 'attack':
                    risk = m.get('risk', 'unknown').upper()
                    destructive = "Yes" if m.get('destructive', False) else "No"
                    print(f'    {m["name"]:<40} {category_display:<20} Risk: {risk:<8} Destructive: {destructive}  {m["description"][:60]}')
                else:
                    print(f'    {m["name"]:<40} {category_display:<20}  {m["description"][:60]}')
            print()
        
        print('  Use "info <module>" for detailed information about any module')
        print('  Use "run <module>" to execute a module')
        print('  Use "category <type>" to filter by category (enum, exploit, persist, backdoor, exfil, privesc)')
        print('  Use "modules <service>" to filter modules by service (e.g., modules iam)')

    def display_module_info_from_action(self, service: str, action) -> None:
        """Display detailed module information from ModuleAction."""
        print(f'\n  Module: {action.name}')
        print(f'  Service: {service}')
        print(f'  Category: {action.category}')
        print(f'  Risk: {getattr(action, "risk_level", "unknown").upper()}')
        print(f'  Destructive: {"Yes" if getattr(action, "destructive", False) else "No"}')
        print(f'  Requires Confirmation: {"Yes" if getattr(action, "requires_confirmation", False) else "No"}')
        print(f'  Description: {action.description}')
        print()
        
        required_permissions = getattr(action, 'required_permissions', [])
        if required_permissions:
            print('  Required Permissions:')
            for perm in required_permissions:
                print(f'    • {perm}')
            print()
        
        mitre_techniques = getattr(action, 'mitre_techniques', [])
        if mitre_techniques:
            print('  MITRE ATT&CK Techniques:')
            for tech in mitre_techniques:
                print(f'    • {tech}')
            print()
        
        # Usage examples
        print('  Usage Examples:')
        print(f'    run {action.name}')
        if service not in {'iam', 'sts', 'cloudfront', 'organizations'}:
            print(f'    run {service} {action.name} us-east-1')
        if getattr(action, 'requires_confirmation', False) and getattr(action, 'destructive', False):
            print(f'    # Note: Requires typing CONFIRM to execute (destructive)')
        print()

    def display_module_info(self, module_meta) -> None:
            """Display detailed module information."""
            print(f'\n  Module: {module_meta.name}')
            print(f'  Service: {module_meta.supported_services[0] if module_meta.supported_services else "unknown"}')
            print(f'  Category: {module_meta.category.value}')
            print(f'  Risk: {module_meta.risk.value.upper()}')
            print(f'  Destructive: {"Yes" if module_meta.destructive else "No"}')
            print(f'  Requires Confirmation: {"Yes" if module_meta.requires_confirmation else "No"}')
            print(f'  Description: {module_meta.description}')
            print()

            if module_meta.required_permissions:
                print('  Required Permissions:')
                for perm in module_meta.required_permissions:
                    print(f'    • {perm}')
                print()

            if module_meta.mitre_techniques:
                print('  MITRE ATT&CK Techniques:')
                for tech in module_meta.mitre_techniques:
                    print(f'    • {tech}')
                print()

            if module_meta.tags:
                print(f'  Tags: {", ".join(module_meta.tags)}')
                print()

            # Usage examples
            service = module_meta.supported_services[0] if module_meta.supported_services else "unknown"
            print('  Usage Examples:')
            print(f'    run {module_meta.name}')
            if service not in {'iam', 'sts', 'cloudfront', 'organizations'}:
                print(f'    run {service} {module_meta.name} us-east-1')
            if module_meta.requires_confirmation and module_meta.destructive:
                print(f'    # Note: Requires typing CONFIRM to execute (destructive)')
            print()

    def parse_list_command(self, command: List[str]) -> None:
        """Parse and execute list command."""
        if len(command) == 1:
            self.list_modules('')

        elif len(command) == 2:
            if command[1] in ('cat', 'category', 'categories'):
                print("[Categories]:")
                # Show unique categories
                categories = set(self.MODULE_CATEGORIES.values())
                for category in sorted(categories):
                    print(f'    {category}')

        elif len(command) == 3:
            if command[1] in ('cat', 'category'):
                self.list_modules(command[2], by_category=True)

    def parse_exec_module_command(self, command: List[str]) -> None:
        """Parse and execute run/exec/use command."""
        if len(command) > 1 and command[-1] == "-h":
            self.parse_help_command(command)
        elif len(command) > 1:
            self.exec_module(command)
        else:
            print('The run/exec/use command requires a module name. Try using the module search function.')

    def parse_search_command(self, command: List[str]) -> None:
        """Parse and execute search command."""
        if len(command) == 1:
            self.list_modules('')
        elif len(command) == 2:
            self.list_modules(command[1])
        elif len(command) >= 3:
            if command[1] in ('cat', 'category'):
                self.list_modules(command[2], by_category=True)

    def parse_set_regions_command(self, command: List[str]) -> None:
        """Parse and execute set_regions command."""
        if len(command) > 1:
            for region in command[1:]:
                if region.lower() == 'all':
                    self.session_regions = ['all']
                    print('  Region set reset to default (all regions).')
                    return
                if self.validate_region(region) is False:
                    print(f'  {region} is not a valid region. Session regions not changed.')
                    return
            self.session_regions = command[1:]
            print(f'  Session regions changed: {self.session_regions}')
        else:
            print('  Error: set_regions requires either "all" or at least one region.')

    def parse_set_ua_suffix_command(self, command: List[str]) -> None:
        """Parse and execute set_ua_suffix command."""
        if len(command) == 1:
            user_agent_suffix = f"awsprowl-session-{uuid.uuid4()}"
        elif len(command) == 2:
            user_agent_suffix = command[1]
        else:
            print('  Usage: set_ua_suffix [<suffix>]')
            return
        self.set_user_agent_suffix(user_agent_suffix)
        self.print_user_agent_suffix()

    def set_user_agent_suffix(self, user_agent_suffix: str) -> None:
        self.user_agent_suffix = user_agent_suffix
        self.config.aws.user_agent_extra = user_agent_suffix
        save_config(self.config)

    def unset_user_agent_suffix(self) -> None:
        self.user_agent_suffix = None
        self.config.aws.user_agent_extra = None
        save_config(self.config)

    def print_user_agent_suffix(self) -> None:
        if self.user_agent_suffix:
            print(f"Using user agent suffix: {self.user_agent_suffix}")
        else:
            print("No user agent suffix set.")

    def update_regions(self) -> None:
        """Update regions database from AWS SSM."""
        print("  This requires calls to AWS SSM API. Continue? (y/n) ", end='')
        answer = input().strip().lower()
        if answer == 'y':
            self.print('  Updating region list...')
            try:
                # Use the auth manager to get regions
                if self.auth_manager is None:
                    self.auth_manager = create_auth_manager(self.config.aws)

                client = self.auth_manager.get_client('ssm')
                all_regions = client.get_parameters_by_path(
                    Path='/aws/service/global-infrastructure/regions',
                    Recursive=True
                )
                region_names = [param['Value'] for param in all_regions['Parameters']]

                all_services = client.get_parameters_by_path(
                    Path='/aws/service/global-infrastructure/services',
                    Recursive=True
                )
                service_names = [param['Value'] for param in all_services['Parameters']]

                regions_services = {"all": region_names}

                for service in service_names:
                    try:
                        service_regions = client.get_parameters_by_path(
                            Path=f'/aws/service/global-infrastructure/services/{service}/regions',
                            Recursive=True
                        )
                        regions_services[service] = [param['Value'] for param in service_regions['Parameters']]
                    except Exception:
                        pass

                # Save to config directory
                regions_file = self.config.get_data_dir() / "service_regions.json"
                regions_file.parent.mkdir(parents=True, exist_ok=True)
                with open(regions_file, 'w') as f:
                    json.dump(regions_services, f, indent=4, sort_keys=True)

                self.print('  Region list updated successfully!')
            except Exception as e:
                self.print(f'  Error updating regions: {e}')
        else:
            self.print('  Region list not updated.')

    def print_all_service_data(self, command: List[str] = None) -> None:
        """Print all services with collected data."""
        if self.session_data:
            for service in self.session_data.keys():
                print(f'  {service}')
        else:
            print('  No service data collected yet.')

    def display_command_help(self, command_name: str) -> None:
        """Display help for a specific command."""
        help_text = {
            'list': '\n    list/ls\n        List all modules\n    list cat[egory] [category_name]\n        List modules by category\n',
            'assume_role': '\n    assume_role <role_arn>\n        Assume an IAM role and use temporary credentials\n',
            'aws': '\n    aws <command>\n        Run AWS CLI command with current credentials\n',
            'console': '\n    console\n        Generate AWS Console login URL\n',
            'export_keys': '\n    export_keys\n        Export active credentials to ~/.aws/credentials\n',
            'search': '\n    search <term>\n        Search modules by name\n    search cat[egory] <category>\n        Search modules by category\n',
            'sessions': '\n    sessions/list_sessions\n        List all saved sessions\n',
            'swap_session': '\n    swap_session <name>\n        Switch to a different session\n',
            'delete_session': '\n    delete_session\n        Delete a session\n',
            'help': '\n    help\n        Display all commands\n    help <module>\n        Display module help\n',
            'whoami': '\n    whoami\n        Display current AWS caller identity\n',
            'clear': '\n    clear\n        Clear the terminal\n',
            'data': '\n    data\n        Display all session data\n    data <service>\n        Display data for a service\n',
            'services': '\n    services\n        List services with collected data\n',
            'regions': '\n    regions\n        Display all valid AWS regions\n',
            'update_regions': '\n    update_regions\n        Update regions from AWS SSM\n',
            'set_regions': '\n    set_regions <region> [<region>...]\n        Set default regions for session\n',
            'set_ua_suffix': '\n    set_ua_suffix [<suffix>]\n        Set user agent suffix\n',
            'unset_ua_suffix': '\n    unset_ua_suffix\n        Remove user agent suffix\n',
            'run': '\n    run/exec/use <module>\n        Execute a module\n',
            'set_keys': '\n    set_keys\n        Set AWS credentials\n',
            'swap_keys': '\n    swap_keys [alias]\n        Switch AWS credentials\n',
            'delete_keys': '\n    delete_keys\n        Delete AWS credentials\n',
            'exit': '\n    exit/quit\n        Exit awsProwl\n',
            'load_commands_file': '\n    load_commands_file <file>\n        Execute commands from file\n',
        }
        print(help_text.get(command_name, 'Command help not available.'))

    def display_module_help(self, module_name: str) -> None:
        """Display help for a module."""
        # Map module names to actual file names
        module_file_map = {
            'lambda': 'lambda_',
            'secretsmanager': 'secrets',
        }
        module_file_name = module_file_map.get(module_name, module_name)

        module = import_module_by_name(module_file_name, include=['__doc__', 'SERVICE_NAME', 'REQUIRED_PERMISSIONS'])
        if module:
            doc = module.__doc__ or 'No description available.'

            # Try to get scanner class for AWS service modules
            service_scanners = {
                'iam', 'ec2', 's3', 'lambda', 'ecs', 'secretsmanager', 'sns',
                'beanstalk', 'cognito', 'sts', 'rds', 'dynamodb', 'cloudfront',
                'kms', 'eks', 'organizations'
            }

            if module_name in service_scanners:
                # Map to file name for class lookup
                module_file_map_class = {
                    'lambda': 'lambda_',
                    'secretsmanager': 'secrets',
                }
                class_file_name = module_file_map_class.get(module_name, module_name)
                module_class = import_module_by_name(class_file_name, include=['__doc__'])

                # Special handling for all-caps service names
                if module_name in ['iam', 'sts', 'ec2', 's3', 'sns', 'rds', 'kms', 'eks']:
                    class_name_suffix = module_name.upper()
                else:
                    class_name_suffix = module_name.capitalize()

                scanner_class = getattr(module_class, f'{class_name_suffix}Scanner', None)
                if scanner_class:
                    service_name = scanner_class.SERVICE_NAME
                    perms = scanner_class.REQUIRED_PERMISSIONS
                else:
                    service_name = module_name
                    perms = []
            else:
                service_name = getattr(module, 'SERVICE_NAME', module_name)
                perms = getattr(module, 'REQUIRED_PERMISSIONS', [])

            print(f'\n{module_name} ({service_name}):\n{doc}\n')
            if perms:
                print('Required permissions:')
                for perm in perms:
                    print(f'  {perm}')
            print()
        else:
            # Try cross-service modules
            cross_modules = {
                'search_encryption': 'Search for unencrypted resources across all services',
                'search_public': 'Search for publicly accessible resources across all services',
                'search_privesc': 'Search for privilege escalation paths',
                'search_secrets': 'Search for exposed secrets in resources',
            }
            if module_name in cross_modules:
                print(f'\n{module_name}: {cross_modules[module_name]}\n')
            else:
                print('Module not found. Use "list" to see available modules.')

    def list_modules(self, search_term: str, by_category: bool = False) -> None:
        """List available modules."""
        found = {}

        # Display name mapping
        display_names = {
            'lambda_': 'lambda',
            'secrets': 'secretsmanager',
        }

        # Scan AWS service modules
        aws_dir = Path(__file__).parent.parent / "aws"
        if aws_dir.exists():
            for file in aws_dir.glob("*.py"):
                if file.name in ("__init__.py", "base.py", "orchestrator.py"):
                    continue
                module_name = file.stem
                category = self.MODULE_CATEGORIES.get(module_name, 'aws_service')
                display_name = display_names.get(module_name, module_name)

                if by_category:
                    if search_term.upper() in category.upper():
                        if category not in found:
                            found[category] = []
                        found[category].append(f'  {display_name}')
                elif search_term in display_name or search_term == '':
                    if category not in found:
                        found[category] = []
                    found[category].append(f'  {display_name}')

        # Scan analysis modules
        analysis_dir = Path(__file__).parent.parent / "analysis"
        if analysis_dir.exists():
            for file in analysis_dir.glob("*.py"):
                if file.name in ("__init__.py", "findings.py", "base.py"):
                    continue
                module_name = file.stem
                category = self.MODULE_CATEGORIES.get(module_name, 'analysis')

                if by_category:
                    if search_term.upper() in category.upper():
                        if category not in found:
                            found[category] = []
                        found[category].append(f'  {module_name}')
                elif search_term in module_name or search_term == '':
                    if category not in found:
                        found[category] = []
                    found[category].append(f'  {module_name}')

        # Cross-service search modules
        cross_modules = ['search_encryption', 'search_public', 'search_privesc', 'search_secrets']
        for mod in cross_modules:
            category = 'cross_service'
            if by_category and search_term.upper() in category.upper():
                if category not in found:
                    found[category] = []
                found[category].append(f'  {mod}')
            elif not by_category and (search_term in mod or search_term == ''):
                if category not in found:
                    found[category] = []
                found[category].append(f'  {mod}')

        if found:
            for category in sorted(found.keys()):
                found[category].sort()
                print(f'\n[Category: {category}]\n')
                print('\n'.join(found[category]))
        else:
            print('\nNo modules found.')
        print()

    def exec_module(self, command: List[str]) -> None:
        """Execute a module - following Prowl's pattern with main() and summary() functions."""
        module_name = command[1].lower()

        # Map module names to actual file names
        module_file_map = {
            'lambda': 'lambda_',
            'secretsmanager': 'secrets',
        }
        module_file_name = module_file_map.get(module_name, module_name)

        module = import_module_by_name(module_file_name, include=['main', '__doc__', 'SERVICE_NAME'])

        if module is not None:
            # Log command (like Prowl)
            self.print(f'{self.get_credentials_summary()} ({time.strftime("%a, %d %b %Y %H:%M:%S", time.gmtime())}): {" ".join(command)}',
                       output='file', is_cmd=True)

            self.print(f'  Running module {module_name}...')

            try:
                # Check if module has main function (like Prowl modules)
                if hasattr(module, 'main'):
                    self.running_module_names.append(module_name)
                    self._module_running = True
                    self._reset_interrupt_state()

                    try:
                        # Run the module's main function
                        if asyncio.iscoroutinefunction(module.main):
                            summary_data = asyncio.run(module.main(self.auth_manager, command[2:]))
                        else:
                            summary_data = module.main(self.auth_manager, command[2:])

                        if summary_data is not None:
                            # Try to get summary (like Prowl)
                            if hasattr(module, 'summary'):
                                summary = module.summary(summary_data, self)
                            else:
                                summary = str(summary_data)

                            self.print(f'{module_name} completed.')
                            self.print(f'MODULE SUMMARY:\n\n{summary.strip()}')

                    except SystemExit as e:
                        if 'SIGINT called' in str(e.args):
                            self.print(f'\n[!] Module {module_name} interrupted by user (Ctrl+C).')
                        else:
                            raise
                    finally:
                        self._module_running = False
                        self.running_module_names.pop()
                else:
                    # Check if it's an AWS service scanner module (class-based)
                    service_scanners = {
                        'iam', 'ec2', 's3', 'lambda', 'ecs', 'secretsmanager', 'sns',
                        'beanstalk', 'cognito', 'sts', 'rds', 'dynamodb', 'cloudfront',
                        'kms', 'eks', 'organizations'
                    }
                    if module_name in service_scanners:
                        # Run AWS service scanner
                        summary_data = asyncio.run(self._run_service_scanner(module, module_name, command[2:]))

                        if summary_data is not None:
                            # Create summary for the scanner
                            summary = self._generate_scanner_summary(summary_data)
                            self.print(f'{module_name} completed.')
                            self.print(f'MODULE SUMMARY:\n\n{summary.strip()}')
                    else:
                        self.print(f'Module {module_name} does not have a main() function.')

            except Exception as e:
                self.print(f'Error running module: {e}')
                traceback.print_exc()
        else:
            print(f'Module not found: {module_name}')

    async def _run_service_scanner(self, module, module_name: str, args: List[str]) -> Dict:
        """Run an AWS service scanner and return summary data."""
        if self.auth_manager is None:
            self.auth_manager = create_auth_manager(self.config.aws)

        # Map module name to file name for scanner class lookup
        module_file_map = {
            'lambda': 'Lambda',
            'secretsmanager': 'Secrets',
        }
        class_name_suffix = module_file_map.get(module_name, module_name.capitalize())

        # Parse args for regions
        import argparse
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument('--region', action='append', help='Region to scan (can be specified multiple times)')
        parser.add_argument('--regions', nargs='+', help='Regions to scan')
        parser.add_argument('--all-regions', action='store_true', help='Scan all regions')
        parsed_args, _ = parser.parse_known_args(args)

        # Determine regions to scan
        if parsed_args.all_regions:
            scan_regions = self.get_regions('all', check_session=False)
        elif parsed_args.regions:
            scan_regions = parsed_args.regions
        elif parsed_args.region:
            scan_regions = parsed_args.region
        else:
            # Default to session regions or us-east-1
            if 'all' in self.session_regions:
                scan_regions = self.get_regions('all', check_session=False)
            else:
                scan_regions = self.session_regions if self.session_regions != ['all'] else ['us-east-1']

        # Handle global services (IAM, STS, CloudFront, etc.)
        global_services = {'iam', 'sts', 'cloudfront', 'organizations'}
        if module_name in global_services:
            scan_regions = ['us-east-1']  # Global services use us-east-1

        self.print(f'  Scanning {module_name.upper()} in regions: {", ".join(scan_regions)}')

        # Get the scanner class
        scanner_class = getattr(module, f'{class_name_suffix}Scanner', None)
        if not scanner_class:
            # Try to find it
            for attr in dir(module):
                if attr.endswith('Scanner') and module_name.lower() in attr.lower():
                    scanner_class = getattr(module, attr)
                    break

        if not scanner_class:
            self.print(f'  Error: Could not find scanner class for {module_name}')
            return {'error': 'Scanner class not found'}

        # Create scanner instance
        scanner = scanner_class(self.auth_manager)

        # Run scan
        all_findings = []
        total_resources = 0
        scan_id = f"scan-{module_name}-{time.strftime('%Y%m%d-%H%M%S')}"

        for region in scan_regions:
            if module_name not in global_services:
                scanner.region = region
                scanner._client = None  # Reset client for new region

            self.print(f'  Scanning {region}...')
            result = await scanner.scan(scan_id, all_findings)
            total_resources += result.resources_found

        # Store findings in session data
        service_key = module_name.upper()
        if service_key not in self.session_data:
            self.session_data[service_key] = {}
        self.session_data[service_key]['findings'] = all_findings
        self.session_data[service_key]['resources_scanned'] = total_resources
        self.session_data[service_key]['regions_scanned'] = scan_regions

        return {
            'service': module_name,
            'regions': scan_regions,
            'resources_found': total_resources,
            'findings_count': len(all_findings),
            'findings': all_findings
        }

    def _generate_scanner_summary(self, summary_data: Dict) -> str:
        """Generate a Prowl-style summary for a service scanner."""
        if 'error' in summary_data:
            return f"Error: {summary_data['error']}"

        lines = []
        lines.append(f"  Service: {summary_data['service'].upper()}")
        lines.append(f"  Regions scanned: {', '.join(summary_data['regions'])}")
        lines.append(f"  Resources found: {summary_data['resources_found']}")
        lines.append(f"  Findings: {summary_data['findings_count']}")

        if summary_data['findings_count'] > 0:
            lines.append("")
            lines.append("  Findings by severity:")
            severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for finding in summary_data['findings']:
                severity = finding.get('severity', 'info').lower()
                if severity in severity_counts:
                    severity_counts[severity] += 1

            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                if severity_counts[severity] > 0:
                    lines.append(f"    {severity.capitalize()}: {severity_counts[severity]}")

            lines.append("")
            lines.append("  Top findings:")
            for finding in summary_data['findings'][:5]:
                severity = finding.get('severity', 'info').upper()
                title = finding.get('title', 'Unknown')
                resource = finding.get('resource_id', 'N/A')
                lines.append(f"    [{severity}] {title} ({resource})")

            if summary_data['findings_count'] > 5:
                lines.append(f"    ... and {summary_data['findings_count'] - 5} more findings")

        return '\n'.join(lines)

    def get_credentials_summary(self) -> str:
        """Get summary of current credentials."""
        if self.auth_manager and self.auth_manager.credentials:
            return self.auth_manager.credentials.access_key[:8] + "****"
        return "No Keys Set"

    def print_key_info(self):
        """Print current key/caller identity info."""
        try:
            if self.auth_manager is None:
                self.auth_manager = create_auth_manager(self.config.aws)
            identity = self.auth_manager.get_caller_identity()
            self.print(json.dumps(identity, indent=2))
        except Exception as e:
            self.print(f'Error getting caller identity: {e}')

    def parse_whoami_command(self, command: List[str]) -> None:
        """Display AWS caller identity."""
        try:
            if self.auth_manager is None:
                self.auth_manager = create_auth_manager(self.config.aws)
            identity = self.auth_manager.get_caller_identity()
            self.print(json.dumps(identity, indent=2))
        except Exception as e:
            self.print(f'Error getting caller identity: {e}')

    def set_keys(self, key_alias: str = None, access_key_id: str = None, secret_access_key: str = None, session_token: str = None):
        """Set AWS keys for the session."""
        print('Setting AWS Keys...')
        print('Press enter to keep current value. Enter C to clear.')

        # Get current values
        current_profile = self.config.aws.profile
        current_key = self.config.aws.access_key_id
        current_secret = self.config.aws.secret_access_key
        current_token = self.config.aws.session_token
        current_region = self.config.aws.region

        if key_alias is None:
            alias = self.input(f'Profile name [{current_profile}]: ')
            if alias.lower() == 'c':
                alias = None
            elif alias:
                self.config.aws.profile = alias
        else:
            self.config.aws.profile = key_alias

        if access_key_id is None:
            key = self.input(f'Access Key ID [{current_key or "None"}]: ')
            if key.lower() == 'c':
                self.config.aws.access_key_id = None
            elif key:
                self.config.aws.access_key_id = key
        else:
            self.config.aws.access_key_id = access_key_id

        if secret_access_key is None:
            if current_secret:
                masked = current_secret[:len(current_secret)//2] + '*' * (len(current_secret)//2)
                secret = self.input(f'Secret Access Key [{masked}]: ')
            else:
                secret = self.input('Secret Access Key [None]: ')
            if secret.lower() == 'c':
                self.config.aws.secret_access_key = None
            elif secret:
                self.config.aws.secret_access_key = secret
        else:
            self.config.aws.secret_access_key = secret_access_key

        if session_token is None:
            token = self.input(f'Session Token (optional) [{current_token or "None"}]: ')
            if token.lower() == 'c':
                self.config.aws.session_token = None
            elif token:
                self.config.aws.session_token = token
        else:
            self.config.aws.session_token = session_token

        # Reset auth manager to pick up new credentials
        self.auth_manager = None
        save_config(self.config)
        self.print('\nKeys saved. Auth manager reset.')

    def swap_keys(self, key_name: str = None) -> None:
        """Swap to different AWS keys/profile."""
        profiles = self.auth_manager.list_profiles() if self.auth_manager else ["default"]

        if key_name:
            if key_name in profiles:
                self.config.aws.profile = key_name
                self.auth_manager = None
                self.print(f'Switched to profile: {key_name}')
            else:
                print(f'Profile {key_name} not found.')
            return

        print('\nAvailable AWS Profiles:')
        for i, profile in enumerate(profiles, 1):
            current = " (ACTIVE)" if profile == self.config.aws.profile else ""
            print(f'  [{i}] {profile}{current}')

        choice = input('Choose profile number: ')
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(profiles):
                self.config.aws.profile = profiles[idx]
                self.auth_manager = None
                self.print(f'Switched to profile: {profiles[idx]}')
            else:
                print('Invalid selection.')
        except ValueError:
            print('Invalid input.')

    def assume_role(self, command: List[str]) -> None:
        """Assume an IAM role."""
        if len(command) < 2:
            print("Usage: assume_role <role_arn> [session_name] [duration]")
            return

        role_arn = command[1]
        session_name = command[2] if len(command) > 2 else "awsprowl-session"
        duration = int(command[3]) if len(command) > 3 else 3600

        try:
            if self.auth_manager is None:
                self.auth_manager = create_auth_manager(self.config.aws)

            creds = self.auth_manager.assume_role(role_arn, session_name, duration_seconds=duration)

            # Update config with assumed role credentials
            self.config.aws.access_key_id = creds.access_key
            self.config.aws.secret_access_key = creds.secret_key
            self.config.aws.session_token = creds.session_token
            self.config.aws.profile = f"assumed-{session_name}"

            self.auth_manager = None  # Reset to pick up new creds
            save_config(self.config)

            self.print(f'Successfully assumed role: {role_arn}')
            self.print_key_info()

        except Exception as e:
            self.print(f'Error assuming role: {e}')

    def export_keys(self, command: List[str]) -> None:
        """Export current keys to AWS CLI credentials file."""
        if not self.config.aws.access_key_id or not self.config.aws.secret_access_key:
            print('No credentials to export.')
            return

        profile_name = self.config.aws.profile or 'awsprowl'
        creds_file = Path.home() / ".aws" / "credentials"
        creds_file.parent.mkdir(exist_ok=True)

        config = f"""
[{profile_name}]
aws_access_key_id = {self.config.aws.access_key_id}
aws_secret_access_key = {self.config.aws.secret_access_key}
"""
        if self.config.aws.session_token:
            config += f'aws_session_token = {self.config.aws.session_token}\n'

        with open(creds_file, 'a') as f:
            f.write(config)

        self.print(f'Exported to {creds_file} as profile [{profile_name}]')

    def check_sessions(self, command: List[str] = []) -> None:
        """Switch sessions."""
        # Simplified - just list sessions for now
        self.list_sessions()
        if len(command) > 1:
            print(f'Session switching not fully implemented. Would switch to: {command[1]}')

    def list_sessions(self) -> None:
        """List all sessions."""
        print(f'Current session: {self.current_session_name}')
        print('Session management not fully implemented in this version.')

    def delete_session(self) -> None:
        """Delete a session."""
        print('Session deletion not implemented in this version.')

    def run_aws_cli_command(self, command: str) -> None:
        """Run AWS CLI command with current credentials."""
        try:
            # Set up environment with current credentials
            env = os.environ.copy()
            if self.config.aws.access_key_id:
                env['AWS_ACCESS_KEY_ID'] = self.config.aws.access_key_id
            if self.config.aws.secret_access_key:
                env['AWS_SECRET_ACCESS_KEY'] = self.config.aws.secret_access_key
            if self.config.aws.session_token:
                env['AWS_SESSION_TOKEN'] = self.config.aws.session_token
            if self.config.aws.region:
                env['AWS_DEFAULT_REGION'] = self.config.aws.region

            result = subprocess.run(command, shell=True, env=env, capture_output=True, text=True)
            if result.stdout:
                self.print(result.stdout)
            if result.stderr:
                self.print(result.stderr, output='screen')
        except Exception as e:
            self.print(f'Error running AWS CLI: {e}')

    def exit(self) -> None:
        """Exit the shell."""
        sys.exit('awsProwl exit')

    def idle(self) -> bool:
        """Main command input loop."""
        while True:
            try:
                prompt = f'awsprowl ({self.current_session_name}:{self.get_credentials_summary()}) > '
                command = input(prompt)
                self.parse_command(command)
                self._reset_interrupt_state()

            except (KeyboardInterrupt, SystemExit) as e:
                if isinstance(e, SystemExit):
                    if e.args and 'SIGINT called' in str(e.args):
                        pass
                    else:
                        raise

                interrupt_count = self._record_interrupt()
                if interrupt_count >= 2:
                    print('\n[*] Exiting awsProwl...')
                    return False
                else:
                    print('\n[*] Press Ctrl+C again to exit.')
                    continue

            except EOFError:
                print('\n[*] EOF detected. Exiting...')
                return False

        return False

    def run(self) -> None:
        """Run the interactive shell."""
        # Initialize
        load_config()
        self.config = get_config()
        setup_logging(self.config.logging)

        print("""
    awsProwl Interactive Shell
    Type 'help' for commands, 'exit' to quit
    """)

        # Initialize auth manager
        try:
            self.auth_manager = create_auth_manager(self.config.aws)
            self.auth_manager.get_caller_identity()
            print(f'[+] Authenticated successfully')
        except Exception as e:
            print(f'[!] No valid credentials: {e}')
            print('Use "set_keys" to configure credentials.')

        self.idle()


def main():
    """Entry point for interactive shell."""
    shell = InteractiveShell()
    shell.run()


if __name__ == '__main__':
    main()