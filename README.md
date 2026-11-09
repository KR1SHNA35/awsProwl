<div align="center">

```text
                         ____                     __
  ____ __      _______/ __ \_________ _      __/ /
 / __ `/ | /| / / ___/ /_/ / ___/ __ \ | /| / / /
/ /_/ /| |/ |/ (__  ) ____/ /  / /_/ / |/ |/ / /
\__,_/ |__/|__/____/_/   /_/   \____/|__/|__/_/
```

# awsProwl

### STALK THE CLOUD. KNOW YOUR ATTACK SURFACE.

**AWS Security Research Framework**

Authorized penetration testing · CTFs · Cloud security assessments

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-8B5CF6?style=for-the-badge&logo=opensourceinitiative&logoColor=white)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-00C853?style=for-the-badge&logo=github&logoColor=white)](https://github.com/KR1SHNA35/awsProwl)
[![AWS](https://img.shields.io/badge/AWS-boto3-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)](https://boto3.amazonaws.com)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-64748B?style=for-the-badge&logo=linux&logoColor=white)](https://github.com/KR1SHNA35/awsProwl)

**28 services · 410 modules · 6 categories · Interactive TUI and classic shell**

<img src="src/utils/banner.png" alt="awsProwl terminal home screen" width="900">

[Overview](#overview) · [Features](#features) · [Installation](#installation) · [Quick Start](#quick-start) · [CLI](#cli-main-commands) · [TUI](#tui-repl-commands) · [Classic Shell](#interactive-shell-commands-classic) · [Permissions](#aws-permissions) · [Safety](#security--operational-safety)

</div>

---

## Overview

**awsProwl** is an AWS security research tool built for authorized penetration testing, CTF competitions, and cloud security assessments. It unifies deep service enumeration, privilege-escalation analysis, exploitation, persistence, and data-exfiltration modules inside one operator-friendly interface.

It's built for practitioners who need **speed, precision, and operational discipline** — every module is tagged with a risk level and authorization requirement, and destructive actions sit behind explicit confirmation gates.

### At a glance

| Capability | Coverage |
|---|---:|
| AWS services | 28 |
| Modules | 410 |
| Module categories | 6 |
| Scan profiles | 5 |
| Report formats | Table, JSON, HTML, Markdown, SARIF, with CSV export |

### Design principles

- **Unified workflow:** service discovery, module execution, result review, and reporting from one environment.
- **Risk-aware execution:** read-only analysis is separated from operations that can change resources or access data.
- **Operator control:** profile, region, module, and output choices remain explicit.
- **Integration-ready results:** structured output supports local analysis and security-tool pipelines.

### Why awsProwl?

| Problem | Solution |
| --- | --- |
| Fragmented AWS tooling | One framework covering 28 services, 410 modules |
| Manual privesc research | Automated detection across IAM, EC2, S3, Lambda, VPC, CodeBuild |
| No safe enumeration mode | `ENUM` category — read-only, zero state changes |
| Poor CI/CD integration | SARIF, HTML, Markdown, JSON, CSV output |
| Credential juggling | Profile, SSO, assume-role, env vars, instance metadata — one auth chain |
| Tool-switching fatigue | Interactive REPL: module browser, fuzzy search, live results |

---

## Features

### Multi-Service Coverage

**28 AWS services**, each with dedicated scanners spanning enumeration, security checks, and attack modules across **6 categories** — **410 modules total**.

| Domain | Services |
| --- | --- |
| **Identity & Access** | IAM · STS · Organizations |
| **Compute** | EC2 · Lambda · ECS · EKS · Elastic Beanstalk · CodeBuild · Lightsail |
| **Storage** | S3 · EBS · EFS · ECR · DynamoDB · RDS |
| **Network** | VPC · CloudFront · ELB · API Gateway · Transfer |
| **Security** | KMS · Secrets Manager · CloudTrail · GuardDuty · Security Hub · Config · WAF |
| **Management** | CloudFormation · SSM · CloudWatch · Service Catalog |
| **Additional** | ACM · Cognito · Detection · Directory Service · SNS |

### Module Categories (Prowler-Inspired)

| Category | Count | Risk | Authorization | What it does |
| --- | --- | --- | --- | --- |
| **ENUM** | 91 | Safe | Read-only | Comprehensive enumeration — users, roles, policies, buckets, instances, functions, clusters, secrets, certificates, trails, keys, topics, repos, dashboards, log groups, alarms, and more |
| **PRIVESC** | 40 | Low–Critical | Read-only analysis | Privilege-escalation path detection across IAM, EC2, S3, Lambda, CodeBuild, VPC |
| **EXPLOIT** | 112 | High–Critical | Explicit confirmation | Active exploitation — resource creation, policy/role manipulation, attribute changes |
| **PERSIST** | 59 | High–Critical | Explicit confirmation | Persistence mechanisms — backup credentials, trust-policy changes, service-linked roles |
| **BACKDOOR** | 44 | Critical | Explicit confirmation | Backdoor creation — permissive trust policies, attacker-controlled identity providers |
| **EXFIL** | 64 | Medium–Critical | Explicit confirmation | Data exfiltration — snapshots, logs, findings, secrets, images, parameters |

> **ENUM** and **PRIVESC** never touch account state. Everything from **EXPLOIT** down requires a typed `CONFIRM`.

#### Category scope

The category labels describe the intent of a module, not a guarantee that every action has identical impact. Review each module's details and required permissions before execution.

- **ENUM:** read-only discovery of identities, roles, policies, buckets, compute resources, functions, clusters, secrets metadata, certificates, trails, keys, topics, repositories, dashboards, log groups, alarms, and other service resources.
- **PRIVESC:** analysis of potential privilege-escalation paths involving IAM policy and trust relationships, `PassRole`, instance profiles, S3 bucket policies, Lambda execution roles, CodeBuild roles, and VPC configurations.
- **EXPLOIT:** active operations that may create or modify users, roles, policies, instances, security groups, storage policies, Lambda resources, API resources, builds, network controls, or other AWS resources.
- **PERSIST:** mechanisms involving credentials, roles, trust policies, policy versions, group membership, service-linked roles, EC2 user data, launch templates, AMIs, Lambda aliases, and layers.
- **BACKDOOR:** mechanisms such as permissive service-role trust relationships and identity providers with externally controlled issuers.
- **EXFIL:** access or export workflows involving object storage, snapshots, audit history, logs, findings, container images, parameters, cluster credentials, and related data sources.

### Scan Profiles

| Profile | Services | Best for |
| --- | --- | --- |
| `quick` | IAM, EC2, S3 | Rapid recon |
| `standard` | IAM, EC2, S3, Lambda, ECS, Secrets Manager, SNS, RDS, DynamoDB, KMS | General assessment |
| `deep` | + Beanstalk, Cognito, STS, CloudFront, EKS | Comprehensive audit |
| `compliance` | Same as `deep` | CIS / NIST / PCI-DSS mapping |
| `ctf` | IAM, EC2, S3, Lambda, STS, RDS, DynamoDB | Time-boxed CTF engagements |

### Interactive REPL (prompt_toolkit)

```text
┌─ awsProwl ───────────────────────────────────────────────────────────────┐
│                                                                          │
│   ____                     __                                            │
│  ____ __      _______/ __ \_________ _      __/ /                        │
│ / __ `/ | /| / / ___/ /_/ / ___/ __ \ | /| / / /                         │
│/ /_/ /| |/ |/ (__  ) ____/ /  / /_/ / |/ |/ / /                          │
│\__,_/ |__/|__/\____/_/   /_/   \____/|__/|__/_/                          │
│                                                                          │
│                         Stalk the Cloud                                 │
│                                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│ Profile: production │ Profiles: 3 │ Services: 28 │ Modules: 410          │
├──────────────────────────────────────────────────────────────────────────┤
│ [IAM]    iam       54 modules  [ENUM] [PRIV-ESC] [EXPLOIT] [PERSIST]     │
│                                [BACKDOOR] [EXFIL]                         │
│ [EC2]    ec2       26 modules  [ENUM] [EXPOSURE] [ENCRYPT] [EXFIL]       │
│                                [PRIV-ESC] [PERSIST]                       │
│ [S3]     s3        23 modules  [ENUM] [EXPOSURE] [ENCRYPT] [EXFIL]       │
│                                [PRIV-ESC] [PERSIST]                       │
│ [LAMBDA] lambda    20 modules  [ENUM] [SEC] [POLICY] [PRIV-ESC]          │
│                                [EXFIL] [PERSIST] [BACKDOOR]               │
│ [ECS]    ecs       13 modules  [ENUM] [PRIV-ESC] [NETWORK] [EXFIL]       │
│                                [EXPLOIT] [PERSIST] [BACKDOOR]             │
│                                                                          │
│ ... 25 more services                                                    │
├──────────────────────────────────────────────────────────────────────────┤
│ awsprowl[services] › search iam_priv                                     │
└──────────────────────────────────────────────────────────────────────────┘
```

**REPL capabilities**

- Service/module browser with category filters (`enum`, `privesc`, `exploit`, `persist`, `backdoor`, `exfil`)
- Fuzzy search across all modules (`search iam`, `search encryption`, `search privesc`)
- Profile switching with live credential validation
- Region selection — single, multiple, or `all`
- Real-time progress with Prowler-style detailed output
- Results viewer — severity breakdown, top findings, JSON/CSV export
- Scan diffing: `diff old.json new.json`
- Finding tags: `tag add 1 critical,prod`
- Command history, and a built-in JSON viewer (`open_json output/prod/iam_scan-all.json`)

---

## Installation

### Prerequisites

- Python 3.10+
- AWS CLI v2 (for profile management)
- Valid AWS credentials configured

### From Source

```bash
git clone https://github.com/KR1SHNA35/awsProwl.git
cd awsProwl
pip install -e .[dev] # development install with test tools
# or
pip install -e . # production install
```

### Verify Installation

```bash
awsprowl --version
awsprowl --help
awsprowl interactive --help
```

### PATH Setup (Important)

If `awsprowl` command is not found after installation, the pip scripts directory isn't in your PATH.

**Linux/macOS (bash/zsh):**
```bash
# Add to ~/.bashrc, ~/.zshrc, or ~/.profile
export PATH="$HOME/.local/bin:$PATH"
# Then reload:
source ~/.bashrc  # or ~/.zshrc
```

**Linux/macOS (fish):**
```fish
fish_add_path $HOME/.local/bin
```

**Windows (PowerShell):**
```powershell
$env:PATH += ";$env:APPDATA\Python\Python312\Scripts"
# Or permanently:
[Environment]::SetEnvironmentVariable("PATH", $env:PATH + ";$env:APPDATA\Python\Python312\Scripts", "User")
```

**Find your pip scripts directory:**
```bash
python3 -m site --user-base
# Then add /bin to that path, e.g. /home/user/.local/bin
```

**One-liner to fix PATH permanently (Linux/macOS):**
```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
```

### AWS Credentials

awsProwl uses the standard AWS credential chain. Configure profiles first:

```bash
aws configure --profile production
aws configure --profile staging
aws sso configure --profile corp-sso
```

**Supported auth methods** (priority order):

1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
2. Named profile (`--profile` or `AWS_PROFILE`)
3. AWS SSO (`aws sso login --profile <name>`)
4. Assume role (`--role-arn`, `--external-id`, `--mfa-token`)
5. EC2 Instance Metadata Service (IMDSv2)
6. ECS Task Role

---

## Quick Start

### Interactive REPL (recommended)

```bash
awsprowl # Launch interactive REPL (TUI mode)
awsprowl --no-tui # Classic interactive scan prompts
awsprowl interactive # Explicit interactive command
awsprowl interactive --no-tui # Classic mode
```

### Direct Scan Commands

```bash
# Quick scan with defaults
awsprowl scan

# Specific profile + region + scan type
awsprowl scan production us-east-1 standard

# All regions, deep scan
awsprowl scan production all deep

# Custom output format
awsprowl scan production us-east-1 standard --output sarif --output-dir ./reports
```

### REPL Workflow Example

```
awsprowl
# 1. Select profile (number or name) or press Enter for default
# 2. Type 'services' to browse available services
# 3. Select service (number) → modules listed with category badges
# 4. Run module: 'run iam_enum_users' or 'run iam scan-all'
# 5. For scan-all modules: prompted for region (Enter=current, 'all'=all regions)
# 6. Results displayed Prowler-style + saved to output/<profile>/<service>_<module>.json
```

---

## CLI Main Commands

> Full documentation of every CLI command and TUI/classic REPL command, with example arguments.

### `awsprowl` (root command)

```bash
awsprowl [OPTIONS] [COMMAND]
```

**Global Options:**

| Option | Short | Description |
| --- | --- | --- |
| `--config` | `-c` | Path to configuration file |
| `--verbose` | `-v` | Increase verbosity (`-v`, `-vv`, `-vvv`) |
| `--quiet` | `-q` | Suppress non-essential output |
| `--no-color` | | Disable colored output |
| `--no-banner` | | Skip startup banner |
| `--tui/--no-tui` | | Enable/disable interactive TUI mode (default: enabled) |
| `--version` | | Show version and exit |
| `--help` | `-h` | Show help message |

**Behavior:** When no subcommand is provided, launches the interactive TUI module browser.

**Examples:**

```bash
awsprowl # Launch TUI (default)
awsprowl --no-tui # Launch classic interactive shell
awsprowl --config ~/.config/awsprowl/custom.yaml # Use custom config
awsprowl -vv # Verbose output
awsprowl --quiet # Minimal output
awsprowl --no-color # Monochrome output
```

### `awsprowl scan`

Run an AWS security scan.

```bash
awsprowl scan [PROFILE] [REGION] [SCAN_TYPE] [OPTIONS]
```

**Arguments:**

| Argument | Required | Description |
| --- | --- | --- |
| `PROFILE` | No | AWS profile name (default: `default`) |
| `REGION` | No | AWS region or `all` for all regions (default: `us-east-1`) |
| `SCAN_TYPE` | No | Scan profile: `quick`, `standard`, `deep`, `compliance`, `ctf` (default: `standard`) |

**Options:**

| Option | Short | Description |
| --- | --- | --- |
| `--output` | `-o` | Output format: `table`, `json`, `html`, `markdown`, `sarif` (default: `table`) |
| `--output-dir` | `-d` | Output directory (default: `./awsprowl-output`) |
| `--quiet` | `-q` | Suppress non-essential output |
| `--no-banner` | | Skip startup banner |

**Scan Profiles:**

| Profile | Services |
| --- | --- |
| `quick` | iam, ec2, s3 |
| `standard` | iam, ec2, s3, lambda, ecs, secretsmanager, sns, rds, dynamodb, kms |
| `deep` | All standard + beanstalk, cognito, sts, cloudfront, eks |
| `compliance` | Same as deep |
| `ctf` | iam, ec2, s3, lambda, sts, rds, dynamodb |

**Examples:**

```bash
# Interactive mode (prompts for all options)
awsprowl scan

# Quick scan with default profile in us-east-1
awsprowl scan

# Explicit profile, region, and scan type
awsprowl scan default us-east-1 quick

# Deep scan across all regions
awsprowl scan myprofile all deep

# Custom output format and directory
awsprowl scan default us-east-1 standard --output json --output-dir /tmp/scans

# Multiple regions
awsprowl scan default "us-east-1,us-west-2,eu-west-1" standard

# Quiet mode for scripting
awsprowl scan default us-east-1 quick --quiet --output json
```

### `awsprowl config`

Manage awsProwl configuration.

```bash
awsprowl config [COMMAND] [OPTIONS]
```

#### `config list`

```bash
awsprowl config list [--show-defaults] [--format table|yaml|json]
```

```bash
awsprowl config list # Table format (default)
awsprowl config list --format yaml # YAML output
awsprowl config list --format json # JSON output
awsprowl config list --show-defaults # Include default values
```

#### `config get`

```bash
awsprowl config get <KEY>
```

```bash
awsprowl config get aws.profile
awsprowl config get scan.regions
awsprowl config get output.format
awsprowl config get logging.level
```

#### `config set`

```bash
awsprowl config set <KEY> <VALUE>
```

```bash
awsprowl config set aws.profile myprofile
awsprowl config set aws.region us-west-2
awsprowl config set scan.regions "us-east-1,us-west-2"
awsprowl config set output.format json
awsprowl config set logging.level DEBUG
awsprowl config set ui.color_scheme dark
```

#### `config reset`

```bash
awsprowl config reset [--yes]
```

```bash
awsprowl config reset # Prompts for confirmation
awsprowl config reset --yes # Force reset without prompt
```

#### `config profiles`

```bash
awsprowl config profiles
```

#### `config edit`

```bash
awsprowl config edit # Opens in $EDITOR (default: nano)
EDITOR=vim awsprowl config edit # Use vim
```

#### `config path`

```bash
awsprowl config path # Shows: ~/.config/awsprowl/config.yaml
```

### `awsprowl version`

Show version information.

```bash
awsprowl version [--short] [--json]
```

```bash
awsprowl version # Full version display with dependencies
awsprowl version --short # Just version number (2.0.0)
awsprowl version --json # JSON output for scripting
```

### Session management

The session command group provides commands for reviewing and managing saved assessment sessions.

```bash
awsprowl session list [--limit N] [--format table|json]
awsprowl session show <session_id> [--format table|json]
awsprowl session load <session_id>
awsprowl session delete <session_id> [--yes]
awsprowl session clean [--older-than N] [--yes]
```

### Report generation

Generate a report from an existing scan or session identifier:

```bash
awsprowl report generate [scan_id] --format html|markdown|sarif|json
```

### `awsprowl interactive`

Start the interactive module browser.

```bash
awsprowl interactive [--no-banner] [--tui/--no-tui]
```

| Option | Description |
| --- | --- |
| `--no-banner` | Skip startup banner |
| `--tui/--no-tui` | Enable/disable TUI mode (default: TUI enabled) |

```bash
awsprowl interactive # TUI mode (default)
awsprowl interactive --no-tui # Classic CLI shell
awsprowl interactive --no-banner # Skip banner in TUI
awsprowl interactive --no-tui --no-banner # Classic shell, no banner
```

---

## TUI REPL Commands

The TUI (`ModuleBrowserTUI`) provides an interactive REPL. Access via `awsprowl` or `awsprowl interactive`.

### Navigation Commands

| Command | Aliases | Description |
| --- | --- | --- |
| `help` | `h`, `?` | Show help with all commands |
| `info <module>` | `show-module`, `module-info` | Show detailed module information (what it does, permissions, MITRE techniques, usage) |
| `modules` | `all-modules`, `list-modules` | Show ALL modules across all services with categories, risk, destructive flags |
| `modules <service>` | | Show modules for a specific service (e.g., `modules iam`, `modules ec2`) |
| `whoami` | `caller-identity` | Display current AWS caller identity (Account, UserId, ARN) |
| `services` | `list`, `ls`, `s` | Show all available services |
| `profiles` | `profile`, `p` | Switch AWS profile |
| `region` | `r` | Show/set current scan region |
| `clear` | `c` | Clear search results or JSON view |
| `last` | `l` | Show last module results |
| `history` | `hist`, `h` | Show command history |
| `back` | `b` | Go back to previous view |
| `exit` | `quit`, `q` | Exit the browser |

**`info` examples:**

```bash
info iam_enum_users # Show info about IAM enumeration module
info iam_exploit_create_user # Show info about IAM exploit module
info check-mfa # Show info about MFA check module
info cloudformation_persist_stack # Show info about CloudFormation persistence
info ec2_exploit_run_instances # Show info about EC2 exploit module
info s3_exfil_download_objects # Show info about S3 exfiltration module
info lambda_exploit_update_function_code # Show info about Lambda exploit
```

**`modules` examples:**

```bash
modules # List all modules across all services
modules iam # List only IAM modules
modules ec2 # List only EC2 modules
modules s3 # List only S3 modules
modules lambda # List only Lambda modules
all-modules # Alias for modules
list-modules # Alias for modules
```

**`whoami` examples:**

```bash
whoami # Show AWS caller identity
caller-identity # Alias for whoami
```

### TUI Search Commands

| Command | Description |
| --- | --- |
| `search <query>` | Search modules by name, service, category, or description |
| `search iam` | All IAM modules |
| `search ec2` | All EC2 modules |
| `search s3` | All S3 modules |
| `search lambda` | All Lambda modules |
| `search encryption` | Cross-service encryption checks |
| `search public` | Cross-service public exposure checks |
| `search privesc` | Cross-service privilege escalation checks |
| `search secrets` | Find secrets across services |
| `search iam_priv` | IAM privilege escalation modules |
| `search iam_enum` | IAM enumeration modules |
| `search ec2_enum` | EC2 enumeration modules |
| `search ec2_privesc` | EC2 privilege escalation modules |
| `search s3_exploit` | S3 exploitation modules |
| `search enum` | All enumeration modules across services |
| `search exploit` | All exploitation modules across services |
| `search persist` | All persistence modules across services |
| `search backdoor` | All backdoor modules across services |
| `search exfil` | All exfiltration modules across services |

### Module Execution Commands

| Command | Description |
| --- | --- |
| `run <module>` | Run module by name (searches all services) |
| `run <service> <module>` | Run specific module in service |
| `run <service> <module> <region>` | Run module in specific region |
| `run <service>` | Run full service scanner (scan-all) |
| `privesc` | Run ALL privilege escalation modules across services |
| `privesc-all` | Alias for privesc |

**Examples:**

```bash
run iam # Run IAM scanner (all checks)
run ec2 # Run EC2 scanner (all checks)
run s3 # Run S3 scanner (all checks)
run iam list-users # Run specific IAM module
run ec2 check-public-ips # Run specific EC2 module
run lambda list-functions us-east-1 # Run Lambda module in specific region
run iam iam_enum_users # Run IAM enumeration module
run iam iam_privesc_full_scan # Run IAM privilege escalation scan
run ec2 ec2_enum_resources # Run EC2 enumeration module
run s3 s3_enum_buckets # Run S3 enumeration module
run sts sts_enum_caller_identity # Run STS enumeration module
```

### Region Commands

| Command | Description |
| --- | --- |
| `region` | Show current scan region and enter selection mode |
| `region <region>` | Set default scan region (e.g., `region us-west-2`) |
| `region list` | List available regions |
| `region all` | Scan all regions |

**Examples:**

```bash
region # Show current region + selection menu
region us-east-1 # Set region to us-east-1
region us-west-2 # Set region to us-west-2
region eu-west-1 # Set region to eu-west-1
region all # Scan all regions
region list # List all available regions
```

### Category Filter Commands

| Command | Description |
| --- | --- |
| `category` | Show current category filter |
| `category <type>` | Filter modules by category |
| `category clear` | Clear category filter (show all) |

**Valid Categories:** `enum`, `privesc`, `exploit`, `persist`, `backdoor`, `exfil`

```bash
category # Show current filter
category enum # Show only enumeration modules
category exploit # Show only exploit modules
category persist # Show only persistence modules
category backdoor # Show only backdoor modules
category exfil # Show only exfiltration modules
category privesc # Show only privilege escalation modules
category clear # Clear filter, show all
```

### Export & Diff Commands

| Command | Description |
| --- | --- |
| `export_csv [file.json] [out.csv]` | Export findings to CSV |
| `diff <old.json> <new.json>` | Compare two scan files |
| `tag list` | List tags for all findings in last results |
| `tag add <idx> <tags...>` | Add tags to finding (comma-separated) |
| `tag remove <idx> <tags...>` | Remove tags from finding |
| `tag set <idx> <tags...>` | Set tags for finding (replace all) |

**Examples:**

```bash
export_csv # Export last results to CSV
export_csv output/default/iam_scan-all.json # Export specific file
export_csv findings.json out.csv # Export with custom output name

diff output/prod/iam_scan-all.json output/staging/iam_scan-all.json

tag list # Show tags for all findings
tag add 1 critical,prod # Add tags to finding #1
tag remove 1 prod # Remove tag from finding #1
tag set 1 critical,prod,ticket-123 # Set tags for finding #1
```

### JSON View Commands

| Command | Aliases | Description |
| --- | --- | --- |
| `open_json <path>` | `oj`, `view_json` | Open and view JSON file with syntax highlighting |

```bash
open_json output/default/iam_scan-all.json
oj output/prod/ec2_scan-all.json
view_json findings-scan-20240115-143022.json
```

### Number Selection (Interactive Menus)

| View | Action |
| --- | --- |
| Profile selection | Type number to select profile |
| Services list | Type number to select service |
| Modules list | Type number to run module |
| Search results | Type number to run module |
| Region selection | Type number (1–11), `all`, or custom region code |

---

## Interactive Shell Commands (Classic)

The classic interactive shell (`awsprowl interactive --no-tui` or `awsprowl --no-tui`) provides these commands.

### Core Commands

| Command | Aliases | Description |
| --- | --- | --- |
| `run` | `exec`, `use` | Execute a scanner module |
| `list` | `ls` | List all available modules |
| `modules` | `all-modules`, `list-modules` | Show ALL modules across all services |
| `modules <service>` | | Show modules for specific service (e.g., `modules iam`, `modules ec2`) |
| `search` | | Search modules by name or category |
| `info <module>` | `show-module`, `module-info` | Show detailed module information (what it does, permissions, MITRE techniques, usage) |
| `help` | | Display help |
| `help <module>` | | Display help for specific module |
| `whoami` | `caller-identity` | Display current AWS caller identity |
| `data` | | Display all collected session data |
| `data <service>` | | Display data for specific service |
| `services` | | Display services with collected data |
| `regions` | | Display all valid AWS regions |
| `set_regions` | | Set default regions for this session |
| `update_regions` | | Update regions database from AWS SSM |
| `set_ua_suffix` | | Set user agent suffix for API calls |
| `unset_ua_suffix` | | Remove user agent suffix |
| `set_keys` | | Add/set AWS keys for this session |
| `swap_keys` | | Switch to different AWS keys/profile |
| `assume_role` | | Assume an IAM role |
| `export_keys` | | Export active keys to AWS CLI config |
| `aws <command>` | | Run AWS CLI command with current credentials |
| `console` | | Generate AWS Console login URL |
| `clear` | | Clear the terminal |
| `history` | | Show command history |
| `exit` | `quit` | Exit awsProwl |
| `load_commands_file` | | Execute commands from file |

### Module Execution

```bash
run <module> [ARGS...]
exec <module> [ARGS...]
use <module> [ARGS...]
```

**Module examples:**

```bash
run iam # Run IAM scanner
run ec2 # Run EC2 scanner
run s3 # Run S3 scanner
run lambda # Run Lambda scanner
run sts # Run STS scanner
run iam_check_mfa # Run IAM MFA check (analysis)
run ec2_check_public_ips # Run EC2 public IP check (analysis)
run s3_check_encryption # Run S3 encryption check (analysis)
run search_encryption # Cross-service encryption search
run search_public # Cross-service public exposure search
run search_privesc # Cross-service privilege escalation search
run search_secrets # Cross-service secrets search
```

**`info` examples:**

```bash
info iam_enum_users # Show info about IAM enumeration module
info iam_exploit_create_user # Show info about IAM exploit module
info check-mfa # Show info about MFA check module
info cloudformation_persist_stack # Show info about CloudFormation persistence
info ec2_exploit_run_instances # Show info about EC2 exploit module
info s3_exfil_download_objects # Show info about S3 exfiltration module
info lambda_exploit_update_function_code # Show info about Lambda exploit
```

**With region arguments:**

```bash
run ec2 --region us-west-2
run ec2 --regions us-east-1 us-west-2 eu-west-1
run iam --all-regions
run lambda --region us-east-1 --region us-west-2
```

### List Commands

```bash
list # List all modules
list cat # List categories
list category # List categories
list cat <category_name> # List modules in category
list category <category_name> # List modules in category
```

**Categories:** `aws_service`, `analysis`, `cross_service`

```bash
list # All modules grouped by category
list cat # Show available categories
list category aws_service # Show all AWS service modules
list category analysis # Show all analysis modules
list category cross_service # Show all cross-service modules
```

### Classic Shell Search Commands

```bash
search <term> # Search modules by name
search cat <category> # Search modules by category
search category <category> # Search modules by category
```

```bash
search iam # Find modules with "iam"
search ec2 # Find modules with "ec2"
search encryption # Find encryption-related modules
search cat aws_service # All AWS service modules
search category analysis # All analysis modules
```

### Help Commands

```bash
help # Main help
help <command> # Help for specific command
help <module> # Help for specific module
```

```bash
help # Full help text
help run # Help for run command
help list # Help for list command
help assume_role # Help for assume_role
help iam # Help for IAM module
help ec2 # Help for EC2 module
help search_encryption # Help for search_encryption module
```

### AWS Credential Management

```bash
# Set keys interactively
set_keys

# Set keys with arguments (non-interactive)
set_keys myprofile AKIA... SECRET... [SESSION_TOKEN]

# Swap to different profile
swap_keys # Interactive selection
swap_keys myprofile # Switch to specific profile

# Assume IAM role
assume_role <role_arn> [session_name] [duration_seconds]

# Export current credentials to ~/.aws/credentials
export_keys
```

```bash
set_keys
set_keys production AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
set_keys staging AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY AQoDYXdzEJr...

swap_keys
swap_keys production

assume_role arn:aws:iam::123456789012:role/ReadOnly
assume_role arn:aws:iam::123456789012:role/Admin mysession 3600

export_keys
```

### Region Management

```bash
regions # Display all valid AWS regions
set_regions <region> [region...] # Set default regions
set_regions all # Reset to all regions
update_regions # Update from AWS SSM (requires confirmation)
```

```bash
regions
set_regions us-east-1
set_regions us-east-1 us-west-2 eu-west-1
set_regions all
update_regions
```

### User Agent Management

```bash
set_ua_suffix # Generate and set random suffix
set_ua_suffix my-custom-suffix # Set custom suffix
unset_ua_suffix # Remove suffix
```

### AWS CLI Integration

```bash
aws <command> # Run AWS CLI with current credentials
```

```bash
aws ec2 describe-instances
aws s3 ls
aws iam list-users
aws sts get-caller-identity
aws cloudformation list-stacks
```

### Console Access

```bash
console # Generate AWS Console login URL
open_console # Alias for console
```

### Data Display

```bash
data # All session data
data <service> # Data for specific service
services # Services with collected data
```

```bash
data
data EC2
data IAM
data S3
services
```

### File-Based Command Execution

```bash
load_commands_file <file>
```

**Example file (`commands.txt`):**

```
run iam
run ec2
run s3
search encryption
```

**Usage:**

```bash
load_commands_file commands.txt
```

### Keyboard Shortcuts (Classic Shell)

| Shortcut | Action |
| --- | --- |
| `Tab` | Auto-complete commands and modules |
| `Ctrl+C` | Stop current module, return to prompt |
| `Ctrl+C` (twice at prompt) | Exit awsProwl |
| `Up/Down` | Command history navigation |

### Keyboard Shortcuts (TUI)

| Shortcut | Action |
| --- | --- |
| `Tab` | Auto-complete (in prompt) |
| `Up/Down` | Command history navigation |
| `Ctrl+C` | Abort current input / interrupt running module |
| `Ctrl+D` | EOF (exit if at empty prompt) |
| Number keys | Select item in numbered lists |

---

## Output Formats

| Format | Extension | Description |
| --- | --- | --- |
| **Table** *(default)* | — | Rich terminal table with severity colors, sortable columns |
| **JSON** | `.json` | Structured findings with full metadata, for programmatic use |
| **HTML** | `.html` | Standalone report — summary cards, severity badges, responsive table, embedded CSS |
| **Markdown** | `.md` | GitHub-renderable report with findings, evidence, remediation steps, CLI commands |
| **SARIF** | `.sarif` | SARIF v2.1.0 — CI/CD integration for GitHub Advanced Security, Azure DevOps, GitLab |
| **CSV** | `.csv` | Tabular export of findings for spreadsheet and data-analysis workflows |

```bash
# SARIF for GitHub Code Scanning
awsprowl scan production us-east-1 standard --output sarif --output-dir ./sarif
# Upload: github/codeql-action/upload-sarif@v3 with sarif/report-<scan_id>.sarif
```

**CSV export (REPL):**

```bash
export_csv # Export last results
export_csv output/prod/iam_scan.json # Export from file
export_csv file.json out.csv # Custom output path
```

### Scan Output Locations

| Type | Location |
| --- | --- |
| TUI scan results | `output/{profile}/{service}_{module}.json` |
| CLI scan results | `{output_dir}/findings-{scan_id}.json` |

---

## Configuration

Configuration file: `~/.config/awsprowl/config.yaml` (XDG-compliant)

```yaml
aws:
 profile: "default"
 region: "us-east-1"
 access_key_id: null
 secret_access_key: null
 session_token: null
 user_agent_extra: null
 max_retries: 3
 timeout: 30
 rate_limit: 10.0

scan:
 profile: "standard"
 services: []
 regions: ["us-east-1"]
 include_global_services: true
 parallel_regions: true
 max_workers: 10
 timeout_per_service: 300
 save_raw_responses: false
 deduplicate_findings: true

output:
 format: "table"
 output_dir: "./awsprowl-output"
 include_timestamp: true
 compress: false
 pretty_print: true

web:
 host: "127.0.0.1"
 port: 8080
 enable_cors: true

logging:
 level: "INFO"
 file: "awsprowl.log"
 max_size: "10 MB"
 retention: "7 days"
 format: "pretty"
 colors: true

ui:
 theme: "dark"
 color_scheme: "default"
 show_progress: true
 show_banner: true
 interactive_mode: false
 unicode: true
 compact_tables: false
```

**Environment variable override** (prefix `AWSPROWL_`):

```bash
export AWSPROWL_AWS__PROFILE=production
export AWSPROWL_SCAN__REGIONS='["us-east-1","us-west-2"]'
export AWSPROWL_OUTPUT__FORMAT=sarif
```

### Environment Variables

| Variable | Description |
| --- | --- |
| `AWS_PROFILE` | Default AWS profile |
| `AWS_REGION` | Default AWS region |
| `AWS_ACCESS_KEY_ID` | Access key (if not in config) |
| `AWS_SECRET_ACCESS_KEY` | Secret key (if not in config) |
| `AWS_SESSION_TOKEN` | Session token (if not in config) |
| `EDITOR` | Editor for `config edit` (default: nano) |
| `AWS_PROWL_CONFIG` | Alternative config file path |

### Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | General error |
| `130` | Interrupted by user (Ctrl+C) |

---

## AWS Permissions

### Minimum Read-Only Policy (ENUM / PRIVESC / SEARCH)

```json
{
 "Version": "2012-10-17",
 "Statement": [
 {
 "Sid": "ReadOnlyEnumeration",
 "Effect": "Allow",
 "Action": [
 "iam:List*", "iam:Get*", "iam:SimulatePrincipalPolicy",
 "iam:GetAccountAuthorizationDetails", "iam:GetCredentialReport",
 "ec2:Describe*", "s3:ListAllMyBuckets", "s3:GetBucket*",
 "lambda:List*", "lambda:Get*", "ecs:List*", "ecs:Describe*",
 "rds:Describe*", "dynamodb:List*", "dynamodb:Describe*",
 "cloudfront:List*", "cloudfront:Get*", "kms:List*", "kms:Describe*",
 "secretsmanager:List*", "secretsmanager:Describe*",
 "sns:List*", "sns:Get*", "sts:GetCallerIdentity",
 "organizations:List*", "organizations:Describe*",
 "cloudtrail:List*", "cloudtrail:Get*",
 "codebuild:List*", "codebuild:BatchGet*",
 "elasticbeanstalk:Describe*", "elasticbeanstalk:List*",
 "elb:Describe*", "elbv2:Describe*",
 "transfer:List*", "transfer:Describe*", "vpc:Describe*",
 "waf:List*", "waf:Get*", "wafv2:List*", "wafv2:Get*",
 "ds:List*", "ds:Describe*", "lightsail:Get*",
 "acm:List*", "acm:Describe*", "ecr:Describe*", "ecr:List*",
 "cloudwatch:List*", "cloudwatch:Get*", "cloudwatch:Describe*",
 "ssm:List*", "ssm:Get*", "ssm:Describe*",
 "cloudformation:List*", "cloudformation:Describe*",
 "apigateway:Get*", "eks:List*", "eks:Describe*"
 ],
 "Resource": "*"
 }
 ]
}
```

> The policy below is an example starting point from the project documentation, not a universal least-privilege policy. Review every action and scope permissions to the services, regions, and assessment activities you are authorized to test.

### Destructive Modules (EXPLOIT / PERSIST / BACKDOOR / EXFIL)

Each destructive module requires additional permissions and documents them in the REPL — `run <module>` or `info <module>` shows MITRE ATT&CK techniques and required permissions **before** the confirmation prompt.

> **Never run destructive modules without explicit written authorization.**

---

## Security & Operational Safety

### Authorization Gates

| Category | Gate |
| --- | --- |
| `ENUM` / `PRIVESC` | Read-only — no confirmation required |
| `EXPLOIT` / `PERSIST` / `BACKDOOR` / `EXFIL` | Destructive — requires explicit `CONFIRM` input |
| `EXFIL` (read-only variants) | No confirmation (metadata only) |

### Credential Handling

- Credentials never logged, printed, or stored in output files
- Access keys masked in status bars (`AKIA****`)
- Session tokens not persisted
- Supports MFA-protected assume-role chains

### OPSEC Considerations

- All API calls go through your credentials — visible in CloudTrail
- Built-in rate limiting (`rate_limit: 10.0` req/s default)
- No automatic credential harvesting from target environments
- Results stored locally in `output/<profile>/`

### Responsible Use

awsProwl is designed for **authorized security testing only**.

- Obtain written permission before assessing any AWS account
- Destructive modules can create/modify/delete resources — understand the impact first
- Exfiltration modules access sensitive data — handle per your data classification policy
- Comply with the AWS Acceptable Use Policy and your organization's rules of engagement

---

## Troubleshooting

| Issue | Resolution |
| --- | --- |
| `Authentication failed` | Verify profile exists: `aws configure list-profiles`. Check credentials: `aws sts get-caller-identity --profile <name>` |
| `AccessDenied` on module | Module requires additional IAM permissions. Run with `--verbose` to see the exact API call |
| `No module found` | Use `search <query>` in the REPL or check `awsprowl config list` |
| `Region not supported` | Some services are global (IAM, STS, CloudFront). Use `us-east-1` for global services |
| `Scan hangs` | Check network connectivity to AWS endpoints. Increase `timeout_per_service` |
| `TUI won't start` | Ensure terminal supports ANSI colors. Try `awsprowl --no-tui` |
| `Import errors` | Reinstall: `pip install -e . --force-reinstall --no-deps` |

### Debug Mode

```bash
awsprowl -vvv scan production us-east-1 quick
# Or set in config:
# logging:
# level: "DEBUG"
```

---

## Quick Reference Card

**Quick security assessment:**

```bash
awsprowl scan default us-east-1 quick --output html --output-dir ./report
```

**Deep compliance scan:**

```bash
awsprowl scan production all compliance --output sarif --output-dir ./compliance
```

**Interactive exploration:**

```bash
awsprowl # TUI
# Then: run iam, run ec2, search privesc, etc.
```

**Classic shell workflow:**

```bash
awsprowl --no-tui
# Then: set_keys, run iam, run ec2_check_public_ips, search public
```

**CI/CD integration:**

```bash
awsprowl scan default us-east-1 standard --output sarif --output-dir ./artifacts --quiet
# Upload artifacts/scan-*.sarif to security scanner
```

---

## Acknowledgements

**[Pacu](https://github.com/RhinoSecurityLabs/pacu)** — an established AWS exploitation framework whose research and techniques have contributed to the broader AWS offensive-security ecosystem. awsProwl acknowledges this work while maintaining its own implementation, workflows, and project direction.

---

## Author

**KR1SHNA35** — [GitHub](https://github.com/KR1SHNA35)

## License

MIT License — see [LICENSE](LICENSE) for details.

```
Copyright (c) 2024 awsProwl Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Disclaimer

**awsProwl is intended for authorized security testing and assessment only.**

Use only on AWS accounts you own or have explicit written permission to test. Destructive modules (`EXPLOIT`, `PERSIST`, `BACKDOOR`, `EXFIL`) modify live resources — exfiltration modules access sensitive data, so handle it per your classification policy. The authors assume no liability for misuse, damage, or legal consequences. Comply with the AWS Acceptable Use Policy, your local laws, and your engagement's rules of engagement.

### *Stay authorized. Stay safe. Stalk responsibly.*
