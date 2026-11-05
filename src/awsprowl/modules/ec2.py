"""
EC2 Service Modules - All EC2-related features across categories

This module provides a unified interface for all EC2 operations:
- enum: Enumeration (safe, read-only)
- privesc: Privilege escalation analysis
- exploit: Active exploitation
- persist: Persistence mechanisms
- backdoor: Covert access
- exfil: Data exfiltration
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="ec2_enum_resources",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate EC2 resources: instances, security groups, VPCs, subnets, volumes, snapshots, AMIs, key pairs, EIPs, NACLs, NAT gateways, route tables, internet gateways, VPC endpoints, launch templates, instance connect endpoints, placement groups, dedicated hosts, capacity reservations, network interfaces, transit gateways, VPC peering, VPN connections, and customer gateways.",
    required_permissions=[
        "ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs",
        "ec2:DescribeSubnets", "ec2:DescribeVolumes", "ec2:DescribeSnapshots",
        "ec2:DescribeImages", "ec2:DescribeKeyPairs", "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeAddresses", "ec2:DescribeInstanceAttribute", "ec2:DescribeNetworkAcls",
        "ec2:DescribeRouteTables", "ec2:DescribeInternetGateways", "ec2:DescribeNatGateways",
        "ec2:DescribeVpcEndpoints", "ec2:DescribeVpcEndpointServices",
        "ec2:DescribeLaunchTemplates", "ec2:DescribeLaunchTemplateVersions",
        "ec2:DescribeInstanceConnectEndpoints", "ec2:DescribePlacementGroups",
        "ec2:DescribeHosts", "ec2:DescribeCapacityReservations",
        "ec2:DescribeTransitGateways", "ec2:DescribeTransitGatewayAttachments",
        "ec2:DescribeTransitGatewayRouteTables", "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeVpnConnections", "ec2:DescribeCustomerGateways", "ec2:DescribeFlowLogs",
        "iam:GetInstanceProfile", "iam:GetRole", "iam:GetRolePolicy",
        "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:GetPolicy", "iam:GetPolicyVersion"
    ],
    supported_services=["ec2", "iam"],
    mitre_techniques=["T1087.004", "T1046", "T1526"],
    tags=["ec2", "enum", "resources", "safe"],
    requires_confirmation=False,
))

# ==================== PRIVESC MODULES ====================
register_module(ModuleMetadata(
    name="ec2_privesc_analysis",
    category=ModuleCategory.PRIVESC,
    risk=ModuleRisk.SAFE,
    description="Analyze EC2 resources for privilege escalation: instance profile abuse, user data injection, security group modification, launch template abuse, ENI attachment, and Instance Connect endpoints.",
    required_permissions=[
        "ec2:DescribeInstances", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs",
        "ec2:DescribeSubnets", "ec2:DescribeNetworkInterfaces", "ec2:DescribeAddresses",
        "ec2:DescribeInstanceAttribute", "ec2:DescribeNetworkAcls",
        "ec2:DescribeRouteTables", "ec2:DescribeInternetGateways", "ec2:DescribeNatGateways",
        "ec2:DescribeVpcEndpoints", "ec2:DescribeLaunchTemplates",
        "ec2:DescribeLaunchTemplateVersions", "ec2:DescribeInstanceConnectEndpoints",
        "ec2:DescribePlacementGroups", "ec2:DescribeHosts", "ec2:DescribeCapacityReservations",
        "ec2:DescribeTransitGateways", "ec2:DescribeTransitGatewayAttachments",
        "ec2:DescribeTransitGatewayRouteTables", "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeVpnConnections", "ec2:DescribeCustomerGateways", "ec2:DescribeFlowLogs",
        "iam:GetInstanceProfile", "iam:GetRole", "iam:GetRolePolicy",
        "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:GetPolicy", "iam:GetPolicyVersion"
    ],
    supported_services=["ec2", "iam"],
    mitre_techniques=["T1087.004", "T1046", "T1078.004", "T1526"],
    tags=["ec2", "privesc", "analysis", "safe"],
    requires_confirmation=False,
))

# ==================== EXPLOIT MODULES ====================
register_module(ModuleMetadata(
    name="ec2_exploit_run_instances",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Launch EC2 instances with user data for code execution. DESTRUCTIVE - creates compute resources.",
    required_permissions=["ec2:RunInstances", "ec2:DescribeInstances", "ec2:DescribeImages", "iam:PassRole"],
    supported_services=["ec2", "iam"],
    mitre_techniques=["T1059.004", "T1611", "T1078.004"],
    tags=["ec2", "exploit", "run-instances", "code-execution", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_exploit_modify_instance_attribute",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Modify instance attributes: user data, IAM profile, security groups. DESTRUCTIVE.",
    required_permissions=["ec2:ModifyInstanceAttribute", "ec2:DescribeInstances", "iam:PassRole"],
    supported_services=["ec2", "iam"],
    mitre_techniques=["T1059.004", "T1078.004"],
    tags=["ec2", "exploit", "modify-attribute", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_exploit_create_security_group",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.MEDIUM,
    description="Create permissive security group for network access. DESTRUCTIVE - opens network access.",
    required_permissions=["ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:DescribeVpcs"],
    supported_services=["ec2"],
    mitre_techniques=["T1046", "T1562.007"],
    tags=["ec2", "exploit", "security-group", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_exploit_create_launch_template",
    category=ModuleCategory.EXPLOIT,
    risk=ModuleRisk.HIGH,
    description="Create launch template with user data for persistent code execution. DESTRUCTIVE.",
    required_permissions=["ec2:CreateLaunchTemplate", "ec2:DescribeLaunchTemplates", "iam:PassRole"],
    supported_services=["ec2", "iam"],
    mitre_techniques=["T1059.004", "T1556.002"],
    tags=["ec2", "exploit", "launch-template", "persistence", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== PERSIST MODULES ====================
register_module(ModuleMetadata(
    name="ec2_persist_user_data",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Modify instance user data for persistent code execution on reboot. DESTRUCTIVE.",
    required_permissions=["ec2:ModifyInstanceAttribute", "ec2:DescribeInstances", "ec2:StopInstances", "ec2:StartInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1059.004", "T1505.003", "T1556.002"],
    tags=["ec2", "persist", "user-data", "reboot-persistence", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_persist_launch_template",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create launch template with user data for persistent instance deployment. DESTRUCTIVE.",
    required_permissions=["ec2:CreateLaunchTemplate", "ec2:CreateLaunchTemplateVersion", "ec2:DescribeLaunchTemplates", "iam:PassRole"],
    supported_services=["ec2", "iam"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611"],
    tags=["ec2", "persist", "launch-template", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_persist_ami",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create custom AMI with backdoored software for persistent deployment. DESTRUCTIVE.",
    required_permissions=["ec2:CreateImage", "ec2:DescribeImages", "ec2:RegisterImage", "ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611"],
    tags=["ec2", "persist", "ami", "golden-image", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_persist_security_group",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.MEDIUM,
    description="Create/modify security group for persistent network access. DESTRUCTIVE.",
    required_permissions=["ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress", "ec2:DescribeSecurityGroups", "ec2:DescribeVpcs"],
    supported_services=["ec2"],
    mitre_techniques=["T1046", "T1562.007"],
    tags=["ec2", "persist", "security-group", "network", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_persist_key_pair",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Create/import key pair for persistent SSH access. DESTRUCTIVE.",
    required_permissions=["ec2:CreateKeyPair", "ec2:ImportKeyPair", "ec2:DescribeKeyPairs"],
    supported_services=["ec2"],
    mitre_techniques=["T1078.004", "T1556.002"],
    tags=["ec2", "persist", "key-pair", "ssh", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_persist_instance_profile",
    category=ModuleCategory.PERSIST,
    risk=ModuleRisk.HIGH,
    description="Associate IAM instance profile with instance for persistent role assumption. DESTRUCTIVE.",
    required_permissions=["ec2:AssociateIamInstanceProfile", "ec2:DescribeIamInstanceProfileAssociations", "ec2:DescribeInstances", "iam:PassRole"],
    supported_services=["ec2", "iam"],
    mitre_techniques=["T1078.004", "T1556.002"],
    tags=["ec2", "persist", "instance-profile", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

# ==================== BACKDOOR MODULES ====================
register_module(ModuleMetadata(
    name="ec2_backdoor_instance_connect",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create EC2 Instance Connect Endpoint for covert SSH/RDP access. DESTRUCTIVE.",
    required_permissions=["ec2:CreateInstanceConnectEndpoint", "ec2:DescribeInstanceConnectEndpoints", "ec2:DeleteInstanceConnectEndpoint", "ec2:DescribeVpcs", "ec2:DescribeSubnets"],
    supported_services=["ec2"],
    mitre_techniques=["T1021.004", "T1505.003", "T1133"],
    tags=["ec2", "backdoor", "instance-connect", "ssh", "rdp", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_backdoor_ssm_agent",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Install/configure SSM Agent on instances for agent-based backdoor access. DESTRUCTIVE.",
    required_permissions=["ssm:CreateAssociation", "ssm:SendCommand", "ec2:DescribeInstances", "iam:PassRole"],
    supported_services=["ssm", "ec2", "iam"],
    mitre_techniques=["T1505.003", "T1569.002", "T1021.004"],
    tags=["ec2", "backdoor", "ssm", "agent", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_backdoor_user_data_script",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Embed reverse shell/backdoor in instance user data for persistent access on boot. DESTRUCTIVE.",
    required_permissions=["ec2:RunInstances", "ec2:ModifyInstanceAttribute", "ec2:DescribeInstances", "ec2:DescribeImages"],
    supported_services=["ec2"],
    mitre_techniques=["T1059.004", "T1505.003", "T1556.002", "T1611"],
    tags=["ec2", "backdoor", "user-data", "reverse-shell", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_backdoor_ami_implant",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.HIGH,
    description="Create custom AMI with pre-installed backdoor (SSH keys, agents, cron jobs). DESTRUCTIVE.",
    required_permissions=["ec2:CreateImage", "ec2:RegisterImage", "ec2:DescribeImages", "ec2:DescribeInstances", "ec2:RunInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1059.004", "T1505.003", "T1611", "T1556.002"],
    tags=["ec2", "backdoor", "ami", "golden-image", "implant", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_backdoor_security_group_hidden",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Create security group with non-standard ports/protocols for covert C2. DESTRUCTIVE.",
    required_permissions=["ec2:CreateSecurityGroup", "ec2:AuthorizeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupEgress", "ec2:DescribeVpcs"],
    supported_services=["ec2"],
    mitre_techniques=["T1046", "T1571", "T1572"],
    tags=["ec2", "backdoor", "security-group", "c2", "covert", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_backdoor_eip_association",
    category=ModuleCategory.BACKDOOR,
    risk=ModuleRisk.MEDIUM,
    description="Allocate and associate Elastic IP for persistent public backdoor endpoint.",
    required_permissions=["ec2:AllocateAddress", "ec2:AssociateAddress", "ec2:DescribeAddresses", "ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1021.004", "T1505.003"],
    tags=["ec2", "backdoor", "eip", "persistent-ip"],
    requires_confirmation=True,
))

# ==================== EXFIL MODULES ====================
register_module(ModuleMetadata(
    name="ec2_exfil_user_data",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Extract EC2 instance user data (often contains secrets, scripts, configs).",
    required_permissions=["ec2:DescribeInstanceAttribute", "ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1555.005", "T1530"],
    tags=["ec2", "exfil", "user-data", "secrets"],
    requires_confirmation=True,
))

register_module(ModuleMetadata(
    name="ec2_exfil_ebs_snapshot",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Create EBS snapshot and share to attacker account for volume data exfiltration. DESTRUCTIVE.",
    required_permissions=["ec2:CreateSnapshot", "ec2:DescribeSnapshots", "ec2:ModifySnapshotAttribute", "ec2:DescribeVolumes", "ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["ec2", "exfil", "ebs", "snapshot", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_exfil_ami",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Create AMI from instance and share to attacker account for full system exfiltration. DESTRUCTIVE.",
    required_permissions=["ec2:CreateImage", "ec2:DescribeImages", "ec2:ModifyImageAttribute", "ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1530", "T1020", "T1611"],
    tags=["ec2", "exfil", "ami", "system-image", "cross-account", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_exfil_instance_metadata",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.MEDIUM,
    description="Extract EC2 instance metadata (IAM role credentials, user data, tags) via IMDS.",
    required_permissions=["ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1555.005", "T1530", "T1041"],
    tags=["ec2", "exfil", "metadata", "imds", "credentials"],
    requires_confirmation=True,
))

# ==================== EBS EXFIL MODULES (PROWL parity) ====================
register_module(ModuleMetadata(
    name="ec2_exfil_ebs_snapshot_download",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Download EBS snapshots to attacker-controlled account/region for offline analysis. PROWL: ebs__download_snapshots. DESTRUCTIVE.",
    required_permissions=["ec2:CreateSnapshot", "ec2:DescribeSnapshots", "ec2:ModifySnapshotAttribute", "ec2:DescribeVolumes", "ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["ec2", "exfil", "ebs", "snapshot", "download", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_exfil_ebs_snapshot_explore",
    category=ModuleCategory.EXFIL,
    risk=ModuleRisk.HIGH,
    description="Explore/mount EBS snapshots to extract files without full volume restore. PROWL: ebs__explore_snapshots. DESTRUCTIVE.",
    required_permissions=["ec2:CreateSnapshot", "ec2:DescribeSnapshots", "ec2:CreateVolume", "ec2:AttachVolume", "ec2:DescribeVolumes", "ec2:DescribeInstances"],
    supported_services=["ec2"],
    mitre_techniques=["T1530", "T1020", "T1041"],
    tags=["ec2", "exfil", "ebs", "snapshot", "explore", "mount", "awsprowl", "destructive"],
    requires_confirmation=True,
    destructive=True,
))

register_module(ModuleMetadata(
    name="ec2_enum_ebs_snapshots_unauth",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate publicly accessible EBS snapshots (unauthenticated). PROWL: ebs__enum_snapshots_unauth.",
    required_permissions=["ec2:DescribeSnapshots"],
    supported_services=["ec2"],
    mitre_techniques=["T1526", "T1083"],
    tags=["ec2", "enum", "ebs", "snapshots", "public", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="ec2_enum_volumes_snapshots",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate EBS volumes and their associated snapshots. PROWL: ebs__enum_volumes_snapshots.",
    required_permissions=["ec2:DescribeVolumes", "ec2:DescribeSnapshots"],
    supported_services=["ec2"],
    mitre_techniques=["T1526", "T1083"],
    tags=["ec2", "enum", "ebs", "volumes", "snapshots", "awsprowl"],
    requires_confirmation=False,
))

# List all EC2 modules
EC2_MODULES = [
    # Enum
    "ec2_enum_resources",
    "ec2_enum_ebs_snapshots_unauth",
    "ec2_enum_volumes_snapshots",
    # Privesc
    "ec2_privesc_analysis",
    # Exploit
    "ec2_exploit_run_instances", "ec2_exploit_modify_instance_attribute", "ec2_exploit_create_security_group",
    "ec2_exploit_create_launch_template",
    # Persist
    "ec2_persist_user_data", "ec2_persist_launch_template", "ec2_persist_ami",
    "ec2_persist_security_group", "ec2_persist_key_pair", "ec2_persist_instance_profile",
    # Backdoor
    "ec2_backdoor_instance_connect", "ec2_backdoor_ssm_agent", "ec2_backdoor_user_data_script",
    "ec2_backdoor_ami_implant", "ec2_backdoor_security_group_hidden", "ec2_backdoor_eip_association",
    # Exfil
    "ec2_exfil_user_data", "ec2_exfil_ebs_snapshot", "ec2_exfil_ami", "ec2_exfil_instance_metadata",
    "ec2_exfil_ebs_snapshot_download", "ec2_exfil_ebs_snapshot_explore",
]

__all__ = ["EC2_MODULES"]
