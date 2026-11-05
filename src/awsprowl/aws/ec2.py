"""EC2 scanner for awsProwl."""

from __future__ import annotations

import asyncio

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class EC2Scanner(AWSServiceBase):
    """Scanner for EC2 resources."""

    SERVICE_NAME = "ec2"
    REQUIRED_PERMISSIONS = [
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots",
        "ec2:DescribeImages",
        "ec2:DescribeKeyPairs",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeAddresses",
        "ec2:DescribeInstanceAttribute",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeRouteTables",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNatGateways",
        "ec2:DescribeVpcEndpoints",
        "ec2:DescribeVpcEndpointServices",
        "ec2:DescribeLaunchTemplates",
        "ec2:DescribeLaunchTemplateVersions",
        "ec2:DescribeInstanceConnectEndpoints",
        "ec2:DescribePlacementGroups",
        "ec2:DescribeHosts",
        "ec2:DescribeCapacityReservations",
        "ec2:DescribeTransitGateways",
        "ec2:DescribeTransitGatewayAttachments",
        "ec2:DescribeTransitGatewayRouteTables",
        "ec2:DescribeVpcPeeringConnections",
        "ec2:DescribeVpnConnections",
        "ec2:DescribeCustomerGateways",
        "ec2:DescribeFlowLogs",
        "iam:GetInstanceProfile",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    @property
    def iam_client(self):
        """Get or create the IAM client."""
        if not hasattr(self, '_iam_client') or self._iam_client is None:
            self._iam_client = self.auth_manager.get_client(
                "iam",
                region=self.region,
                config=self.config,
            )
        return self._iam_client

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan EC2 resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)

        try:
            # Run all scans in parallel
            await asyncio.gather(
                self._scan_instances(scan_id, findings, result),
                self._scan_security_groups(scan_id, findings, result),
                self._scan_vpcs(scan_id, findings, result),
                self._scan_subnets(scan_id, findings, result),
                self._scan_volumes(scan_id, findings, result),
                self._scan_snapshots(scan_id, findings, result),
                self._scan_amis(scan_id, findings, result),
                self._scan_key_pairs(scan_id, findings, result),
                self._scan_eips(scan_id, findings, result),
                self._scan_nacls(scan_id, findings, result),
                self._scan_nat_gateways(scan_id, findings, result),
                self._scan_route_tables(scan_id, findings, result),
                self._scan_internet_gateways(scan_id, findings, result),
                self._scan_vpc_endpoints(scan_id, findings, result),
                self._scan_launch_templates(scan_id, findings, result),
                self._scan_instance_connect_endpoints(scan_id, findings, result),
                self._scan_placement_groups(scan_id, findings, result),
                self._scan_dedicated_hosts(scan_id, findings, result),
                self._scan_capacity_reservations(scan_id, findings, result),
                self._scan_network_interfaces(scan_id, findings, result),
                self._scan_transit_gateways(scan_id, findings, result),
                self._scan_vpc_peering(scan_id, findings, result),
                self._scan_vpn_connections(scan_id, findings, result),
                self._scan_customer_gateways(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in EC2 scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_instances(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan EC2 instances."""
        try:
            paginator = self.client.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        result.resources_found += 1
                        await self._analyze_instance(instance, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeInstances", findings)

    async def _analyze_instance(self, instance: dict, scan_id: str, findings: list) -> None:
        """Analyze a single EC2 instance for security issues."""
        instance_id = instance["InstanceId"]
        state = instance.get("State", {}).get("Name", "unknown")

        # Add enumeration finding
        await self._add_enumeration_finding("ec2_instance", instance_id, instance_id, {
            "instance_type": instance.get("InstanceType", ""),
            "state": state,
            "launch_time": str(instance.get("LaunchTime", "")),
            "platform": instance.get("Platform", ""),
            "vpc_id": instance.get("VpcId", ""),
            "subnet_id": instance.get("SubnetId", ""),
            "private_ip": instance.get("PrivateIpAddress", ""),
            "public_ip": instance.get("PublicIpAddress", ""),
            "security_groups": [sg.get("GroupId", "") for sg in instance.get("SecurityGroups", [])],
            "iam_instance_profile": instance.get("IamInstanceProfile", {}).get("Arn", "") if instance.get("IamInstanceProfile") else "",
            "monitoring": instance.get("Monitoring", {}).get("State", ""),
        }, findings, scan_id)

        # Skip terminated instances
        if state == "terminated":
            return

        # Check for public IP
        public_ip = instance.get("PublicIpAddress")
        if public_ip:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Instance {instance_id} has public IP",
                description=f"EC2 instance {instance_id} has a public IP address ({public_ip}) which may expose it to the internet",
                severity="medium",
                category="network_exposure",
                resource_type="ec2_instance",
                resource_id=instance_id,
                resource_name=instance_id,
                region=self.region,
                evidence=[{"type": "instance_attribute", "description": "Public IP address", "data": {"public_ip": public_ip}}],
                remediation={
                    "summary": "Remove public IP or restrict access via security groups",
                    "steps": [
                        "Review if public IP is necessary",
                        "If not needed, disassociate Elastic IP or use NAT Gateway",
                        "Restrict inbound traffic via security groups",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        "aws ec2 disassociate-address --association-id <association-id>",
                    ],
                },
                rule_id="ec2_public_ip",
            ))

        # Check for IMDSv1 (metadata service v1)
        metadata_options = instance.get("MetadataOptions", {})
        http_tokens = metadata_options.get("HttpTokens", "optional")
        if http_tokens == "optional":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Instance {instance_id} allows IMDSv1",
                description="EC2 instance allows Instance Metadata Service Version 1 (IMDSv1) which is vulnerable to SSRF attacks",
                severity="high",
                category="vulnerable_configuration",
                resource_type="ec2_instance",
                resource_id=instance_id,
                resource_name=instance_id,
                region=self.region,
                evidence=[{"type": "instance_attribute", "description": "IMDS configuration", "data": metadata_options}],
                remediation={
                    "summary": "Enforce IMDSv2",
                    "steps": [
                        "Modify instance metadata options to require IMDSv2",
                        "Test applications for compatibility",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws ec2 modify-instance-metadata-options --instance-id {instance_id} --http-tokens required --http-endpoint enabled",
                    ],
                },
                rule_id="ec2_imdsv1_enabled",
            ))

        # Check for user data (potential secrets)
        try:
            attr = self.client.describe_instance_attribute(
                InstanceId=instance_id,
                Attribute="userData",
            )
            user_data = attr.get("UserData", {}).get("Value", "")
            if user_data:
                # Check for potential secrets in user data
                import base64
                try:
                    decoded = base64.b64decode(user_data).decode("utf-8", errors="ignore")
                    if any(keyword in decoded.lower() for keyword in ["password", "secret", "key", "token", "api_key", "access_key"]):
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"Instance {instance_id} user data may contain secrets",
                            description="EC2 instance user data contains potential secrets or credentials",
                            severity="high",
                            category="secrets_exposure",
                            resource_type="ec2_instance",
                            resource_id=instance_id,
                            resource_name=instance_id,
                            region=self.region,
                            evidence=[{"type": "user_data", "description": "User data with potential secrets", "data": {"preview": decoded[:200]}}],
                            remediation={
                                "summary": "Remove secrets from user data",
                                "steps": [
                                    "Move secrets to AWS Secrets Manager or Parameter Store",
                                    "Update instance to fetch secrets at runtime",
                                    "Remove sensitive data from user data",
                                ],
                                "effort": "medium",
                                "automatable": False,
                            },
                            rule_id="ec2_user_data_secrets",
                        ))
                except Exception:
                    pass
        except botocore.exceptions.ClientError:
            pass

        # Check for overly permissive security groups
        for sg in instance.get("SecurityGroups", []):
            sg_id = sg["GroupId"]
            await self._check_security_group_rules(sg_id, f"instance/{instance_id}", scan_id, findings)

        # Check IAM instance profile for excessive permissions
        iam_profile = instance.get("IamInstanceProfile")
        if iam_profile and iam_profile.get("Arn"):
            await self._check_instance_profile(iam_profile["Arn"], instance_id, scan_id, findings)

    async def _check_instance_profile(self, profile_arn: str, instance_id: str, scan_id: str, findings: list) -> None:
        """Check EC2 instance's IAM instance profile for excessive permissions."""
        try:
            # Get instance profile to find the role
            profile_name = profile_arn.split("/")[-1]
            profile = self.iam_client.get_instance_profile(InstanceProfileName=profile_name)

            for role in profile.get("InstanceProfile", {}).get("Roles", []):
                role_arn = role.get("Arn", "")
                role_name = role.get("RoleName", "")
                if role_arn:
                    await self._check_role_permissions(role_arn, role_name, f"instance/{instance_id}", scan_id, findings)

        except botocore.exceptions.ClientError:
            pass

    async def _check_role_permissions(self, role_arn: str, role_name: str, resource_id: str, scan_id: str, findings: list) -> None:
        """Check IAM role permissions for excessive access (similar to Lambda's check)."""
        try:
            # Get inline policies
            inline = self.iam_client.list_role_policies(RoleName=role_name)
            for policy_name in inline.get("PolicyNames", []):
                policy = self.iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                await self._check_policy_document(policy["PolicyDocument"], f"instance_role/{role_name}/inline/{policy_name}", resource_id, scan_id, findings)

            # Get attached policies
            attached = self.iam_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached.get("AttachedPolicies", []):
                policy_detail = self.iam_client.get_policy(PolicyArn=policy["PolicyArn"])
                version = self.iam_client.get_policy_version(
                    PolicyArn=policy["PolicyArn"],
                    VersionId=policy_detail["Policy"]["DefaultVersionId"],
                )
                await self._check_policy_document(version["PolicyVersion"]["Document"], f"instance_role/{role_name}/attached/{policy['PolicyName']}", resource_id, scan_id, findings)

        except botocore.exceptions.ClientError:
            pass

    async def _check_policy_document(self, policy_doc: dict, policy_id: str, resource_id: str, scan_id: str, findings: list) -> None:
        """Check a policy document for excessive permissions."""
        statements = policy_doc.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]

            # Check for wildcard action + wildcard resource
            has_wildcard_action = "*" in actions or any(a.endswith("*") for a in actions)
            has_wildcard_resource = "*" in resources

            if has_wildcard_action and has_wildcard_resource:
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"EC2 instance role {policy_id} has overly permissive policy",
                    description="Instance profile role policy allows all actions on all resources (full admin access)",
                    severity="critical",
                    category="excessive_permissions",
                    resource_type="ec2_instance",
                    resource_id=resource_id,
                    region=self.region,
                    evidence=[{"type": "role_policy", "description": f"Overly permissive policy {policy_id}", "data": policy_doc}],
                    remediation={
                        "summary": "Apply least privilege to EC2 instance role",
                        "steps": [
                            "Identify minimum required permissions for the instance",
                            "Create new policy with specific actions and resources",
                            "Attach new policy to role and remove overly permissive one",
                        ],
                        "effort": "medium",
                        "automatable": False,
                    },
                    rule_id="ec2_instance_role_wildcard_policy",
                ))

    async def _scan_security_groups(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan security groups."""
        try:
            paginator = self.client.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    result.resources_found += 1
                    await self._analyze_security_group(sg, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeSecurityGroups", findings)

    async def _analyze_security_group(self, sg: dict, scan_id: str, findings: list) -> None:
        """Analyze a single security group for security issues."""
        sg_id = sg["GroupId"]
        sg_name = sg["GroupName"]

        # Add enumeration finding
        await self._add_enumeration_finding("security_group", sg_id, sg_name, {
            "description": sg.get("Description", ""),
            "vpc_id": sg.get("VpcId", ""),
            "owner_id": sg.get("OwnerId", ""),
            "inbound_rules_count": len(sg.get("IpPermissions", [])),
            "outbound_rules_count": len(sg.get("IpPermissionsEgress", [])),
        }, findings, scan_id)

        await self._check_security_group_rules(sg_id, f"security_group/{sg_name}", scan_id, findings)

    async def _check_security_group_rules(self, sg_id: str, resource_id: str, scan_id: str, findings: list) -> None:
        """Check security group rules for overly permissive access."""
        try:
            sg = self.client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]

            for rule in sg.get("IpPermissions", []):
                await self._analyze_sg_rule(sg_id, resource_id, rule, "inbound", scan_id, findings)

            for rule in sg.get("IpPermissionsEgress", []):
                await self._analyze_sg_rule(sg_id, resource_id, rule, "outbound", scan_id, findings)

        except botocore.exceptions.ClientError:
            pass

    async def _analyze_sg_rule(self, sg_id: str, resource_id: str, rule: dict, direction: str, scan_id: str, findings: list) -> None:
        """Analyze a single security group rule."""
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        protocol = rule.get("IpProtocol", "-1")

        # Check IPv4 ranges
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if cidr == "0.0.0.0/0":
                self._check_open_port(sg_id, resource_id, direction, protocol, from_port, to_port, "0.0.0.0/0", scan_id, findings)

        # Check IPv6 ranges
        for ip_range in rule.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6", "")
            if cidr == "::/0":
                self._check_open_port(sg_id, resource_id, direction, protocol, from_port, to_port, "::/0", scan_id, findings)

    def _check_open_port(self, sg_id: str, resource_id: str, direction: str, protocol: str, from_port: int, to_port: int, cidr: str, scan_id: str, findings: list) -> None:
        """Check if an open port is dangerous."""
        # All ports
        if protocol == "-1" or (from_port == 0 and to_port == 65535):
            severity = "critical" if direction == "inbound" else "medium"
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Security group {sg_id} allows all {direction} traffic from {cidr}",
                description=f"Security group allows ALL {direction} traffic from anywhere ({cidr})",
                severity=severity,
                category="network_exposure" if direction == "inbound" else "data_exfiltration",
                resource_type="security_group",
                resource_id=sg_id,
                region=self.region,
                evidence=[{"type": "security_group_rule", "description": f"Open {direction} rule", "data": {"protocol": protocol, "from_port": from_port, "to_port": to_port, "cidr": cidr}}],
                remediation={
                    "summary": f"Restrict {direction} traffic to specific CIDR ranges",
                    "steps": [
                        "Identify required source/destination IPs",
                        "Update security group rules",
                        "Test connectivity",
                    ],
                    "effort": "low",
                    "automatable": True,
                },
                rule_id=f"ec2_sg_all_{direction}",
            ))
            return

        # Check specific dangerous ports
        dangerous_ports = {
            22: ("SSH", "high"),
            3389: ("RDP", "high"),
            3306: ("MySQL", "high"),
            5432: ("PostgreSQL", "high"),
            1433: ("MSSQL", "high"),
            27017: ("MongoDB", "high"),
            6379: ("Redis", "high"),
            9200: ("Elasticsearch", "high"),
            5601: ("Kibana", "medium"),
            8080: ("HTTP Alt", "medium"),
            8443: ("HTTPS Alt", "medium"),
        }

        for port in range(from_port, to_port + 1):
            if port in dangerous_ports and direction == "inbound":
                service_name, severity = dangerous_ports[port]
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"Security group {sg_id} exposes {service_name} (port {port}) to {cidr}",
                    description=f"Security group allows {direction} access to {service_name} on port {port} from {cidr}",
                    severity=severity,
                    category="network_exposure",
                    resource_type="security_group",
                    resource_id=sg_id,
                    region=self.region,
                    evidence=[{"type": "security_group_rule", "description": f"Open {direction} port", "data": {"port": port, "service": service_name, "cidr": cidr}}],
                    remediation={
                        "summary": f"Restrict {service_name} access to specific IPs",
                        "steps": [
                            "Identify required source IPs",
                            "Update security group to allow only those IPs",
                            "Consider using VPN or bastion host",
                        ],
                        "effort": "low",
                        "automatable": True,
                    },
                    rule_id=f"ec2_sg_{service_name.lower()}_exposed",
                ))

    async def _scan_vpcs(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan VPCs."""
        try:
            paginator = self.client.get_paginator("describe_vpcs")
            for page in paginator.paginate():
                for vpc in page.get("Vpcs", []):
                    result.resources_found += 1
                    await self._analyze_vpc(vpc, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeVpcs", findings)

    async def _analyze_vpc(self, vpc: dict, scan_id: str, findings: list) -> None:
        """Analyze a VPC for security issues."""
        vpc_id = vpc["VpcId"]
        is_default = vpc.get("IsDefault", False)

        # Add enumeration finding
        await self._add_enumeration_finding("vpc", vpc_id, vpc_id, {
            "cidr_block": vpc.get("CidrBlock", ""),
            "is_default": is_default,
            "state": vpc.get("State", ""),
            "dhcp_options_id": vpc.get("DhcpOptionsId", ""),
            "instance_tenancy": vpc.get("InstanceTenancy", ""),
        }, findings, scan_id)

        if is_default:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Default VPC in use: {vpc_id}",
                description="Default VPC is being used. Default VPCs have overly permissive default security groups and settings",
                severity="low",
                category="weak_configuration",
                resource_type="vpc",
                resource_id=vpc_id,
                resource_name=vpc_id,
                region=self.region,
                remediation={
                    "summary": "Use custom VPC with least-privilege configuration",
                    "steps": [
                        "Create custom VPC with private/public subnets",
                        "Configure NAT Gateway for outbound internet",
                        "Migrate resources to custom VPC",
                        "Delete default VPC if unused",
                    ],
                    "effort": "medium",
                    "automatable": False,
                },
                rule_id="ec2_default_vpc",
            ))

        # Check flow logs
        try:
            flow_logs = self.client.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            )
            if not flow_logs.get("FlowLogs"):
                self._add_finding_deduped(findings, self.create_finding(
                    title=f"VPC {vpc_id} has no flow logs",
                    description="VPC Flow Logs are not enabled, limiting network visibility and threat detection",
                    severity="medium",
                    category="logging_missing",
                    resource_type="vpc",
                    resource_id=vpc_id,
                    resource_name=vpc_id,
                    region=self.region,
                    remediation={
                        "summary": "Enable VPC Flow Logs",
                        "steps": [
                            "Create CloudWatch Logs group or S3 bucket for logs",
                            "Enable VPC Flow Logs",
                            "Configure log retention",
                        ],
                        "effort": "low",
                        "automatable": True,
                        "cli_commands": [
                            f"aws ec2 create-flow-logs --resource-type VPC --resource-ids {vpc_id} --traffic-type ALL --log-group-name vpc-flow-logs --deliver-logs-permission-arn arn:aws:iam::123456789012:role/flowlogs-role",
                        ],
                    },
                    rule_id="ec2_vpc_no_flow_logs",
                ))
        except botocore.exceptions.ClientError:
            pass

    async def _scan_subnets(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan subnets for security issues."""
        try:
            paginator = self.client.get_paginator("describe_subnets")
            for page in paginator.paginate():
                for subnet in page.get("Subnets", []):
                    result.resources_found += 1
                    await self._analyze_subnet(subnet, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeSubnets", findings)

    async def _analyze_subnet(self, subnet: dict, scan_id: str, findings: list) -> None:
        """Analyze a subnet for security issues."""
        subnet_id = subnet["SubnetId"]
        vpc_id = subnet.get("VpcId", "")
        cidr = subnet.get("CidrBlock", "")
        az = subnet.get("AvailabilityZone", "")
        map_public_ip = subnet.get("MapPublicIpOnLaunch", False)
        available_ips = subnet.get("AvailableIpAddressCount", 0)
        state = subnet.get("State", "unknown")

        # Add enumeration finding
        await self._add_enumeration_finding("subnet", subnet_id, subnet_id, {
            "vpc_id": vpc_id,
            "cidr_block": cidr,
            "availability_zone": az,
            "map_public_ip_on_launch": map_public_ip,
            "available_ip_count": available_ips,
            "state": state,
        }, findings, scan_id)

        # Check for public subnets (auto-assign public IP)
        if map_public_ip:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Subnet {subnet_id} auto-assigns public IPs",
                description=f"Subnet {subnet_id} in {az} (CIDR: {cidr}) is configured to auto-assign public IPs to instances. This may expose instances to the internet.",
                severity="medium",
                category="network_exposure",
                resource_type="subnet",
                resource_id=subnet_id,
                resource_name=subnet_id,
                region=self.region,
                evidence=[{"type": "subnet_config", "description": "Public subnet configuration", "data": {"subnet_id": subnet_id, "vpc_id": vpc_id, "cidr": cidr, "az": az, "map_public_ip_on_launch": map_public_ip}}],
                remediation={
                    "summary": "Disable auto-assign public IP or use NAT Gateway for outbound access",
                    "steps": [
                        "Disable MapPublicIpOnLaunch for this subnet",
                        "Configure NAT Gateway in public subnet for outbound internet",
                        "Move workloads to private subnets",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws ec2 modify-subnet-attribute --subnet-id {subnet_id} --no-map-public-ip-on-launch",
                    ],
                },
                rule_id="ec2_subnet_public",
            ))

        # Check for subnets with very few available IPs (capacity issue)
        if available_ips < 10 and state == "available":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"Subnet {subnet_id} has low IP capacity ({available_ips} IPs available)",
                description=f"Subnet {subnet_id} in {az} (CIDR: {cidr}) has only {available_ips} available IP addresses remaining",
                severity="low",
                category="availability",
                resource_type="subnet",
                resource_id=subnet_id,
                resource_name=subnet_id,
                region=self.region,
                evidence=[{"type": "subnet_config", "description": "IP capacity", "data": {"subnet_id": subnet_id, "cidr": cidr, "available_ips": available_ips}}],
                remediation={
                    "summary": "Plan for subnet expansion",
                    "steps": [
                        "Review subnet sizing and growth projections",
                        "Consider adding additional subnets or expanding CIDR",
                    ],
                    "effort": "medium",
                    "automatable": False,
                },
                rule_id="ec2_subnet_low_capacity",
            ))

        # Check for subnets without flow logs (via VPC flow logs - checked in VPC analysis)
        # This is informational - list the subnet
        self._add_finding_deduped(findings, self.create_finding(
            title=f"Subnet: {subnet_id} ({az})",
            description=f"Subnet CIDR: {cidr}, VPC: {vpc_id}, State: {state}, Available IPs: {available_ips}, Auto-assign Public IP: {map_public_ip}",
            severity="info",
            category="informational",
            resource_type="subnet",
            resource_id=subnet_id,
            resource_name=subnet_id,
            region=self.region,
            rule_id="ec2_list_subnets",
        ))

    async def _scan_volumes(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan EBS volumes."""
        try:
            paginator = self.client.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page.get("Volumes", []):
                    result.resources_found += 1
                    await self._analyze_volume(volume, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeVolumes", findings)

    async def _analyze_volume(self, volume: dict, scan_id: str, findings: list) -> None:
        """Analyze an EBS volume for security issues."""
        volume_id = volume["VolumeId"]
        encrypted = volume.get("Encrypted", False)

        # Add enumeration finding
        await self._add_enumeration_finding("ebs_volume", volume_id, volume_id, {
            "size_gb": volume.get("Size", 0),
            "encrypted": encrypted,
            "volume_type": volume.get("VolumeType", ""),
            "state": volume.get("State", ""),
            "availability_zone": volume.get("AvailabilityZone", ""),
            "snapshot_id": volume.get("SnapshotId", ""),
            "iops": volume.get("Iops", 0),
            "throughput": volume.get("Throughput", 0),
            "kms_key_id": volume.get("KmsKeyId", ""),
            "attachments": [{"instance_id": a.get("InstanceId", ""), "device": a.get("Device", ""), "state": a.get("State", "")} for a in volume.get("Attachments", [])],
        }, findings, scan_id)

        if not encrypted:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"EBS volume {volume_id} is not encrypted",
                description="EBS volume is not encrypted at rest, exposing data to physical access risks",
                severity="high",
                category="encryption_missing",
                resource_type="ebs_volume",
                resource_id=volume_id,
                resource_name=volume_id,
                region=self.region,
                remediation={
                    "summary": "Encrypt EBS volume",
                    "steps": [
                        "Create snapshot of volume",
                        "Create encrypted copy of snapshot",
                        "Create new encrypted volume from snapshot",
                        "Replace volume on instance",
                    ],
                    "effort": "medium",
                    "automatable": True,
                    "cli_commands": [
                        f"aws ec2 create-snapshot --volume-id {volume_id} --description 'For encryption'",
                        "aws ec2 copy-snapshot --source-snapshot-id <snap-id> --encrypted --kms-key-id <kms-key>",
                        "aws ec2 create-volume --snapshot-id <encrypted-snap> --availability-zone <az> --encrypted",
                    ],
                },
                rule_id="ec2_volume_unencrypted",
            ))

    async def _scan_snapshots(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan EBS snapshots."""
        try:
            # Only scan our own snapshots
            paginator = self.client.get_paginator("describe_snapshots")
            for page in paginator.paginate(OwnerIds=["self"]):
                for snapshot in page.get("Snapshots", []):
                    result.resources_found += 1
                    await self._analyze_snapshot(snapshot, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeSnapshots", findings)

    async def _analyze_snapshot(self, snapshot: dict, scan_id: str, findings: list) -> None:
        """Analyze an EBS snapshot for security issues."""
        snapshot_id = snapshot["SnapshotId"]
        encrypted = snapshot.get("Encrypted", False)

        # Add enumeration finding
        await self._add_enumeration_finding("ebs_snapshot", snapshot_id, snapshot_id, {
            "volume_id": snapshot.get("VolumeId", ""),
            "volume_size_gb": snapshot.get("VolumeSize", 0),
            "encrypted": encrypted,
            "state": snapshot.get("State", ""),
            "start_time": str(snapshot.get("StartTime", "")),
            "owner_id": snapshot.get("OwnerId", ""),
            "description": snapshot.get("Description", ""),
            "kms_key_id": snapshot.get("KmsKeyId", ""),
        }, findings, scan_id)

        if not encrypted:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"EBS snapshot {snapshot_id} is not encrypted",
                description="EBS snapshot is not encrypted at rest",
                severity="high",
                category="encryption_missing",
                resource_type="ebs_snapshot",
                resource_id=snapshot_id,
                resource_name=snapshot_id,
                region=self.region,
                remediation={
                    "summary": "Encrypt snapshot",
                    "steps": [
                        "Copy snapshot with encryption enabled",
                        "Delete unencrypted snapshot",
                    ],
                    "effort": "low",
                    "automatable": True,
                },
                rule_id="ec2_snapshot_unencrypted",
            ))

        # Check for public snapshots
        try:
            perms = self.client.describe_snapshot_attribute(
                SnapshotId=snapshot_id,
                Attribute="createVolumePermission",
            )
            for perm in perms.get("CreateVolumePermissions", []):
                if perm.get("Group") == "all":
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"EBS snapshot {snapshot_id} is public",
                        description="Snapshot is publicly accessible - anyone can create volumes from it",
                        severity="critical",
                        category="data_exposure",
                        resource_type="ebs_snapshot",
                        resource_id=snapshot_id,
                        resource_name=snapshot_id,
                        region=self.region,
                        remediation={
                            "summary": "Make snapshot private",
                            "steps": [
                                "Remove 'all' group from createVolumePermission",
                                "Add specific account IDs if sharing needed",
                            ],
                            "effort": "low",
                            "automatable": True,
                            "cli_commands": [
                                f"aws ec2 modify-snapshot-attribute --snapshot-id {snapshot_id} --attribute createVolumePermission --operation-type remove --group-names all",
                            ],
                        },
                        rule_id="ec2_snapshot_public",
                    ))
        except botocore.exceptions.ClientError:
            pass

    async def _scan_amis(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan AMIs."""
        try:
            paginator = self.client.get_paginator("describe_images")
            for page in paginator.paginate(Owners=["self"]):
                for ami in page.get("Images", []):
                    result.resources_found += 1
                    await self._analyze_ami(ami, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeImages", findings)

    async def _analyze_ami(self, ami: dict, scan_id: str, findings: list) -> None:
        """Analyze an AMI for security issues."""
        ami_id = ami["ImageId"]
        public = ami.get("Public", False)

        # Add enumeration finding
        await self._add_enumeration_finding("ami", ami_id, ami_id, {
            "name": ami.get("Name", ""),
            "description": ami.get("Description", ""),
            "public": public,
            "owner_id": ami.get("OwnerId", ""),
            "state": ami.get("State", ""),
            "architecture": ami.get("Architecture", ""),
            "root_device_type": ami.get("RootDeviceType", ""),
            "virtualization_type": ami.get("VirtualizationType", ""),
            "platform": ami.get("Platform", ""),
            "creation_date": ami.get("CreationDate", ""),
        }, findings, scan_id)

        if public:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"AMI {ami_id} is public",
                description="Custom AMI is publicly accessible",
                severity="high",
                category="data_exposure",
                resource_type="ami",
                resource_id=ami_id,
                resource_name=ami.get("Name", ami_id),
                region=self.region,
                remediation={
                    "summary": "Make AMI private",
                    "steps": [
                        "Remove public launch permission",
                        "Share with specific accounts if needed",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws ec2 modify-image-attribute --image-id {ami_id} --launch-permission 'Remove=[{{Group=all}}]'",
                    ],
                },
                rule_id="ec2_ami_public",
            ))

    async def _scan_key_pairs(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan key pairs."""
        try:
            response = self.client.describe_key_pairs()
            for key in response.get("KeyPairs", []):
                result.resources_found += 1
                key_name = key["KeyName"]
                key_type = key.get("KeyType", "rsa")
                key_format = key.get("KeyFormat", "pem")

                # Add enumeration finding
                await self._add_enumeration_finding("key_pair", key_name, key_name, {
                    "key_type": key_type,
                    "key_format": key_format,
                    "key_fingerprint": key.get("KeyFingerprint", ""),
                    "create_time": str(key.get("CreateTime", "")),
                }, findings, scan_id)

                # Check for old key types
                if key_type != "ed25519":
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Key pair {key_name} uses {key_type} instead of ed25519",
                        description=f"SSH key pair uses {key_type} which is less secure than ed25519",
                        severity="low",
                        category="weak_configuration",
                        resource_type="key_pair",
                        resource_id=key_name,
                        resource_name=key_name,
                        region=self.region,
                        remediation={
                            "summary": "Generate new ed25519 key pair",
                            "steps": [
                                "Generate new ed25519 key pair",
                                "Update instances/launch templates to use new key",
                                "Delete old key pair",
                            ],
                            "effort": "low",
                            "automatable": True,
                        },
                        rule_id="ec2_old_key_type",
                    ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeKeyPairs", findings)

    async def _scan_eips(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Elastic IPs."""
        try:
            response = self.client.describe_addresses()
            for eip in response.get("Addresses", []):
                result.resources_found += 1
                allocation_id = eip.get("AllocationId", "")
                instance_id = eip.get("InstanceId", "")
                network_interface_id = eip.get("NetworkInterfaceId", "")
                public_ip = eip.get("PublicIp", "")

                # Add enumeration finding
                await self._add_enumeration_finding("elastic_ip", allocation_id, public_ip, {
                    "public_ip": public_ip,
                    "allocation_id": allocation_id,
                    "instance_id": instance_id,
                    "network_interface_id": network_interface_id,
                    "private_ip": eip.get("PrivateIpAddress", ""),
                    "domain": eip.get("Domain", ""),
                    "network_border_group": eip.get("NetworkBorderGroup", ""),
                }, findings, scan_id)

                # Check for unattached EIPs (cost issue)
                if not instance_id and not network_interface_id:
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Unattached Elastic IP: {public_ip}",
                        description=f"Elastic IP {public_ip} is not associated with any resource (incurs charges)",
                        severity="low",
                        category="cost_optimization",
                        resource_type="elastic_ip",
                        resource_id=allocation_id,
                        resource_name=public_ip,
                        region=self.region,
                        remediation={
                            "summary": "Release unattached Elastic IP",
                            "steps": [
                                "Verify IP is not needed",
                                "Release the Elastic IP",
                            ],
                            "effort": "low",
                            "automatable": True,
                            "cli_commands": [
                                f"aws ec2 release-address --allocation-id {allocation_id}",
                            ],
                        },
                        rule_id="ec2_eip_unattached",
                    ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeAddresses", findings)

    async def _scan_nacls(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Network ACLs."""
        try:
            paginator = self.client.get_paginator("describe_network_acls")
            for page in paginator.paginate():
                for nacl in page.get("NetworkAcls", []):
                    result.resources_found += 1
                    await self._analyze_nacl(nacl, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeNetworkAcls", findings)

    async def _analyze_nacl(self, nacl: dict, scan_id: str, findings: list) -> None:
        """Analyze a Network ACL."""
        nacl_id = nacl["NetworkAclId"]
        is_default = nacl.get("IsDefault", False)

        # Add enumeration finding
        await self._add_enumeration_finding("network_acl", nacl_id, nacl_id, {
            "vpc_id": nacl.get("VpcId", ""),
            "is_default": is_default,
            "owner_id": nacl.get("OwnerId", ""),
            "entries_count": len(nacl.get("Entries", [])),
        }, findings, scan_id)

        for entry in nacl.get("Entries", []):
            if entry.get("RuleAction") == "allow" and entry.get("CidrBlock") == "0.0.0.0/0":
                port_range = entry.get("PortRange", {})
                from_port = port_range.get("From", 0)
                to_port = port_range.get("To", 65535)
                protocol = entry.get("Protocol", "-1")
                egress = entry.get("Egress", False)
                direction = "outbound" if egress else "inbound"

                if protocol == "-1" or (from_port == 0 and to_port == 65535):
                    severity = "medium" if direction == "inbound" else "low"
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"Network ACL {nacl_id} allows all {direction} traffic",
                        description=f"Network ACL allows ALL {direction} traffic from 0.0.0.0/0",
                        severity=severity,
                        category="network_exposure",
                        resource_type="network_acl",
                        resource_id=nacl_id,
                        region=self.region,
                        remediation={
                            "summary": "Restrict Network ACL rules",
                            "steps": [
                                "Review required traffic",
                                "Update NACL rules to specific ports/CIDRs",
                            ],
                            "effort": "medium",
                            "automatable": False,
                        },
                        rule_id=f"ec2_nacl_all_{direction}",
                    ))

    async def _scan_nat_gateways(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan NAT Gateways."""
        try:
            paginator = self.client.get_paginator("describe_nat_gateways")
            for page in paginator.paginate():
                for nat in page.get("NatGateways", []):
                    result.resources_found += 1
                    nat_id = nat["NatGatewayId"]
                    state = nat.get("State", "")

                    # Add enumeration finding
                    await self._add_enumeration_finding("nat_gateway", nat_id, nat_id, {
                        "state": state,
                        "vpc_id": nat.get("VpcId", ""),
                        "subnet_id": nat.get("SubnetId", ""),
                        "connectivity_type": nat.get("ConnectivityType", ""),
                        "create_time": str(nat.get("CreateTime", "")),
                    }, findings, scan_id)

                    if state == "available":
                        # Check if in public subnet (normal) but warn about cost
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"NAT Gateway {nat_id} is active",
                            description=f"NAT Gateway {nat_id} is running (incurs hourly charges + data processing fees)",
                            severity="info",
                            category="cost_optimization",
                            resource_type="nat_gateway",
                            resource_id=nat_id,
                            resource_name=nat_id,
                            region=self.region,
                            remediation={
                                "summary": "Review NAT Gateway necessity",
                                "steps": [
                                    "Verify if NAT Gateway is still needed",
                                    "Consider VPC endpoints for AWS services",
                                    "Delete if unused",
                                ],
                                "effort": "low",
                                "automatable": False,
                            },
                            rule_id="ec2_nat_gateway_active",
                        ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeNatGateways", findings)

    async def _scan_route_tables(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Route Tables."""
        try:
            paginator = self.client.get_paginator("describe_route_tables")
            for page in paginator.paginate():
                for rt in page.get("RouteTables", []):
                    result.resources_found += 1
                    rt_id = rt["RouteTableId"]
                    vpc_id = rt.get("VpcId", "")
                    is_main = any(a.get("Main", False) for a in rt.get("Associations", []))

                    await self._add_enumeration_finding("route_table", rt_id, rt_id, {
                        "vpc_id": vpc_id,
                        "is_main": is_main,
                        "owner_id": rt.get("OwnerId", ""),
                        "routes": rt.get("Routes", []),
                        "associations": rt.get("Associations", []),
                    }, findings, scan_id)

                    # Check for routes to IGW (public subnets)
                    for route in rt.get("Routes", []):
                        if route.get("GatewayId", "").startswith("igw-"):
                            self._add_finding_deduped(findings, self.create_finding(
                                title=f"Route table {rt_id} has route to Internet Gateway",
                                description=f"Route table routes 0.0.0.0/0 to IGW {route.get('GatewayId')}",
                                severity="info",
                                category="network_exposure",
                                resource_type="route_table",
                                resource_id=rt_id,
                                resource_name=rt_id,
                                region=self.region,
                                evidence=[{"type": "route", "description": "IGW route", "data": route}],
                                rule_id="ec2_rt_igw_route",
                            ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeRouteTables", findings)

    async def _scan_internet_gateways(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Internet Gateways."""
        try:
            paginator = self.client.get_paginator("describe_internet_gateways")
            for page in paginator.paginate():
                for igw in page.get("InternetGateways", []):
                    result.resources_found += 1
                    igw_id = igw["InternetGatewayId"]
                    attachments = igw.get("Attachments", [])

                    await self._add_enumeration_finding("internet_gateway", igw_id, igw_id, {
                        "attachments": attachments,
                        "owner_id": igw.get("OwnerId", ""),
                    }, findings, scan_id)

                    if not attachments:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"Internet Gateway {igw_id} is detached",
                            description="Internet Gateway is not attached to any VPC",
                            severity="low",
                            category="cost_optimization",
                            resource_type="internet_gateway",
                            resource_id=igw_id,
                            resource_name=igw_id,
                            region=self.region,
                            rule_id="ec2_igw_detached",
                        ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeInternetGateways", findings)

    async def _scan_vpc_endpoints(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan VPC Endpoints."""
        try:
            paginator = self.client.get_paginator("describe_vpc_endpoints")
            for page in paginator.paginate():
                for endpoint in page.get("VpcEndpoints", []):
                    result.resources_found += 1
                    endpoint_id = endpoint["VpcEndpointId"]
                    vpc_id = endpoint.get("VpcId", "")
                    service_name = endpoint.get("ServiceName", "")
                    endpoint_type = endpoint.get("VpcEndpointType", "")
                    state = endpoint.get("State", "")
                    policy = endpoint.get("PolicyDocument", "")

                    await self._add_enumeration_finding("vpc_endpoint", endpoint_id, endpoint_id, {
                        "vpc_id": vpc_id,
                        "service_name": service_name,
                        "type": endpoint_type,
                        "state": state,
                        "has_policy": bool(policy),
                        "route_table_ids": endpoint.get("RouteTableIds", []),
                        "subnet_ids": endpoint.get("SubnetIds", []),
                        "security_group_ids": endpoint.get("Groups", []),
                    }, findings, scan_id)

                    # Check for overly permissive endpoint policy
                    if policy:
                        import json
                        policy_doc = json.loads(policy)
                        statements = policy_doc.get("Statement", [])
                        if not isinstance(statements, list):
                            statements = [statements]
                        for stmt in statements:
                            if stmt.get("Effect") == "Allow":
                                principal = stmt.get("Principal", {})
                                if principal == "*" or principal.get("AWS") == "*":
                                    actions = stmt.get("Action", [])
                                    if isinstance(actions, str):
                                        actions = [actions]
                                    if "*" in actions:
                                        self._add_finding_deduped(findings, self.create_finding(
                                            title=f"VPC Endpoint {endpoint_id} has overly permissive policy",
                                            description="Endpoint policy allows all actions from any principal",
                                            severity="high",
                                            category="excessive_permissions",
                                            resource_type="vpc_endpoint",
                                            resource_id=endpoint_id,
                                            resource_name=endpoint_id,
                                            region=self.region,
                                            evidence=[{"type": "endpoint_policy", "description": "Permissive endpoint policy", "data": policy_doc}],
                                            rule_id="ec2_vpc_endpoint_permissive_policy",
                                        ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeVpcEndpoints", findings)

    async def _scan_launch_templates(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Launch Templates."""
        try:
            paginator = self.client.get_paginator("describe_launch_templates")
            for page in paginator.paginate():
                for lt in page.get("LaunchTemplates", []):
                    result.resources_found += 1
                    lt_id = lt["LaunchTemplateId"]
                    lt_name = lt["LaunchTemplateName"]
                    default_version = lt.get("DefaultVersionNumber", 0)
                    latest_version = lt.get("LatestVersionNumber", 0)

                    await self._add_enumeration_finding("launch_template", lt_id, lt_name, {
                        "id": lt_id,
                        "name": lt_name,
                        "default_version": default_version,
                        "latest_version": latest_version,
                        "create_time": str(lt.get("CreateTime", "")),
                        "created_by": lt.get("CreatedBy", ""),
                    }, findings, scan_id)

                    # Get versions
                    try:
                        versions = self.client.describe_launch_template_versions(LaunchTemplateId=lt_id)
                        for version in versions.get("LaunchTemplateVersions", []):
                            version_num = version["VersionNumber"]
                            template_data = version.get("LaunchTemplateData", {})

                            # Check for user data in template
                            user_data = template_data.get("UserData", "")
                            if user_data:
                                import base64
                                try:
                                    decoded = base64.b64decode(user_data).decode("utf-8", errors="ignore")
                                    if any(keyword in decoded.lower() for keyword in ["password", "secret", "key", "token", "api_key", "access_key"]):
                                        self._add_finding_deduped(findings, self.create_finding(
                                            title=f"Launch template {lt_name} version {version_num} user data may contain secrets",
                                            description="Launch template user data contains potential secrets",
                                            severity="high",
                                            category="secrets_exposure",
                                            resource_type="launch_template",
                                            resource_id=f"{lt_id}/{version_num}",
                                            resource_name=lt_name,
                                            region=self.region,
                                            evidence=[{"type": "user_data", "description": "User data with potential secrets", "data": {"preview": decoded[:200]}}],
                                            rule_id="ec2_lt_user_data_secrets",
                                        ))
                                except Exception:
                                    pass

                            # Check for IMDSv1 in template
                            metadata_options = template_data.get("MetadataOptions", {})
                            if metadata_options.get("HttpTokens") == "optional":
                                self._add_finding_deduped(findings, self.create_finding(
                                    title=f"Launch template {lt_name} version {version_num} allows IMDSv1",
                                    description="Launch template configures IMDSv1 (optional tokens)",
                                    severity="high",
                                    category="vulnerable_configuration",
                                    resource_type="launch_template",
                                    resource_id=f"{lt_id}/{version_num}",
                                    resource_name=lt_name,
                                    region=self.region,
                                    evidence=[{"type": "template_data", "description": "IMDSv1 configuration", "data": metadata_options}],
                                    rule_id="ec2_lt_imdsv1",
                                ))

                            # Check for public IP assignment
                            if template_data.get("NetworkInterfaces"):
                                for ni in template_data["NetworkInterfaces"]:
                                    if ni.get("AssociatePublicIpAddress"):
                                        self._add_finding_deduped(findings, self.create_finding(
                                            title=f"Launch template {lt_name} version {version_num} assigns public IP",
                                            description="Launch template configures network interface to assign public IP",
                                            severity="medium",
                                            category="network_exposure",
                                            resource_type="launch_template",
                                            resource_id=f"{lt_id}/{version_num}",
                                            resource_name=lt_name,
                                            region=self.region,
                                            rule_id="ec2_lt_public_ip",
                                        ))

                    except botocore.exceptions.ClientError:
                        pass

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeLaunchTemplates", findings)

    async def _scan_instance_connect_endpoints(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan EC2 Instance Connect Endpoints."""
        try:
            paginator = self.client.get_paginator("describe_instance_connect_endpoints")
            for page in paginator.paginate():
                for endpoint in page.get("InstanceConnectEndpoints", []):
                    result.resources_found += 1
                    endpoint_id = endpoint["InstanceConnectEndpointId"]
                    state = endpoint.get("State", "")
                    vpc_id = endpoint.get("VpcId", "")
                    subnet_id = endpoint.get("SubnetId", "")

                    await self._add_enumeration_finding("instance_connect_endpoint", endpoint_id, endpoint_id, {
                        "state": state,
                        "vpc_id": vpc_id,
                        "subnet_id": subnet_id,
                        "security_group_ids": endpoint.get("SecurityGroupIds", []),
                        "preserve_client_ip": endpoint.get("PreserveClientIp", False),
                    }, findings, scan_id)

                    if state == "create-complete":
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"EC2 Instance Connect Endpoint {endpoint_id} is active",
                            description="Instance Connect Endpoint allows SSH/RDP access to instances without public IPs",
                            severity="info",
                            category="enumeration",
                            resource_type="instance_connect_endpoint",
                            resource_id=endpoint_id,
                            resource_name=endpoint_id,
                            region=self.region,
                            rule_id="ec2_ice_active",
                        ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] not in ("InvalidAction", "UnsupportedOperation"):
                self.handle_client_error(e, "DescribeInstanceConnectEndpoints", findings)

    async def _scan_placement_groups(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Placement Groups."""
        try:
            response = self.client.describe_placement_groups()
            for pg in response.get("PlacementGroups", []):
                result.resources_found += 1
                pg_name = pg["GroupName"]
                strategy = pg.get("Strategy", "")
                state = pg.get("State", "")

                await self._add_enumeration_finding("placement_group", pg_name, pg_name, {
                    "strategy": strategy,
                    "state": state,
                    "partition_count": pg.get("PartitionCount", 0),
                }, findings, scan_id)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribePlacementGroups", findings)

    async def _scan_dedicated_hosts(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Dedicated Hosts."""
        try:
            paginator = self.client.get_paginator("describe_hosts")
            for page in paginator.paginate():
                for host in page.get("Hosts", []):
                    result.resources_found += 1
                    host_id = host["HostId"]
                    state = host.get("State", "")
                    availability_zone = host.get("AvailabilityZone", "")
                    instance_type = host.get("InstanceType", "")

                    await self._add_enumeration_finding("dedicated_host", host_id, host_id, {
                        "state": state,
                        "availability_zone": availability_zone,
                        "instance_type": instance_type,
                        "auto_placement": host.get("AutoPlacement", ""),
                        "availability": host.get("Availability", ""),
                    }, findings, scan_id)

                    if state == "available":
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"Dedicated Host {host_id} is available (cost)",
                            description=f"Dedicated Host {host_id} in {availability_zone} is available (incurs hourly charges)",
                            severity="info",
                            category="cost_optimization",
                            resource_type="dedicated_host",
                            resource_id=host_id,
                            resource_name=host_id,
                            region=self.region,
                            rule_id="ec2_host_available",
                        ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeHosts", findings)

    async def _scan_capacity_reservations(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Capacity Reservations."""
        try:
            paginator = self.client.get_paginator("describe_capacity_reservations")
            for page in paginator.paginate():
                for cr in page.get("CapacityReservations", []):
                    result.resources_found += 1
                    cr_id = cr["CapacityReservationId"]
                    state = cr.get("State", "")
                    instance_type = cr.get("InstanceType", "")
                    availability_zone = cr.get("AvailabilityZone", "")
                    available_count = cr.get("AvailableInstanceCount", 0)
                    total_count = cr.get("TotalInstanceCount", 0)

                    await self._add_enumeration_finding("capacity_reservation", cr_id, cr_id, {
                        "state": state,
                        "instance_type": instance_type,
                        "availability_zone": availability_zone,
                        "available_count": available_count,
                        "total_count": total_count,
                        "tenancy": cr.get("Tenancy", ""),
                    }, findings, scan_id)

                    if state == "active" and available_count == total_count:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"Capacity Reservation {cr_id} is fully unused",
                            description=f"Capacity Reservation has {available_count}/{total_count} instances available (cost optimization)",
                            severity="info",
                            category="cost_optimization",
                            resource_type="capacity_reservation",
                            resource_id=cr_id,
                            resource_name=cr_id,
                            region=self.region,
                            rule_id="ec2_cr_fully_unused",
                        ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeCapacityReservations", findings)

    async def _scan_network_interfaces(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Network Interfaces."""
        try:
            paginator = self.client.get_paginator("describe_network_interfaces")
            for page in paginator.paginate():
                for ni in page.get("NetworkInterfaces", []):
                    result.resources_found += 1
                    ni_id = ni["NetworkInterfaceId"]
                    vpc_id = ni.get("VpcId", "")
                    subnet_id = ni.get("SubnetId", "")
                    status = ni.get("Status", "")
                    private_ip = ni.get("PrivateIpAddress", "")
                    public_ip = ni.get("Association", {}).get("PublicIp", "") if ni.get("Association") else ""
                    security_groups = [sg["GroupId"] for sg in ni.get("Groups", [])]
                    attachment = ni.get("Attachment", {})
                    attached_instance = attachment.get("InstanceId", "") if attachment else ""

                    await self._add_enumeration_finding("network_interface", ni_id, ni_id, {
                        "vpc_id": vpc_id,
                        "subnet_id": subnet_id,
                        "status": status,
                        "private_ip": private_ip,
                        "public_ip": public_ip,
                        "security_groups": security_groups,
                        "attached_instance": attached_instance,
                        "description": ni.get("Description", ""),
                        "source_dest_check": ni.get("SourceDestCheck", True),
                    }, findings, scan_id)

                    # Check for public IP on unattached ENI
                    if public_ip and not attached_instance:
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"Unattached ENI {ni_id} has public IP {public_ip}",
                            description="Network interface is not attached to an instance but has a public IP",
                            severity="medium",
                            category="network_exposure",
                            resource_type="network_interface",
                            resource_id=ni_id,
                            resource_name=ni_id,
                            region=self.region,
                            rule_id="ec2_eni_unattached_public_ip",
                        ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeNetworkInterfaces", findings)

    async def _scan_transit_gateways(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Transit Gateways."""
        try:
            paginator = self.client.get_paginator("describe_transit_gateways")
            for page in paginator.paginate():
                for tgw in page.get("TransitGateways", []):
                    result.resources_found += 1
                    tgw_id = tgw["TransitGatewayId"]
                    state = tgw.get("State", "")
                    owner_id = tgw.get("OwnerId", "")

                    await self._add_enumeration_finding("transit_gateway", tgw_id, tgw_id, {
                        "state": state,
                        "owner_id": owner_id,
                        "description": tgw.get("Description", ""),
                        "amazon_side_asn": tgw.get("AmazonSideAsn", 0),
                        "vpn_ecmp_support": tgw.get("Options", {}).get("VpnEcmpSupport", ""),
                        "dns_support": tgw.get("Options", {}).get("DnsSupport", ""),
                    }, findings, scan_id)

                    # Scan TGW attachments
                    try:
                        tgw_attachments = self.client.describe_transit_gateway_attachments(
                            Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
                        )
                        for attachment in tgw_attachments.get("TransitGatewayAttachments", []):
                            att_id = attachment["TransitGatewayAttachmentId"]
                            att_type = attachment.get("ResourceType", "")
                            resource_id = attachment.get("ResourceId", "")

                            await self._add_enumeration_finding("transit_gateway_attachment", att_id, att_id, {
                                "transit_gateway_id": tgw_id,
                                "resource_type": att_type,
                                "resource_id": resource_id,
                                "state": attachment.get("State", ""),
                            }, findings, scan_id)

                    except botocore.exceptions.ClientError:
                        pass

                    # Scan TGW route tables
                    try:
                        tgw_route_tables = self.client.describe_transit_gateway_route_tables(
                            Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
                        )
                        for rt in tgw_route_tables.get("TransitGatewayRouteTables", []):
                            rt_id = rt["TransitGatewayRouteTableId"]
                            await self._add_enumeration_finding("transit_gateway_route_table", rt_id, rt_id, {
                                "transit_gateway_id": tgw_id,
                                "state": rt.get("State", ""),
                                "default_association": rt.get("DefaultAssociationRouteTable", False),
                                "default_propagation": rt.get("DefaultPropagationRouteTable", False),
                            }, findings, scan_id)
                    except botocore.exceptions.ClientError:
                        pass

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] not in ("InvalidAction", "UnsupportedOperation"):
                self.handle_client_error(e, "DescribeTransitGateways", findings)

    async def _scan_vpc_peering(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan VPC Peering Connections."""
        try:
            paginator = self.client.get_paginator("describe_vpc_peering_connections")
            for page in paginator.paginate():
                for pcx in page.get("VpcPeeringConnections", []):
                    result.resources_found += 1
                    pcx_id = pcx["VpcPeeringConnectionId"]
                    status = pcx.get("Status", {}).get("Code", "")
                    requester_vpc = pcx.get("RequesterVpcInfo", {}).get("VpcId", "")
                    accepter_vpc = pcx.get("AccepterVpcInfo", {}).get("VpcId", "")
                    requester_owner = pcx.get("RequesterVpcInfo", {}).get("OwnerId", "")
                    accepter_owner = pcx.get("AccepterVpcInfo", {}).get("OwnerId", "")

                    await self._add_enumeration_finding("vpc_peering_connection", pcx_id, pcx_id, {
                        "status": status,
                        "requester_vpc": requester_vpc,
                        "requester_owner": requester_owner,
                        "accepter_vpc": accepter_vpc,
                        "accepter_owner": accepter_owner,
                        "tags": pcx.get("Tags", []),
                    }, findings, scan_id)

                    if status == "active":
                        # Check for cross-account peering
                        if requester_owner != accepter_owner:
                            self._add_finding_deduped(findings, self.create_finding(
                                title=f"VPC Peering {pcx_id} is cross-account",
                                description=f"Peering between {requester_owner} ({requester_vpc}) and {accepter_owner} ({accepter_vpc})",
                                severity="info",
                                category="cross_account_access",
                                resource_type="vpc_peering_connection",
                                resource_id=pcx_id,
                                resource_name=pcx_id,
                                region=self.region,
                                rule_id="ec2_vpc_peering_cross_account",
                            ))

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeVpcPeeringConnections", findings)

    async def _scan_vpn_connections(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan VPN Connections."""
        try:
            paginator = self.client.get_paginator("describe_vpn_connections")
            for page in paginator.paginate():
                for vpn in page.get("VpnConnections", []):
                    result.resources_found += 1
                    vpn_id = vpn["VpnConnectionId"]
                    state = vpn.get("State", "")
                    vpn_type = vpn.get("Type", "")
                    vgw_id = vpn.get("VpnGatewayId", "")
                    cgw_id = vpn.get("CustomerGatewayId", "")

                    await self._add_enumeration_finding("vpn_connection", vpn_id, vpn_id, {
                        "state": state,
                        "type": vpn_type,
                        "vpn_gateway_id": vgw_id,
                        "customer_gateway_id": cgw_id,
                        "category": vpn.get("Category", ""),
                        "options": vpn.get("Options", {}),
                    }, findings, scan_id)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeVpnConnections", findings)

    async def _scan_customer_gateways(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Customer Gateways."""
        try:
            paginator = self.client.get_paginator("describe_customer_gateways")
            for page in paginator.paginate():
                for cgw in page.get("CustomerGateways", []):
                    result.resources_found += 1
                    cgw_id = cgw["CustomerGatewayId"]
                    ip_address = cgw.get("IpAddress", "")
                    bgp_asn = cgw.get("BgpAsn", "")
                    state = cgw.get("State", "")

                    await self._add_enumeration_finding("customer_gateway", cgw_id, cgw_id, {
                        "ip_address": ip_address,
                        "bgp_asn": bgp_asn,
                        "state": state,
                        "type": cgw.get("Type", ""),
                    }, findings, scan_id)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "DescribeCustomerGateways", findings)

    def _get_finding_key(self, finding: dict) -> str:
        """Generate a unique key for a finding to enable deduplication."""
        key_parts = [
            finding.get("rule_id", ""),
            finding.get("resource_id", ""),
            finding.get("region", ""),
        ]
        key_str = "|".join(key_parts)
        import hashlib
        return hashlib.sha256(key_str.encode()).hexdigest()[:16]

    def _add_finding_deduped(self, findings: list, new_finding: dict, seen_keys: set | None = None) -> None:
        """Add a finding to the list with deduplication."""
        if seen_keys is None:
            seen_keys = set()
            for f in findings:
                seen_keys.add(self._get_finding_key(f))

        finding_key = self._get_finding_key(new_finding)
        if finding_key not in seen_keys:
            findings.append(new_finding)
            seen_keys.add(finding_key)

    async def _add_enumeration_finding(self, resource_type: str, resource_id: str, resource_name: str,
                                        details: dict, findings: list, scan_id: str) -> None:
        """Add an informational enumeration finding for a discovered resource."""
        finding = self.create_finding(
            title=f"Discovered {resource_type}: {resource_name}",
            description=f"Enumerated {resource_type} in {self.region}: {resource_name}",
            severity="info",
            category="enumeration",
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            region=self.region,
            evidence=[{"type": "enumeration", "description": f"{resource_type} details", "data": details}],
            remediation={
                "summary": "Review discovered resource",
                "steps": [
                    "Verify this resource is expected and properly configured",
                    "Check for security misconfigurations",
                ],
                "effort": "low",
                "automatable": False,
            },
            rule_id=f"ec2_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)
