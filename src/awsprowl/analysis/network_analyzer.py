"""Network analyzer module for awsProwl."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from awsprowl.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class NetworkPath:
    """Represents a network path between resources."""
    source: str
    source_type: str
    destination: str
    destination_type: str
    protocol: str
    port: int | str
    allowed: bool
    path_type: str  # ingress, egress, internal
    security_groups: list[str] = field(default_factory=list)
    nacls: list[str] = field(default_factory=list)
    route_tables: list[str] = field(default_factory=list)


@dataclass
class NetworkExposure:
    """Represents a network exposure finding."""
    resource_id: str
    resource_type: str
    exposure_type: str  # public_ingress, public_egress, cross_account, etc.
    severity: str
    description: str
    details: dict = field(default_factory=dict)


class NetworkAnalyzer:
    """Analyzes network configurations for security issues."""

    def __init__(self, scan_data: dict):
        """
        Initialize with scan data from all scanners.

        scan_data should contain:
        - vpcs: list of VPCs with subnets, route tables, NACLs
        - security_groups: list of SGs with rules
        - instances: list of EC2 instances with ENIs
        - load_balancers: list of ALBs/NLBs
        - rds_instances: list of RDS instances
        - lambda_functions: list of Lambda functions with VPC config
        - eks_clusters: list of EKS clusters
        - nat_gateways: list of NAT gateways
        - internet_gateways: list of IGWs
        - vpc_endpoints: list of VPC endpoints
        """
        self.scan_data = scan_data
        self.vpcs = scan_data.get("vpcs", [])
        self.security_groups = scan_data.get("security_groups", [])
        self.instances = scan_data.get("instances", [])
        self.load_balancers = scan_data.get("load_balancers", [])
        self.rds_instances = scan_data.get("rds_instances", [])
        self.lambda_functions = scan_data.get("lambda_functions", [])
        self.eks_clusters = scan_data.get("eks_clusters", [])
        self.nat_gateways = scan_data.get("nat_gateways", [])
        self.internet_gateways = scan_data.get("internet_gateways", [])
        self.vpc_endpoints = scan_data.get("vpc_endpoints", [])
        self.subnets = scan_data.get("subnets", [])
        self.route_tables = scan_data.get("route_tables", [])
        self.nacls = scan_data.get("nacls", [])

        self.exposures: list[NetworkExposure] = []
        self.paths: list[NetworkPath] = []

    def analyze(self) -> dict:
        """Run all network analysis checks."""
        self.exposures = []
        self.paths = []

        self._analyze_public_exposure()
        self._analyze_security_groups()
        self._analyze_nacls()
        self._analyze_route_tables()
        self._analyze_vpc_endpoints()
        self._analyze_cross_account_access()
        self._analyze_lambda_vpc()
        self._analyze_rds_exposure()
        self._analyze_eks_exposure()
        self._build_network_paths()

        return {
            "exposures": [self._exposure_to_dict(e) for e in self.exposures],
            "paths": [self._path_to_dict(p) for p in self.paths],
            "summary": self._get_summary(),
        }

    def _analyze_public_exposure(self) -> None:
        """Analyze resources directly exposed to the internet."""
        # Check EC2 instances with public IPs in public subnets
        public_subnets = self._get_public_subnets()

        for instance in self.instances:
            for eni in instance.get("network_interfaces", []):
                if eni.get("association", {}).get("PublicIp"):
                    subnet_id = eni.get("SubnetId")
                    if subnet_id in public_subnets:
                        self.exposures.append(NetworkExposure(
                            resource_id=instance["InstanceId"],
                            resource_type="ec2_instance",
                            exposure_type="public_ingress",
                            severity="high",
                            description=f"Instance {instance['InstanceId']} has public IP in public subnet",
                            details={
                                "public_ip": eni["association"]["PublicIp"],
                                "subnet_id": subnet_id,
                                "security_groups": [sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
                            }
                        ))

        # Check RDS instances with public access
        for rds in self.rds_instances:
            if rds.get("PubliclyAccessible"):
                self.exposures.append(NetworkExposure(
                    resource_id=rds["DBInstanceIdentifier"],
                    resource_type="rds_instance",
                    exposure_type="public_ingress",
                    severity="critical",
                    description=f"RDS instance {rds['DBInstanceIdentifier']} is publicly accessible",
                    details={
                        "endpoint": rds.get("Endpoint", {}).get("Address", ""),
                        "vpc_id": rds.get("DBSubnetGroup", {}).get("VpcId", ""),
                    }
                ))

        # Check load balancers with internet-facing scheme
        for lb in self.load_balancers:
            if lb.get("Scheme") == "internet-facing":
                self.exposures.append(NetworkExposure(
                    resource_id=lb["LoadBalancerArn"],
                    resource_type="load_balancer",
                    exposure_type="public_ingress",
                    severity="medium",
                    description=f"Load balancer {lb['LoadBalancerName']} is internet-facing",
                    details={
                        "dns_name": lb.get("DNSName", ""),
                        "type": lb.get("Type", ""),
                        "vpc_id": lb.get("VpcId", ""),
                    }
                ))

        # Check EKS clusters with public endpoint
        for cluster in self.eks_clusters:
            if cluster.get("resourcesVpcConfig", {}).get("endpointPublicAccess"):
                cidrs = cluster.get("resourcesVpcConfig", {}).get("publicAccessCidrs", [])
                severity = "critical" if not cidrs or "0.0.0.0/0" in cidrs else "high"
                self.exposures.append(NetworkExposure(
                    resource_id=cluster["name"],
                    resource_type="eks_cluster",
                    exposure_type="public_ingress",
                    severity=severity,
                    description=f"EKS cluster {cluster['name']} has public API endpoint",
                    details={
                        "endpoint": cluster.get("endpoint", ""),
                        "public_cidrs": cidrs,
                    }
                ))

    def _analyze_security_groups(self) -> None:
        """Analyze security group rules for overly permissive access."""
        for sg in self.security_groups:
            sg_id = sg["GroupId"]

            for rule in sg.get("IpPermissions", []):
                self._check_sg_rule(sg, rule, "ingress")

            for rule in sg.get("IpPermissionsEgress", []):
                self._check_sg_rule(sg, rule, "egress")

    def _check_sg_rule(self, sg: dict, rule: dict, direction: str) -> None:
        """Check a single security group rule."""
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")
        protocol = rule.get("IpProtocol", "")

        # Check IPv4 CIDR ranges
        for ip_range in rule.get("IpRanges", []):
            cidr = ip_range.get("CidrIp", "")
            if cidr == "0.0.0.0/0":
                self._evaluate_open_sg_rule(sg, rule, direction, cidr, "ipv4")

        # Check IPv6 CIDR ranges
        for ip_range in rule.get("Ipv6Ranges", []):
            cidr = ip_range.get("CidrIpv6", "")
            if cidr == "::/0":
                self._evaluate_open_sg_rule(sg, rule, direction, cidr, "ipv6")

    def _evaluate_open_sg_rule(self, sg: dict, rule: dict, direction: str, cidr: str, ip_version: str) -> None:
        """Evaluate an open security group rule."""
        sg_id = sg["GroupId"]
        protocol = rule.get("IpProtocol", "")
        from_port = rule.get("FromPort")
        to_port = rule.get("ToPort")

        port_desc = self._get_port_description(from_port, to_port, protocol)
        severity = self._get_port_severity(from_port, to_port, protocol)

        if direction == "ingress":
            exposure_type = "public_ingress"
            desc = f"Security group {sg_id} allows {port_desc} from {cidr} (ingress)"
        else:
            exposure_type = "public_egress"
            desc = f"Security group {sg_id} allows {port_desc} to {cidr} (egress)"
            # Egress to 0.0.0.0/0 is often needed for internet access
            if severity == "critical":
                severity = "medium"

        self.exposures.append(NetworkExposure(
            resource_id=sg_id,
            resource_type="security_group",
            exposure_type=exposure_type,
            severity=severity,
            description=desc,
            details={
                "sg_id": sg_id,
                "sg_name": sg.get("GroupName", ""),
                "vpc_id": sg.get("VpcId", ""),
                "protocol": protocol,
                "from_port": from_port,
                "to_port": to_port,
                "cidr": cidr,
                "direction": direction,
            }
        ))

    def _get_port_description(self, from_port: int | None, to_port: int | None, protocol: str) -> str:
        """Get human-readable port description."""
        if protocol == "-1" or protocol == "all":
            return "all traffic"
        if from_port is None or to_port is None:
            return f"{protocol} traffic"
        if from_port == to_port:
            return f"{protocol}/{from_port}"
        return f"{protocol}/{from_port}-{to_port}"

    def _get_port_severity(self, from_port: int | None, to_port: int | None, protocol: str) -> str:
        """Determine severity based on port/protocol."""
        if protocol == "-1" or protocol == "all":
            return "critical"

        if from_port is None or to_port is None:
            return "high"

        # Critical ports
        critical_ports = {22, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 11211}
        if from_port <= 1024 and to_port >= 1024:
            # Range includes critical ports
            for p in critical_ports:
                if from_port <= p <= to_port:
                    return "critical"

        for p in critical_ports:
            if from_port <= p <= to_port:
                return "critical"

        # High ports (database, admin)
        high_ports = {8080, 8443, 9000, 9090, 9200, 9300, 27017, 27018, 27019}
        for p in high_ports:
            if from_port <= p <= to_port:
                return "high"

        # Web ports
        if (from_port <= 80 <= to_port) or (from_port <= 443 <= to_port):
            return "medium"

        return "low"

    def _analyze_nacls(self) -> None:
        """Analyze Network ACLs for overly permissive rules."""
        for nacl in self.nacls:
            nacl_id = nacl["NetworkAclId"]
            vpc_id = nacl["VpcId"]

            for entry in nacl.get("Entries", []):
                if entry.get("RuleAction") != "allow":
                    continue

                cidr = entry.get("CidrBlock", "")
                ipv6_cidr = entry.get("Ipv6CidrBlock", "")
                target_cidr = cidr or ipv6_cidr

                if target_cidr in ("0.0.0.0/0", "::/0"):
                    protocol = entry.get("Protocol", "")
                    from_port = entry.get("PortRange", {}).get("From")
                    to_port = entry.get("PortRange", {}).get("To")

                    # Only flag if it's not the default allow all (rule number 100/32767)
                    rule_num = entry.get("RuleNumber", 0)
                    if rule_num not in (100, 32767):
                        severity = self._get_port_severity(from_port, to_port, protocol)
                        self.exposures.append(NetworkExposure(
                            resource_id=nacl_id,
                            resource_type="nacl",
                            exposure_type="public_ingress" if entry.get("Egress") == False else "public_egress",
                            severity=severity,
                            description=f"NACL {nacl_id} allows {self._get_port_description(from_port, to_port, protocol)} from {target_cidr}",
                            details={
                                "nacl_id": nacl_id,
                                "vpc_id": vpc_id,
                                "rule_number": rule_num,
                                "protocol": protocol,
                                "from_port": from_port,
                                "to_port": to_port,
                                "cidr": target_cidr,
                                "egress": entry.get("Egress", False),
                            }
                        ))

    def _analyze_route_tables(self) -> None:
        """Analyze route tables for unintended internet access."""
        for rt in self.route_tables:
            rt_id = rt["RouteTableId"]
            vpc_id = rt["VpcId"]

            for route in rt.get("Routes", []):
                if route.get("GatewayId", "").startswith("igw-"):
                    # Check if this is the main route table
                    associations = rt.get("Associations", [])
                    main = any(a.get("Main") for a in associations)

                    # Check associated subnets
                    subnet_ids = [a.get("SubnetId") for a in associations if a.get("SubnetId")]

                    self.exposures.append(NetworkExposure(
                        resource_id=rt_id,
                        resource_type="route_table",
                        exposure_type="internet_gateway_route",
                        severity="medium" if main else "low",
                        description=f"Route table {rt_id} has route to Internet Gateway",
                        details={
                            "route_table_id": rt_id,
                            "vpc_id": vpc_id,
                            "main": main,
                            "associated_subnets": subnet_ids,
                            "gateway_id": route.get("GatewayId"),
                        }
                    ))

    def _analyze_vpc_endpoints(self) -> None:
        """Analyze VPC endpoints for security issues."""
        for endpoint in self.vpc_endpoints:
            endpoint_id = endpoint["VpcEndpointId"]
            service_name = endpoint.get("ServiceName", "")
            policy = endpoint.get("PolicyDocument", {})

            # Check for overly permissive endpoint policies
            if policy:
                import json
                try:
                    policy_doc = json.loads(policy) if isinstance(policy, str) else policy
                    statements = policy_doc.get("Statement", [])
                    if not isinstance(statements, list):
                        statements = [statements]

                    for stmt in statements:
                        if stmt.get("Effect") == "Allow":
                            principal = stmt.get("Principal", {})
                            if principal == "*" or principal.get("AWS") == "*":
                                self.exposures.append(NetworkExposure(
                                    resource_id=endpoint_id,
                                    resource_type="vpc_endpoint",
                                    exposure_type="cross_account",
                                    severity="high",
                                    description=f"VPC endpoint {endpoint_id} has overly permissive policy",
                                    details={
                                        "endpoint_id": endpoint_id,
                                        "service_name": service_name,
                                        "policy": policy_doc,
                                    }
                                ))
                except Exception:
                    pass

    def _analyze_cross_account_access(self) -> None:
        """Analyze security groups for cross-account references."""
        for sg in self.security_groups:
            sg_id = sg["GroupId"]

            for rule in sg.get("IpPermissions", []):
                for pair in rule.get("UserIdGroupPairs", []):
                    if pair.get("GroupId") and pair.get("UserId"):
                        owner_id = pair.get("UserId")
                        current_account = self.scan_data.get("account_id", "")
                        if owner_id != current_account:
                            self.exposures.append(NetworkExposure(
                                resource_id=sg_id,
                                resource_type="security_group",
                                exposure_type="cross_account",
                                severity="medium",
                                description=f"Security group {sg_id} references SG from account {owner_id}",
                                details={
                                    "sg_id": sg_id,
                                    "referenced_sg": pair.get("GroupId"),
                                    "owner_account": owner_id,
                                    "protocol": rule.get("IpProtocol"),
                                    "from_port": rule.get("FromPort"),
                                    "to_port": rule.get("ToPort"),
                                }
                            ))

    def _analyze_lambda_vpc(self) -> None:
        """Analyze Lambda functions in VPC for network issues."""
        for func in self.lambda_functions:
            vpc_config = func.get("VpcConfig", {})
            if not vpc_config.get("VpcId"):
                continue  # Not in VPC

            subnet_ids = vpc_config.get("SubnetIds", [])
            sg_ids = vpc_config.get("SecurityGroupIds", [])

            # Check if subnets are public
            public_subnets = self._get_public_subnets()
            for subnet_id in subnet_ids:
                if subnet_id in public_subnets:
                    self.exposures.append(NetworkExposure(
                        resource_id=func["FunctionName"],
                        resource_type="lambda_function",
                        exposure_type="public_egress",
                        severity="medium",
                        description=f"Lambda {func['FunctionName']} in public subnet {subnet_id}",
                        details={
                            "function_name": func["FunctionName"],
                            "subnet_id": subnet_id,
                            "security_groups": sg_ids,
                        }
                    ))

    def _analyze_rds_exposure(self) -> None:
        """Analyze RDS instances for network exposure."""
        for rds in self.rds_instances:
            if not rds.get("PubliclyAccessible"):
                continue

            subnet_group = rds.get("DBSubnetGroup", {})
            subnets = subnet_group.get("Subnets", [])
            public_subnets = self._get_public_subnets()

            for subnet in subnets:
                if subnet.get("SubnetIdentifier") in public_subnets:
                    self.exposures.append(NetworkExposure(
                        resource_id=rds["DBInstanceIdentifier"],
                        resource_type="rds_instance",
                        exposure_type="public_ingress",
                        severity="critical",
                        description=f"RDS {rds['DBInstanceIdentifier']} in public subnet",
                        details={
                            "subnet_id": subnet.get("SubnetIdentifier"),
                            "vpc_id": subnet_group.get("VpcId"),
                        }
                    ))

    def _analyze_eks_exposure(self) -> None:
        """Analyze EKS clusters for network exposure."""
        for cluster in self.eks_clusters:
            vpc_config = cluster.get("resourcesVpcConfig", {})
            endpoint_public = vpc_config.get("endpointPublicAccess", True)
            endpoint_private = vpc_config.get("endpointPrivateAccess", False)

            if endpoint_public and not endpoint_private:
                self.exposures.append(NetworkExposure(
                    resource_id=cluster["name"],
                    resource_type="eks_cluster",
                    exposure_type="public_ingress",
                    severity="high",
                    description=f"EKS cluster {cluster['name']} only has public endpoint",
                    details={
                        "endpoint": cluster.get("endpoint", ""),
                        "public_access": True,
                        "private_access": False,
                    }
                ))

    def _build_network_paths(self) -> None:
        """Build network paths between resources."""
        # Build paths from internet to resources via IGs
        public_subnets = self._get_public_subnets()

        for subnet_id in public_subnets:
            # Find resources in this subnet
            for instance in self.instances:
                for eni in instance.get("network_interfaces", []):
                    if eni.get("SubnetId") == subnet_id:
                        self.paths.append(NetworkPath(
                            source="0.0.0.0/0",
                            source_type="internet",
                            destination=instance["InstanceId"],
                            destination_type="ec2_instance",
                            protocol="tcp",
                            port="*",
                            allowed=True,
                            path_type="ingress",
                            security_groups=[sg["GroupId"] for sg in instance.get("SecurityGroups", [])],
                        ))

    def _get_public_subnets(self) -> set[str]:
        """Get set of public subnet IDs (subnets with route to IGW)."""
        public_subnets = set()

        # Find route tables with IGW routes
        igw_routes_rt = set()
        for rt in self.route_tables:
            for route in rt.get("Routes", []):
                if route.get("GatewayId", "").startswith("igw-"):
                    igw_routes_rt.add(rt["RouteTableId"])
                    break

        # Find subnets associated with these route tables
        for rt in self.route_tables:
            if rt["RouteTableId"] in igw_routes_rt:
                for assoc in rt.get("Associations", []):
                    if assoc.get("SubnetId"):
                        public_subnets.add(assoc["SubnetId"])

        return public_subnets

    def _get_summary(self) -> dict:
        """Get summary of network analysis."""
        by_type = defaultdict(int)
        by_severity = defaultdict(int)

        for exp in self.exposures:
            by_type[exp.exposure_type] += 1
            by_severity[exp.severity] += 1

        return {
            "total_exposures": len(self.exposures),
            "by_type": dict(by_type),
            "by_severity": dict(by_severity),
            "total_paths": len(self.paths),
        }

    def _exposure_to_dict(self, exp: NetworkExposure) -> dict:
        """Convert exposure to dict."""
        return {
            "resource_id": exp.resource_id,
            "resource_type": exp.resource_type,
            "exposure_type": exp.exposure_type,
            "severity": exp.severity,
            "description": exp.description,
            "details": exp.details,
        }

    def _path_to_dict(self, path: NetworkPath) -> dict:
        """Convert path to dict."""
        return {
            "source": path.source,
            "source_type": path.source_type,
            "destination": path.destination,
            "destination_type": path.destination_type,
            "protocol": path.protocol,
            "port": path.port,
            "allowed": path.allowed,
            "path_type": path.path_type,
            "security_groups": path.security_groups,
            "nacls": path.nacls,
            "route_tables": path.route_tables,
        }
