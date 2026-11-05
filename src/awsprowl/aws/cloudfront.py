"""CloudFront scanner for awsProwl."""

from __future__ import annotations

import asyncio
import hashlib

import botocore.exceptions

from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class CloudFrontScanner(AWSServiceBase):
    """Scanner for CloudFront resources."""

    SERVICE_NAME = "cloudfront"
    REQUIRED_PERMISSIONS = [
        "cloudfront:ListDistributions",
        "cloudfront:GetDistribution",
        "cloudfront:GetDistributionConfig",
        "cloudfront:ListTagsForResource",
        "cloudfront:ListOriginAccessControls",
        "cloudfront:GetOriginAccessControl",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        # CloudFront is global, uses us-east-1 endpoint
        super().__init__(auth_manager, region or "us-east-1")

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan CloudFront resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region="global")

        try:
            await asyncio.gather(
                self._scan_distributions(scan_id, findings, result),
                self._scan_origin_access_controls(scan_id, findings, result),
                return_exceptions=True,
            )

        except Exception as e:
            log.error("Error in CloudFront scan: {}", e)
            result.errors.append(str(e))

        return result

    async def _scan_distributions(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan CloudFront distributions."""
        try:
            paginator = self.client.get_paginator("list_distributions")
            for page in paginator.paginate():
                for dist in page.get("DistributionList", {}).get("Items", []):
                    result.resources_found += 1
                    await self._analyze_distribution(dist, scan_id, findings)

        except botocore.exceptions.ClientError as e:
            self.handle_client_error(e, "ListDistributions", findings)

    async def _analyze_distribution(self, dist: dict, scan_id: str, findings: list) -> None:
        """Analyze a CloudFront distribution."""
        dist_id = dist["Id"]
        domain_name = dist.get("DomainName", "")
        status = dist.get("Status", "")
        config = dist.get("DistributionConfig", {})
        origins = config.get("Origins", {}).get("Items", [])
        default_cache_behavior = config.get("DefaultCacheBehavior", {})
        cache_behaviors = config.get("CacheBehaviors", {}).get("Items", [])
        viewer_cert = config.get("ViewerCertificate", {})
        logging = config.get("Logging", {})
        geo_restriction = config.get("Restrictions", {}).get("GeoRestriction", {})
        web_acl_id = config.get("WebACLId", "")
        http_version = config.get("HttpVersion", "")
        is_ipv6 = config.get("IsIPV6Enabled", False)

        # Add enumeration finding
        await self._add_enumeration_finding("cloudfront_distribution", dist_id, domain_name, {
            "status": status,
            "domain_name": domain_name,
            "origins_count": len(origins),
            "has_waf": bool(web_acl_id),
            "logging_enabled": logging.get("Enabled", False),
            "http_version": http_version,
            "ipv6_enabled": is_ipv6,
            "geo_restriction_type": geo_restriction.get("RestrictionType", "none"),
        }, findings, scan_id)

        # Check if distribution uses HTTPS only
        viewer_protocol = default_cache_behavior.get("ViewerProtocolPolicy", "")
        if viewer_protocol != "redirect-to-https" and viewer_protocol != "https-only":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"CloudFront distribution {dist_id} allows HTTP access",
                description=f"Default cache behavior allows {viewer_protocol or 'HTTP'} instead of HTTPS only",
                severity="high",
                category="weak_configuration",
                resource_type="cloudfront_distribution",
                resource_id=dist_id,
                resource_name=domain_name,
                region="global",
                remediation={
                    "summary": "Enforce HTTPS for all viewers",
                    "steps": [
                        "Update default cache behavior to 'redirect-to-https' or 'https-only'",
                        "Update all cache behaviors similarly",
                    ],
                    "effort": "low",
                    "automatable": True,
                    "cli_commands": [
                        f"aws cloudfront get-distribution-config --id {dist_id} --query 'DistributionConfig' --output json > config.json",
                        "# Edit config.json to set ViewerProtocolPolicy to 'redirect-to-https' for all behaviors",
                        f"aws cloudfront update-distribution --id {dist_id} --distribution-config file://config.json --if-match <ETag>",
                    ],
                },
                rule_id="cloudfront_http_allowed",
            ))

        # Check origin protocol policy
        for origin in origins:
            origin_id = origin.get("Id", "")
            origin_domain = origin.get("DomainName", "")
            custom_origin = origin.get("CustomOriginConfig", {})
            s3_origin = origin.get("S3OriginConfig", {})

            if custom_origin:
                origin_protocol = custom_origin.get("OriginProtocolPolicy", "")
                if origin_protocol != "https-only":
                    self._add_finding_deduped(findings, self.create_finding(
                        title=f"CloudFront distribution {dist_id} origin {origin_id} uses insecure protocol",
                        description=f"Origin {origin_domain} uses {origin_protocol or 'HTTP'} instead of HTTPS",
                        severity="high",
                        category="weak_configuration",
                        resource_type="cloudfront_distribution",
                        resource_id=dist_id,
                        resource_name=domain_name,
                        region="global",
                        evidence=[{"type": "origin_config", "description": "Origin protocol policy", "data": {"origin_id": origin_id, "origin_domain": origin_domain, "protocol": origin_protocol}}],
                        remediation={
                            "summary": "Enforce HTTPS for origin connections",
                            "steps": [
                                "Update origin protocol policy to 'https-only'",
                                "Ensure origin supports HTTPS",
                            ],
                            "effort": "low",
                            "automatable": True,
                        },
                        rule_id="cloudfront_origin_http",
                    ))

        # Check for legacy SSL/TLS
        ssl_support_method = viewer_cert.get("SSLSupportMethod", "")
        if ssl_support_method == "vip":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"CloudFront distribution {dist_id} uses legacy SSL support method",
                description="Distribution uses dedicated IP SSL (VIP) instead of SNI",
                severity="medium",
                category="weak_configuration",
                resource_type="cloudfront_distribution",
                resource_id=dist_id,
                resource_name=domain_name,
                region="global",
                rule_id="cloudfront_legacy_ssl",
            ))

        min_protocol = viewer_cert.get("MinimumProtocolVersion", "")
        if min_protocol and min_protocol.startswith("TLSv1") and not min_protocol.startswith("TLSv1.2"):
            self._add_finding_deduped(findings, self.create_finding(
                title=f"CloudFront distribution {dist_id} uses outdated TLS version: {min_protocol}",
                description="Distribution allows TLS versions older than TLS 1.2",
                severity="high",
                category="weak_configuration",
                resource_type="cloudfront_distribution",
                resource_id=dist_id,
                resource_name=domain_name,
                region="global",
                remediation={
                    "summary": "Update minimum TLS version to TLS 1.2 or higher",
                    "steps": [
                        "Update viewer certificate minimum protocol version",
                    ],
                    "effort": "low",
                    "automatable": True,
                },
                rule_id="cloudfront_old_tls",
            ))

        # Check for WAF
        if not web_acl_id:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"CloudFront distribution {dist_id} has no WAF associated",
                description="Distribution is not protected by AWS WAF",
                severity="medium",
                category="weak_configuration",
                resource_type="cloudfront_distribution",
                resource_id=dist_id,
                resource_name=domain_name,
                region="global",
                remediation={
                    "summary": "Associate WAF web ACL",
                    "steps": [
                        "Create WAF web ACL with appropriate rules",
                        "Associate web ACL with distribution",
                    ],
                    "effort": "medium",
                    "automatable": True,
                },
                rule_id="cloudfront_no_waf",
            ))

        # Check logging
        if not logging.get("Enabled", False):
            self._add_finding_deduped(findings, self.create_finding(
                title=f"CloudFront distribution {dist_id} has logging disabled",
                description="Access logging is not enabled for the distribution",
                severity="medium",
                category="logging_missing",
                resource_type="cloudfront_distribution",
                resource_id=dist_id,
                resource_name=domain_name,
                region="global",
                remediation={
                    "summary": "Enable access logging",
                    "steps": [
                        "Create S3 bucket for CloudFront logs",
                        "Enable logging on distribution pointing to log bucket",
                    ],
                    "effort": "low",
                    "automatable": True,
                },
                rule_id="cloudfront_logging_disabled",
            ))

        # Check geo restriction
        restriction_type = geo_restriction.get("RestrictionType", "none")
        locations = geo_restriction.get("Locations", [])
        if restriction_type == "none":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"CloudFront distribution {dist_id} has no geo restriction",
                description="Distribution is accessible from all countries",
                severity="low",
                category="weak_configuration",
                resource_type="cloudfront_distribution",
                resource_id=dist_id,
                resource_name=domain_name,
                region="global",
                remediation={
                    "summary": "Configure geo restriction if needed",
                    "steps": [
                        "Determine allowed/blocked countries",
                        "Configure geo restriction on distribution",
                    ],
                    "effort": "low",
                    "automatable": True,
                },
                rule_id="cloudfront_no_geo_restriction",
            ))

        # Check HTTP version
        if http_version not in ("http2", "http2and3", "http3"):
            self._add_finding_deduped(findings, self.create_finding(
                title=f"CloudFront distribution {dist_id} uses legacy HTTP version: {http_version}",
                description="Distribution uses HTTP/1.1 instead of HTTP/2 or HTTP/3",
                severity="low",
                category="weak_configuration",
                resource_type="cloudfront_distribution",
                resource_id=dist_id,
                resource_name=domain_name,
                region="global",
                rule_id="cloudfront_legacy_http_version",
            ))

        # Check for default root object
        default_root = config.get("DefaultRootObject", "")
        if not default_root:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"CloudFront distribution {dist_id} has no default root object",
                description="No default root object configured, may expose directory listing",
                severity="low",
                category="weak_configuration",
                resource_type="cloudfront_distribution",
                resource_id=dist_id,
                resource_name=domain_name,
                region="global",
                rule_id="cloudfront_no_default_root",
            ))

        # Check price class
        price_class = config.get("PriceClass", "PriceClass_All")
        if price_class == "PriceClass_All":
            self._add_finding_deduped(findings, self.create_finding(
                title=f"CloudFront distribution {dist_id} uses PriceClass_All (all edge locations)",
                description="Using all edge locations increases cost - consider PriceClass_100 or PriceClass_200 if traffic is regional",
                severity="info",
                category="cost_optimization",
                resource_type="cloudfront_distribution",
                resource_id=dist_id,
                resource_name=domain_name,
                region="global",
                rule_id="cloudfront_price_class_all",
            ))

        # Check custom error responses
        custom_errors = config.get("CustomErrorResponses", {}).get("Items", [])
        error_codes = {e.get("ErrorCode") for e in custom_errors}
        if 403 not in error_codes and 404 not in error_codes:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"CloudFront distribution {dist_id} has no custom error pages for 403/404",
                description="Default error responses may leak information",
                severity="low",
                category="weak_configuration",
                resource_type="cloudfront_distribution",
                resource_id=dist_id,
                resource_name=domain_name,
                region="global",
                rule_id="cloudfront_no_custom_errors",
            ))

        # Check IPv6
        if not is_ipv6:
            self._add_finding_deduped(findings, self.create_finding(
                title=f"CloudFront distribution {dist_id} has IPv6 disabled",
                description="IPv6 is not enabled for the distribution",
                severity="info",
                category="weak_configuration",
                resource_type="cloudfront_distribution",
                resource_id=dist_id,
                resource_name=domain_name,
                region="global",
                rule_id="cloudfront_ipv6_disabled",
            ))

    async def _scan_origin_access_controls(self, scan_id: str, findings: list, result: ScanResult) -> None:
        """Scan Origin Access Controls (OAC)."""
        try:
            paginator = self.client.get_paginator("list_origin_access_controls")
            for page in paginator.paginate():
                for oac in page.get("OriginAccessControlList", {}).get("Items", []):
                    result.resources_found += 1
                    oac_id = oac.get("Id", "")
                    oac_config = oac.get("OriginAccessControlConfig", {})
                    oac_name = oac_config.get("Name", oac_id)

                    # Add enumeration finding
                    await self._add_enumeration_finding("cloudfront_oac", oac_id, oac_name, {
                        "name": oac_name,
                        "signing_behavior": oac_config.get("SigningBehavior", ""),
                        "signing_protocol": oac_config.get("SigningProtocol", ""),
                        "origin_type": oac_config.get("OriginAccessControlOriginType", ""),
                    }, findings, scan_id)

                    # Check OAC signing behavior
                    signing = oac_config.get("SigningBehavior", "")
                    if signing != "always":
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"CloudFront OAC {oac_id} does not always sign requests",
                            description=f"OAC signing behavior is '{signing}' instead of 'always'",
                            severity="medium",
                            category="weak_configuration",
                            resource_type="cloudfront_oac",
                            resource_id=oac_id,
                            resource_name=oac_config.get("Name", oac_id),
                            region="global",
                            rule_id="cloudfront_oac_not_always_sign",
                        ))

                    # Check origin type
                    origin_type = oac_config.get("OriginAccessControlOriginType", "")
                    if origin_type != "s3":
                        self._add_finding_deduped(findings, self.create_finding(
                            title=f"CloudFront OAC {oac_id} is not for S3 origin",
                            description=f"OAC origin type is '{origin_type}' - OAC is designed for S3 origins",
                            severity="info",
                            category="informational",
                            resource_type="cloudfront_oac",
                            resource_id=oac_id,
                            resource_name=oac_config.get("Name", oac_id),
                            region="global",
                            rule_id="cloudfront_oac_non_s3",
                        ))

        except botocore.exceptions.ClientError as e:
            if e.response["Error"]["Code"] != "AccessDenied":
                self.handle_client_error(e, "ListOriginAccessControls", findings)

    def _get_finding_key(self, finding: dict) -> str:
        """Generate a unique key for a finding to enable deduplication."""
        key_parts = [
            finding.get("rule_id", ""),
            finding.get("resource_id", ""),
            finding.get("region", ""),
        ]
        key_str = "|".join(key_parts)
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
            description=f"Enumerated {resource_type} in global: {resource_name}",
            severity="info",
            category="enumeration",
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            region="global",
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
            rule_id=f"cloudfront_enum_{resource_type}",
        )
        self._add_finding_deduped(findings, finding)
