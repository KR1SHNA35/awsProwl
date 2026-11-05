"""ACM scanner for awsProwl."""

from __future__ import annotations

import botocore.exceptions
from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class ACMScanner(AWSServiceBase):
    """Scanner for ACM resources."""

    SERVICE_NAME = "acm"
    REQUIRED_PERMISSIONS = [
        "acm:ListCertificates",
        "acm:DescribeCertificate",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan ACM resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)
        
        try:
            await self._scan_certificates(scan_id, findings, result)
            await self._scan_certificate_details(scan_id, findings, result)
        except botocore.exceptions.ClientError as e:
            log.error(f"ACM scan failed: {e}")
            result.errors.append(str(e))
        
        return result

    async def _scan_certificates(self, scan_id: str, findings: list, result: ScanResult):
        """Scan certificates."""
        try:
            paginator = self.client.get_paginator("list_certificates")
            for page in paginator.paginate():
                for cert in page.get("CertificateSummaryList", []):
                    cert_arn = cert.get("CertificateArn")
                    domain = cert.get("DomainName", "Unknown")
                    
                    findings.append({
                        "title": f"ACM Certificate: {domain}",
                        "description": f"ARN: {cert_arn}\nStatus: {cert.get('Status', 'Unknown')}\nType: {cert.get('Type', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "acm_certificate",
                        "resource_id": cert_arn,
                        "resource_name": domain,
                        "region": self.region,
                        "rule_id": "acm_enum_certificates",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan certificates: {e}")
            result.errors.append(str(e))

    async def _scan_certificate_details(self, scan_id: str, findings: list, result: ScanResult):
        """Scan certificate details."""
        try:
            paginator = self.client.get_paginator("list_certificates")
            for page in paginator.paginate():
                for cert in page.get("CertificateSummaryList", []):
                    cert_arn = cert.get("CertificateArn")
                    domain = cert.get("DomainName", "Unknown")
                    
                    detail = self.client.describe_certificate(CertificateArn=cert_arn)
                    cert_detail = detail.get("Certificate", {})
                    
                    findings.append({
                        "title": f"ACM Certificate Details: {domain}",
                        "description": f"ARN: {cert_arn}\nSANs: {', '.join(cert_detail.get('SubjectAlternativeNames', []))}\nKey Algorithm: {cert_detail.get('KeyAlgorithm', 'Unknown')}\nNot Before: {cert_detail.get('NotBefore', 'Unknown')}\nNot After: {cert_detail.get('NotAfter', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "acm_certificate",
                        "resource_id": cert_arn,
                        "resource_name": domain,
                        "region": self.region,
                        "rule_id": "acm_enum_certificate_details",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan certificate details: {e}")
            result.errors.append(str(e))
