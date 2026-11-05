"""Transfer Family scanner for awsProwl."""

from __future__ import annotations

import botocore.exceptions
from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class TransferScanner(AWSServiceBase):
    """Scanner for Transfer Family resources."""

    SERVICE_NAME = "transfer"
    REQUIRED_PERMISSIONS = [
        "transfer:ListServers",
        "transfer:DescribeServer",
        "transfer:ListCertificates",
        "transfer:DescribeCertificate",
        "transfer:ListConnectors",
        "transfer:DescribeConnector",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan Transfer Family resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)
        
        try:
            await self._scan_servers(scan_id, findings, result)
            await self._scan_certificates(scan_id, findings, result)
            await self._scan_connectors(scan_id, findings, result)
        except botocore.exceptions.ClientError as e:
            log.error(f"Transfer scan failed: {e}")
            result.errors.append(str(e))
        
        return result

    async def _scan_servers(self, scan_id: str, findings: list, result: ScanResult):
        """Scan servers."""
        try:
            paginator = self.client.get_paginator("list_servers")
            for page in paginator.paginate():
                for server in page.get("Servers", []):
                    server_id = server.get("ServerId")
                    
                    findings.append({
                        "title": f"Transfer Server: {server_id}",
                        "description": f"State: {server.get('State', 'Unknown')}\nProtocol: {', '.join(server.get('Protocols', []))}\nEndpoint Type: {server.get('EndpointType', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "transfer_server",
                        "resource_id": server_id,
                        "resource_name": server_id,
                        "region": self.region,
                        "rule_id": "transfer_enum_servers",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan servers: {e}")
            result.errors.append(str(e))

    async def _scan_certificates(self, scan_id: str, findings: list, result: ScanResult):
        """Scan certificates."""
        try:
            paginator = self.client.get_paginator("list_certificates")
            for page in paginator.paginate():
                for cert in page.get("Certificates", []):
                    cert_id = cert.get("CertificateId")
                    
                    findings.append({
                        "title": f"Transfer Certificate: {cert_id}",
                        "description": f"Usage: {cert.get('Usage', 'Unknown')}\nActive Date: {cert.get('ActiveDate', 'Unknown')}\nInactive Date: {cert.get('InactiveDate', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "transfer_certificate",
                        "resource_id": cert_id,
                        "resource_name": cert_id,
                        "region": self.region,
                        "rule_id": "transfer_enum_certificates",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan certificates: {e}")
            result.errors.append(str(e))

    async def _scan_connectors(self, scan_id: str, findings: list, result: ScanResult):
        """Scan connectors."""
        try:
            paginator = self.client.get_paginator("list_connectors")
            for page in paginator.paginate():
                for conn in page.get("Connectors", []):
                    conn_id = conn.get("ConnectorId")
                    
                    findings.append({
                        "title": f"Transfer Connector: {conn_id}",
                        "description": f"Url: {conn.get('Url', 'Unknown')}\nAs2Config: {conn.get('As2Config', {})}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "transfer_connector",
                        "resource_id": conn_id,
                        "resource_name": conn_id,
                        "region": self.region,
                        "rule_id": "transfer_enum_connectors",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan connectors: {e}")
            result.errors.append(str(e))
