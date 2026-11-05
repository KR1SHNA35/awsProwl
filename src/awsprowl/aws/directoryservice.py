"""Directory Service scanner for awsProwl."""

from __future__ import annotations

import botocore.exceptions
from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class DirectoryServiceScanner(AWSServiceBase):
    """Scanner for Directory Service resources."""

    SERVICE_NAME = "ds"
    REQUIRED_PERMISSIONS = [
        "ds:DescribeDirectories",
        "ds:DescribeTrusts",
        "ds:DescribeSnapshots",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan Directory Service resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)
        
        try:
            await self._scan_directories(scan_id, findings, result)
            await self._scan_trusts(scan_id, findings, result)
            await self._scan_snapshots(scan_id, findings, result)
        except botocore.exceptions.ClientError as e:
            log.error(f"Directory Service scan failed: {e}")
            result.errors.append(str(e))
        
        return result

    async def _scan_directories(self, scan_id: str, findings: list, result: ScanResult):
        """Scan directories."""
        try:
            paginator = self.client.get_paginator("describe_directories")
            for page in paginator.paginate():
                for d in page.get("DirectoryDescriptions", []):
                    dir_id = d.get("DirectoryId")
                    name = d.get("Name", "Unknown")
                    
                    findings.append({
                        "title": f"Directory Service: {name} ({dir_id})",
                        "description": f"Type: {d.get('Type', 'Unknown')}\nSize: {d.get('Size', 'Unknown')}\nStatus: {d.get('Stage', 'Unknown')}\nVPC: {d.get('VpcSettings', {}).get('VpcId', 'None')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "directory_service",
                        "resource_id": dir_id,
                        "resource_name": name,
                        "region": self.region,
                        "rule_id": "ds_enum_directories",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan directories: {e}")
            result.errors.append(str(e))

    async def _scan_trusts(self, scan_id: str, findings: list, result: ScanResult):
        """Scan trusts."""
        try:
            paginator = self.client.get_paginator("describe_trusts")
            for page in paginator.paginate():
                for t in page.get("Trusts", []):
                    trust_id = t.get("TrustId")
                    trust_type = t.get("TrustType", "Unknown")
                    
                    findings.append({
                        "title": f"Directory Trust: {trust_id} ({trust_type})",
                        "description": f"Direction: {t.get('TrustDirection', 'Unknown')}\nTrust State: {t.get('TrustState', 'Unknown')}\nRemote Domain: {t.get('RemoteDomainName', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "directory_trust",
                        "resource_id": trust_id,
                        "resource_name": trust_id,
                        "region": self.region,
                        "rule_id": "ds_enum_trusts",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan trusts: {e}")
            result.errors.append(str(e))

    async def _scan_snapshots(self, scan_id: str, findings: list, result: ScanResult):
        """Scan snapshots."""
        try:
            paginator = self.client.get_paginator("describe_snapshots")
            for page in paginator.paginate():
                for s in page.get("Snapshots", []):
                    snap_id = s.get("SnapshotId")
                    
                    findings.append({
                        "title": f"Directory Snapshot: {snap_id}",
                        "description": f"Directory: {s.get('DirectoryId', 'Unknown')}\nType: {s.get('Type', 'Unknown')}\nStatus: {s.get('Status', 'Unknown')}\nStart Time: {s.get('StartTime', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "directory_snapshot",
                        "resource_id": snap_id,
                        "resource_name": snap_id,
                        "region": self.region,
                        "rule_id": "ds_enum_snapshots",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan snapshots: {e}")
            result.errors.append(str(e))
