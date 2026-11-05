"""Lightsail scanner for awsProwl."""

from __future__ import annotations

import botocore.exceptions
from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class LightsailScanner(AWSServiceBase):
    """Scanner for Lightsail resources."""

    SERVICE_NAME = "lightsail"
    REQUIRED_PERMISSIONS = [
        "lightsail:GetInstances",
        "lightsail:GetDisks",
        "lightsail:GetSnapshots",
        "lightsail:GetBlueprints",
        "lightsail:GetBundles",
        "lightsail:GetRelationalDatabases",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan Lightsail resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)
        
        try:
            await self._scan_instances(scan_id, findings, result)
            await self._scan_blueprints(scan_id, findings, result)
            await self._scan_databases(scan_id, findings, result)
        except botocore.exceptions.ClientError as e:
            log.error(f"Lightsail scan failed: {e}")
            result.errors.append(str(e))
        
        return result

    async def _scan_instances(self, scan_id: str, findings: list, result: ScanResult):
        """Scan instances."""
        try:
            paginator = self.client.get_paginator("get_instances")
            for page in paginator.paginate():
                for inst in page.get("instances", []):
                    name = inst.get("name")
                    
                    findings.append({
                        "title": f"Lightsail Instance: {name}",
                        "description": f"State: {inst.get('state', {}).get('name', 'Unknown')}\nBlueprint: {inst.get('blueprintId', 'Unknown')}\nBundle: {inst.get('bundleId', 'Unknown')}\nIP: {inst.get('publicIpAddress', 'None')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "lightsail_instance",
                        "resource_id": name,
                        "resource_name": name,
                        "region": self.region,
                        "rule_id": "lightsail_enum_instances",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan instances: {e}")
            result.errors.append(str(e))

    async def _scan_blueprints(self, scan_id: str, findings: list, result: ScanResult):
        """Scan blueprints."""
        try:
            paginator = self.client.get_paginator("get_blueprints")
            for page in paginator.paginate():
                for bp in page.get("blueprints", []):
                    bp_id = bp.get("blueprintId")
                    name = bp.get("name", "Unknown")
                    
                    findings.append({
                        "title": f"Lightsail Blueprint: {name}",
                        "description": f"ID: {bp_id}\nType: {bp.get('type', 'Unknown')}\nPlatform: {bp.get('platform', 'Unknown')}\nVersion: {bp.get('version', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "lightsail_blueprint",
                        "resource_id": bp_id,
                        "resource_name": name,
                        "region": self.region,
                        "rule_id": "lightsail_enum_blueprints",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan blueprints: {e}")
            result.errors.append(str(e))

    async def _scan_databases(self, scan_id: str, findings: list, result: ScanResult):
        """Scan databases."""
        try:
            paginator = self.client.get_paginator("get_relational_databases")
            for page in paginator.paginate():
                for db in page.get("relationalDatabases", []):
                    name = db.get("name")
                    
                    findings.append({
                        "title": f"Lightsail Database: {name}",
                        "description": f"Engine: {db.get('engine', 'Unknown')}\nVersion: {db.get('engineVersion', 'Unknown')}\nState: {db.get('state', 'Unknown')}\nHardware: {db.get('hardware', {}).get('name', 'Unknown')}",
                        "severity": "info",
                        "category": "enumeration",
                        "resource_type": "lightsail_database",
                        "resource_id": name,
                        "resource_name": name,
                        "region": self.region,
                        "rule_id": "lightsail_enum_databases",
                    })
                    result.resources_scanned += 1
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan databases: {e}")
            result.errors.append(str(e))
