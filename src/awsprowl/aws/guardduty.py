"""GuardDuty scanner for awsProwl."""

from __future__ import annotations

import botocore.exceptions
from awsprowl.aws.base import AWSServiceBase, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


class GuardDutyScanner(AWSServiceBase):
    """Scanner for GuardDuty resources."""

    SERVICE_NAME = "guardduty"
    REQUIRED_PERMISSIONS = [
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:ListFindings",
        "guardduty:GetFindings",
        "guardduty:ListMembers",
        "guardduty:ListOrganizationAdminAccounts",
    ]

    def __init__(self, auth_manager: AWSAuthManager, region: str | None = None):
        super().__init__(auth_manager, region)

    async def scan(self, scan_id: str, findings: list) -> ScanResult:
        """Scan GuardDuty resources for security issues."""
        result = ScanResult(service=self.SERVICE_NAME, region=self.region)
        
        try:
            await self._scan_services(scan_id, findings, result)
        except botocore.exceptions.ClientError as e:
            log.error(f"GuardDuty scan failed: {e}")
            result.errors.append(str(e))
        
        return result

    async def _scan_services(self, scan_id: str, findings: list, result: ScanResult):
        """Scan GuardDuty detectors and related services."""
        try:
            # List detectors
            response = self.client.list_detectors()
            detector_ids = response.get("DetectorIds", [])
            
            for det_id in detector_ids:
                det = self.client.get_detector(DetectorId=det_id)
                
                findings.append({
                    "title": f"GuardDuty Detector: {det_id}",
                    "description": f"Status: {det.get('Status', 'Unknown')}\nCreated: {det.get('CreatedAt', 'Unknown')}\nFinding Interval: {det.get('FindingPublishingFrequency', 'Unknown')}",
                    "severity": "info",
                    "category": "enumeration",
                    "resource_type": "guardduty_detector",
                    "resource_id": det_id,
                    "resource_name": det_id,
                    "region": self.region,
                    "rule_id": "detection_enum_services",
                })
                result.resources_scanned += 1
            
            # List members
            if detector_ids:
                paginator = self.client.get_paginator("list_members")
                for page in paginator.paginate(DetectorId=detector_ids[0]):
                    for member in page.get("Members", []):
                        member_id = member.get("AccountId")
                        
                        findings.append({
                            "title": f"GuardDuty Member: {member_id}",
                            "description": f"Email: {member.get('Email', 'Unknown')}\nStatus: {member.get('RelationshipStatus', 'Unknown')}\nInvited: {member.get('InvitedAt', 'Unknown')}",
                            "severity": "info",
                            "category": "enumeration",
                            "resource_type": "guardduty_member",
                            "resource_id": member_id,
                            "resource_name": member_id,
                            "region": self.region,
                            "rule_id": "detection_exfil_guardduty_accounts",
                        })
                        result.resources_scanned += 1
            
            # List org admin accounts
            org_admins = self.client.list_organization_admin_accounts()
            for admin in org_admins.get("AdminAccounts", []):
                admin_id = admin.get("AdminAccountId")
                
                findings.append({
                    "title": f"GuardDuty Org Admin: {admin_id}",
                    "description": f"Status: {admin.get('AdminStatus', 'Unknown')}",
                    "severity": "info",
                    "category": "enumeration",
                    "resource_type": "guardduty_admin",
                    "resource_id": admin_id,
                    "resource_name": admin_id,
                    "region": self.region,
                    "rule_id": "detection_enum_services",
                })
                result.resources_scanned += 1
                
        except botocore.exceptions.ClientError as e:
            log.error(f"Failed to scan GuardDuty: {e}")
            result.errors.append(str(e))
