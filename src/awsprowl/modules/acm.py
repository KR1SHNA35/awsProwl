"""
ACM (Certificate Manager) Service Modules - All ACM-related features

This module provides a unified interface for all ACM operations:
- enum: Enumeration (safe, read-only)
"""

from awsprowl.modules import ModuleCategory, ModuleMetadata, ModuleRisk, register_module

# ==================== ENUM MODULES ====================
register_module(ModuleMetadata(
    name="acm_enum_certificates",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate ACM certificates (public and private). PROWL: acm__enum.",
    required_permissions=[
        "acm:ListCertificates", "acm:DescribeCertificate",
        "acm:ListTagsForCertificate"
    ],
    supported_services=["acm"],
    mitre_techniques=["T1526", "T1083"],
    tags=["acm", "enum", "certificates", "tls", "ssl", "awsprowl"],
    requires_confirmation=False,
))

register_module(ModuleMetadata(
    name="acm_enum_certificate_details",
    category=ModuleCategory.ENUM,
    risk=ModuleRisk.SAFE,
    description="Enumerate detailed certificate information (domains, SANs, validity, key algorithm).",
    required_permissions=[
        "acm:DescribeCertificate", "acm:ListCertificates"
    ],
    supported_services=["acm"],
    mitre_techniques=["T1526", "T1083", "T1590.005"],
    tags=["acm", "enum", "certificate-details", "domains", "safe"],
    requires_confirmation=False,
))

# List all ACM modules
ACM_MODULES = [
    # Enum
    "acm_enum_certificates", "acm_enum_certificate_details",
]

__all__ = ["ACM_MODULES"]