"""Scan orchestrator for awsProwl."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from awsprowl.aws.base import ParallelScanner, ScanResult
from awsprowl.core.auth import AWSAuthManager
from awsprowl.core.config import ScanConfig, get_config
from awsprowl.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class ScanSession:
    """Represents a scan session."""

    scan_id: str
    profile: str
    regions: list[str]
    services: list[str]
    scan_profile: str
    started_at: datetime
    completed_at: datetime | None = None
    status: str = "running"  # running, completed, failed, cancelled
    results: list[ScanResult] = field(default_factory=list)
    findings: list = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    config_snapshot: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "scan_id": self.scan_id,
            "profile": self.profile,
            "regions": self.regions,
            "services": self.services,
            "scan_profile": self.scan_profile,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "status": self.status,
            "results": [
                {
                    "service": r.service,
                    "region": r.region,
                    "resources_found": r.resources_found,
                    "findings_count": len(r.findings),
                    "errors": r.errors,
                    "duration_ms": r.duration_ms,
                }
                for r in self.results
            ],
            "findings": self.findings,
            "errors": self.errors,
            "config": self.config_snapshot,
        }


class ScanOrchestrator:
    """Orchestrates multi-service, multi-region scans."""

    # Scan profiles define which services to scan
    SCAN_PROFILES = {
        "quick": ["iam", "ec2", "s3"],
        "standard": ["iam", "ec2", "s3", "lambda", "ecs", "secretsmanager", "sns", "rds", "dynamodb", "kms"],
        "deep": [
            "iam", "ec2", "s3", "lambda", "ecs", "secretsmanager", "sns",
            "beanstalk", "cognito", "sts", "rds", "dynamodb", "cloudfront", "kms", "eks",
        ],
        "compliance": [
            "iam", "ec2", "s3", "lambda", "ecs", "secretsmanager", "sns",
            "beanstalk", "cognito", "sts", "rds", "dynamodb", "cloudfront", "kms", "eks",
        ],
        "ctf": [
            "iam", "ec2", "s3", "lambda", "sts", "rds", "dynamodb",
        ],
    }

    # Service to regions mapping (some services are global)
    GLOBAL_SERVICES = {"iam", "sts", "cloudfront", "route53", "waf", "wafv2", "organizations"}

    def __init__(self, auth_manager: AWSAuthManager, config: ScanConfig | None = None):
        self.auth_manager = auth_manager
        self.config = config or get_config().scan
        self.parallel_scanner = ParallelScanner(auth_manager)
        self._current_session: ScanSession | None = None

    def get_services_for_profile(self, profile: str) -> list[str]:
        """Get list of services for a scan profile."""
        return self.SCAN_PROFILES.get(profile, self.SCAN_PROFILES["standard"])

    def get_regions_for_scan(self, regions: list[str] | None = None) -> list[str]:
        """Get regions to scan, expanding 'all' if needed."""
        if regions is None or not regions:
            return self.config.regions or ["us-east-1"]

        if "all" in regions:
            # Return all available regions (subset for performance)
            return [
                "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "eu-west-1", "eu-west-2", "eu-central-1",
                "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
            ]
        return regions

    async def run_scan(
        self,
        profile: str = "default",
        regions: list[str] | None = None,
        services: list[str] | None = None,
        scan_profile: str = "standard",
        progress_callback=None,
    ) -> ScanSession:
        """Run a complete scan."""
        # Generate scan ID
        scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"

        # Determine services to scan
        if services:
            scan_services = services
        else:
            scan_services = self.get_services_for_profile(scan_profile)

        # Determine regions
        scan_regions = self.get_regions_for_scan(regions)

        # Create session
        session = ScanSession(
            scan_id=scan_id,
            profile=profile,
            regions=scan_regions,
            services=scan_services,
            scan_profile=scan_profile,
            started_at=datetime.now(timezone.utc),
            config_snapshot={
                "aws": {"profile": profile},
                "scan": {
                    "regions": scan_regions,
                    "services": scan_services,
                    "scan_profile": scan_profile,
                },
            },
        )

        self._current_session = session

        try:
            log.info("Starting scan {} with profile {}, regions {}, services {}",
                     scan_id, profile, scan_regions, scan_services)

            # Run the scan
            results = await self.parallel_scanner.scan_services(
                scan_services,
                scan_regions,
                scan_id,
                session.findings,
            )

            session.results = results

            # Count totals
            total_resources = sum(r.resources_found for r in results)
            total_findings = len(session.findings)
            total_errors = sum(len(r.errors) for r in results)

            log.info("Scan {} completed: {} resources, {} findings, {} errors",
                     scan_id, total_resources, total_findings, total_errors)

            session.status = "completed"
            session.completed_at = datetime.now(timezone.utc)

        except Exception as e:
            log.error("Scan {} failed: {}", scan_id, e)
            session.status = "failed"
            session.errors.append(str(e))
            session.completed_at = datetime.now(timezone.utc)
            raise

        finally:
            # Save session
            await self._save_session(session)
            self._current_session = None

        return session

    async def _save_session(self, session: ScanSession) -> None:
        """Save scan session to disk."""
        try:
            sessions_dir = Path.home() / ".local" / "share" / "awsprowl" / "sessions"
            sessions_dir.mkdir(parents=True, exist_ok=True)

            session_file = sessions_dir / f"{session.scan_id}.json"
            import json
            with open(session_file, "w") as f:
                json.dump(session.to_dict(), f, indent=2, default=str)

            log.debug("Saved scan session to {}", session_file)

        except Exception as e:
            log.error("Failed to save session: {}", e)

    def get_current_session(self) -> ScanSession | None:
        """Get the currently running scan session."""
        return self._current_session

    def cancel_current_scan(self) -> None:
        """Cancel the currently running scan."""
        if self._current_session:
            self._current_session.status = "cancelled"
            log.info("Scan {} cancelled", self._current_session.scan_id)

    @staticmethod
    def load_session(scan_id: str) -> ScanSession | None:
        """Load a saved scan session."""
        try:
            sessions_dir = Path.home() / ".local" / "share" / "awsprowl" / "sessions"
            session_file = sessions_dir / f"{scan_id}.json"

            if not session_file.exists():
                return None

            import json
            with open(session_file) as f:
                data = json.load(f)

            session = ScanSession(
                scan_id=data["scan_id"],
                profile=data["profile"],
                regions=data["regions"],
                services=data["services"],
                scan_profile=data["scan_profile"],
                started_at=datetime.fromisoformat(data["started_at"]),
                completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
                status=data["status"],
                findings=data["findings"],
                errors=data["errors"],
                config_snapshot=data["config"],
            )

            # Reconstruct results
            for r in data.get("results", []):
                session.results.append(ScanResult(
                    service=r["service"],
                    region=r["region"],
                    resources_found=r["resources_found"],
                    findings=[],  # Not loaded for memory efficiency
                    errors=r["errors"],
                    duration_ms=r["duration_ms"],
                ))

            return session

        except Exception as e:
            log.error("Failed to load session {}: {}", scan_id, e)
            return None

    @staticmethod
    def list_sessions(limit: int = 50) -> list[dict]:
        """List recent scan sessions."""
        try:
            sessions_dir = Path.home() / ".local" / "share" / "awsprowl" / "sessions"
            if not sessions_dir.exists():
                return []

            sessions = []
            for session_file in sorted(sessions_dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)[:limit]:
                try:
                    import json
                    with open(session_file) as f:
                        data = json.load(f)

                    sessions.append({
                        "scan_id": data["scan_id"],
                        "started_at": data["started_at"],
                        "completed_at": data.get("completed_at"),
                        "status": data["status"],
                        "profile": data["profile"],
                        "regions": data["regions"],
                        "scan_profile": data["scan_profile"],
                        "findings_count": len(data.get("findings", [])),
                        "services": data["services"],
                    })
                except Exception:
                    pass

            return sessions

        except Exception as e:
            log.error("Failed to list sessions: {}", e)
            return []

    @staticmethod
    def delete_session(scan_id: str) -> bool:
        """Delete a scan session."""
        try:
            sessions_dir = Path.home() / ".local" / "share" / "awsprowl" / "sessions"
            session_file = sessions_dir / f"{scan_id}.json"

            if session_file.exists():
                session_file.unlink()
                return True

            return False

        except Exception as e:
            log.error("Failed to delete session {}: {}", scan_id, e)
            return False

    @staticmethod
    def clean_old_sessions(keep: int = 10) -> int:
        """Clean old scan sessions, keeping only the most recent."""
        try:
            sessions_dir = Path.home() / ".local" / "share" / "awsprowl" / "sessions"
            if not sessions_dir.exists():
                return 0

            session_files = sorted(sessions_dir.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)
            deleted = 0

            for session_file in session_files[keep:]:
                try:
                    session_file.unlink()
                    deleted += 1
                except Exception:
                    pass

            return deleted

        except Exception as e:
            log.error("Failed to clean sessions: {}", e)
            return 0
