"""Session management for awsProwl.

Provides session creation, retrieval, and management with SQLite database backend.
Follows patterns from Prowler's ProwlerSession.
"""

from __future__ import annotations

import contextlib
from collections.abc import Generator
from pathlib import Path
from typing import Any

from awsprowl.core.base import Session as DBSession
from awsprowl.core.config import get_config
from awsprowl.core.exceptions import SessionError
from awsprowl.core.models import AWSKey, ProwlSession, migrations
from awsprowl.utils import stringify

# Global reference to active session (set by CLI)
_active_session: ProwlSession | None = None


def get_active_session() -> ProwlSession | None:
    """Get the currently active session."""
    global _active_session
    return _active_session


def set_active_session(session: ProwlSession) -> None:
    """Set the active session globally."""
    global _active_session
    _active_session = session


def create_session(name: str, key_alias: str | None = None) -> ProwlSession:
    """Create a new session."""
    database = DBSession()

    # Run migrations to ensure schema is up to date
    migrations(database)

    # Check if session with this name already exists
    existing = database.query(ProwlSession).filter(ProwlSession.name == name).scalar()
    if existing:
        raise SessionError(f"Session '{name}' already exists")

    session = ProwlSession(name=name, key_alias=key_alias or "default")
    database.add(session)
    database.commit()
    database.refresh(session)

    return session


def get_session(name: str) -> ProwlSession | None:
    """Get a session by name."""
    database = DBSession()
    return database.query(ProwlSession).filter(ProwlSession.name == name).scalar()


def get_active_session_from_db() -> ProwlSession | None:
    """Get the active session from the database."""
    database = DBSession()
    return ProwlSession.get_active_session(database)


def list_sessions() -> list[ProwlSession]:
    """List all sessions."""
    database = DBSession()
    return database.query(ProwlSession).order_by(ProwlSession.created.desc()).all()


def delete_session(name: str) -> bool:
    """Delete a session by name."""
    database = DBSession()
    session = database.query(ProwlSession).filter(ProwlSession.name == name).scalar()
    if not session:
        return False

    database.delete(session)
    database.commit()
    return True


def update_session(name: str, **kwargs) -> ProwlSession | None:
    """Update a session's fields."""
    database = DBSession()
    session = database.query(ProwlSession).filter(ProwlSession.name == name).scalar()
    if not session:
        return None

    for key, value in kwargs.items():
        value = stringify(value)
        setattr(session, key, value)

    database.add(session)
    database.commit()
    database.refresh(session)
    return session


def activate_session(name: str) -> ProwlSession | None:
    """Activate a session by name."""
    database = DBSession()
    session = database.query(ProwlSession).filter(ProwlSession.name == name).scalar()
    if not session:
        return None

    session.activate(database)
    set_active_session(session)
    return session


def deactivate_session() -> None:
    """Deactivate the current session."""
    global _active_session
    _active_session = None


def add_aws_key(
    session_name: str,
    access_key_id: str,
    secret_access_key: str,
    session_token: str | None = None,
    key_alias: str | None = None,
    user_name: str | None = None,
    role_name: str | None = None,
    arn: str | None = None,
    account_id: str | None = None,
    user_id: str | None = None,
) -> AWSKey:
    """Add an AWS key to a session."""
    database = DBSession()
    session = database.query(ProwlSession).filter(ProwlSession.name == session_name).scalar()
    if not session:
        raise SessionError(f"Session '{session_name}' not found")

    # Check if key with this alias already exists for this session
    if key_alias:
        existing = (
            database.query(AWSKey)
            .filter(AWSKey.session_id == session.id, AWSKey.key_alias == key_alias)
            .scalar()
        )
        if existing:
            raise SessionError(f"Key with alias '{key_alias}' already exists in session '{session_name}'")

    key = AWSKey(
        session_id=session.id,
        access_key_id=access_key_id,
        secret_access_key=secret_access_key,
        session_token=session_token,
        key_alias=key_alias or "default",
        user_name=user_name,
        role_name=role_name,
        arn=arn,
        account_id=account_id,
        user_id=user_id,
    )

    database.add(key)
    database.commit()
    database.refresh(key)

    # Update session's key_alias if it matches
    if session.key_alias == key.key_alias:
        session.key_alias = key.key_alias
        database.add(session)
        database.commit()

    return key


def get_aws_keys(session_name: str) -> list[AWSKey]:
    """Get all AWS keys for a session."""
    database = DBSession()
    session = database.query(ProwlSession).filter(ProwlSession.name == session_name).scalar()
    if not session:
        return []

    return session.aws_keys.all()


def get_active_aws_key(session_name: str) -> AWSKey | None:
    """Get the active AWS key for a session (matches session's key_alias)."""
    database = DBSession()
    session = database.query(ProwlSession).filter(ProwlSession.name == session_name).scalar()
    if not session:
        return None

    return session.get_active_aws_key(database)


def delete_aws_key(session_name: str, key_alias: str) -> bool:
    """Delete an AWS key from a session."""
    database = DBSession()
    session = database.query(ProwlSession).filter(ProwlSession.name == session_name).scalar()
    if not session:
        return False

    key = (
        database.query(AWSKey)
        .filter(AWSKey.session_id == session.id, AWSKey.key_alias == key_alias)
        .scalar()
    )
    if not key:
        return False

    database.delete(key)
    database.commit()
    return True


def get_session_dir(session_name: str | None = None) -> Path:
    """Get the session directory path."""
    config = get_config()
    data_dir = config.get_data_dir()

    if session_name is None:
        active = get_active_session()
        if active is None:
            raise SessionError("No active session set")
        session_name = active.name

    session_path = (data_dir / "sessions" / session_name).absolute()
    session_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return session_path


def get_session_downloads_dir(session_name: str | None = None) -> Path:
    """Get the session downloads directory path."""
    session_dir = get_session_dir(session_name)
    downloads_path = (session_dir / "downloads").absolute()
    downloads_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return downloads_path


def get_session_module_data_dir(module: str, session_name: str | None = None) -> Path:
    """Get the session module data directory path."""
    session_dir = get_session_dir(session_name)
    module_path = (session_dir / "modules" / module).absolute()
    module_path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return module_path


@contextlib.contextmanager
def save(
    file_name: str,
    mode: str = "w",
    header: str | None = None,
    session_name: str | None = None,
    **kwargs,
) -> Generator[Any, None, None]:
    """Save content to a file in the session's downloads directory.

    Args:
        file_name: Name of the file to save
        mode: File open mode (default: 'w')
        header: Optional header to write if file doesn't exist (e.g., CSV header)
        session_name: Optional session name (uses active session if not provided)
        **kwargs: Additional arguments passed to open()

    Yields:
        File object for writing
    """
    downloads_dir = get_session_downloads_dir(session_name)
    file_path = downloads_dir / file_name
    file_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    file_exists = file_path.exists()

    with open(file_path, mode, **kwargs) as f:
        if header and not file_exists:
            f.write(header + "\n")
        try:
            yield f
        finally:
            f.close()


def print_session_summary(session: ProwlSession) -> None:
    """Print a summary of a session."""
    print(f"\nSession: {session.name} (ID: {session.id})")
    print(f"  Created: {session.created}")
    print(f"  Active: {session.is_active}")
    print(f"  Key Alias: {session.key_alias or 'None'}")
    print(f"  Regions: {session.session_regions}")

    if session.access_key_id:
        print(f"  Access Key: {session.access_key_id[:8]}...")

    # Count AWS data fields with data
    data_fields = session.get_all_aws_data_fields_as_dict()
    if data_fields:
        print(f"  AWS Data Fields: {len(data_fields)}")
        for field, value in data_fields.items():
            if isinstance(value, dict) or isinstance(value, list):
                print(f"    {field}: {len(value)} items")
            else:
                print(f"    {field}: {type(value).__name__}")
    else:
        print("  AWS Data: None")

    # List keys
    database = DBSession()
    keys = session.aws_keys.all()
    if keys:
        print(f"  AWS Keys ({len(keys)}):")
        for key in keys:
            print(f"    - {key.key_alias} ({key.access_key_id[:8]}...)")
    else:
        print("  AWS Keys: None")


def export_session_data(session: ProwlSession, output_path: Path) -> None:
    """Export session data to a JSON file."""
    import json

    data = {
        "session": {
            "id": session.id,
            "name": session.name,
            "created": str(session.created),
            "is_active": session.is_active,
            "key_alias": session.key_alias,
            "access_key_id": session.access_key_id,
            "session_regions": session.session_regions,
            "user_agent_suffix": session.user_agent_suffix,
        },
        "aws_keys": [],
        "aws_data": session.get_all_aws_data_fields_as_dict(),
    }

    for key in session.aws_keys.all():
        data["aws_keys"].append(key.get_fields_as_camel_case_dictionary())

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def import_session_data(
    name: str,
    data: dict,
    overwrite: bool = False,
) -> ProwlSession:
    """Import session data from a dictionary."""
    database = DBSession()

    # Check if session exists
    existing = database.query(ProwlSession).filter(ProwlSession.name == name).scalar()
    if existing:
        if not overwrite:
            raise SessionError(f"Session '{name}' already exists. Use overwrite=True to replace.")
        database.delete(existing)
        database.commit()

    # Create new session
    session_data = data.get("session", {})
    session = ProwlSession(
        name=name,
        key_alias=session_data.get("key_alias", "default"),
        access_key_id=session_data.get("access_key_id"),
        session_regions=session_data.get("session_regions", ["all"]),
        user_agent_suffix=session_data.get("user_agent_suffix"),
    )
    database.add(session)
    database.commit()
    database.refresh(session)

    # Import AWS keys
    for key_data in data.get("aws_keys", []):
        key = AWSKey(
            session_id=session.id,
            access_key_id=key_data.get("AccessKeyId"),
            secret_access_key=key_data.get("SecretAccessKey"),
            session_token=key_data.get("SessionToken"),
            key_alias=key_data.get("KeyAlias", "default"),
            user_name=key_data.get("UserName"),
            role_name=key_data.get("RoleName"),
            arn=key_data.get("Arn"),
            account_id=key_data.get("AccountId"),
            user_id=key_data.get("UserId"),
            roles=key_data.get("Roles"),
            groups=key_data.get("Groups"),
            policies=key_data.get("Policies"),
            permissions_confirmed=key_data.get("PermissionsConfirmed"),
            allow_permissions=key_data.get("Permissions", {}).get("Allow", {}),
            deny_permissions=key_data.get("Permissions", {}).get("Deny", {}),
            mq=key_data.get("MQ"),
            sns=key_data.get("SNS"),
        )
        database.add(key)

    # Import AWS data
    for field, value in data.get("aws_data", {}).items():
        if hasattr(session, field):
            setattr(session, field, value)

    database.add(session)
    database.commit()
    database.refresh(session)

    return session
