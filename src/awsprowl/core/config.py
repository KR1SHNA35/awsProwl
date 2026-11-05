"""Configuration management for awsProwl."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AWSConfig(BaseModel):
    """AWS-specific configuration."""

    profile: str | None = None
    region: str = "us-east-1"
    access_key_id: str | None = None
    secret_access_key: str | None = None
    session_token: str | None = None
    role_arn: str | None = None
    external_id: str | None = None
    mfa_serial: str | None = None
    mfa_token: str | None = None
    max_retries: int = 3
    timeout: int = 30
    rate_limit: float = 10.0  # requests per second


class ScanConfig(BaseModel):
    """Scan configuration."""

    profile: Literal["quick", "standard", "deep", "compliance", "ctf", "custom"] = "standard"
    services: list[str] = Field(default_factory=list)
    regions: list[str] = Field(default_factory=lambda: ["us-east-1"])
    include_global_services: bool = True
    parallel_regions: bool = True
    max_workers: int = 10
    timeout_per_service: int = 300
    save_raw_responses: bool = False
    deduplicate_findings: bool = True


class OutputConfig(BaseModel):
    """Output configuration."""

    format: Literal["json", "table", "tree", "sarif", "html", "markdown"] = "table"
    output_dir: str = "./output"
    include_timestamp: bool = True
    compress: bool = False
    pretty_print: bool = True


class WebConfig(BaseModel):
    """Web server configuration."""

    host: str = "127.0.0.1"
    port: int = 8080
    enable_cors: bool = True
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000", "http://localhost:5173"])
    websocket_ping_interval: int = 30
    static_dir: str | None = None


class LoggingConfig(BaseModel):
    """Logging configuration."""

    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    file: str | None = "awsprowl.log"
    max_size: str = "10 MB"
    retention: str = "7 days"
    format: Literal["json", "pretty"] = "pretty"
    colors: bool = True


class UIConfig(BaseModel):
    """UI/UX configuration."""

    theme: Literal["dark", "light", "auto"] = "dark"
    color_scheme: Literal["default", "high_contrast", "monochrome"] = "default"
    show_progress: bool = True
    show_banner: bool = True
    interactive_mode: bool = False
    unicode: bool = True
    compact_tables: bool = False


class Config(BaseSettings):
    """Main configuration class."""

    model_config = SettingsConfigDict(
        env_prefix="AWSPROWL_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    aws: AWSConfig = Field(default_factory=AWSConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    ui: UIConfig = Field(default_factory=UIConfig)

    # Metadata
    version: str = "0.1.0"
    config_version: int = 1

    @field_validator("aws")
    @classmethod
    def validate_aws_config(cls, v: AWSConfig) -> AWSConfig:
        # Allow region from environment
        if not v.region and os.environ.get("AWS_REGION"):
            v.region = os.environ["AWS_REGION"]
        return v

    @classmethod
    def load_from_file(cls, path: Path | str) -> Config:
        """Load configuration from YAML file."""
        path = Path(path)
        if not path.exists():
            return cls()

        with path.open("r") as f:
            data = yaml.safe_load(f) or {}

        return cls(**data)

    def save_to_file(self, path: Path | str) -> None:
        """Save configuration to YAML file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Convert to dict, excluding defaults
        data = self.model_dump(exclude_unset=True, exclude_defaults=False)

        with path.open("w") as f:
            yaml.dump(data, f, default_flow_style=False, sort_keys=False)

    def get_config_dir(self) -> Path:
        """Get the configuration directory."""
        # XDG Base Directory Specification
        config_home = os.environ.get("XDG_CONFIG_HOME")
        if config_home:
            return Path(config_home) / "awsprowl"
        return Path.home() / ".config" / "awsprowl"

    def get_data_dir(self) -> Path:
        """Get the data directory."""
        data_home = os.environ.get("XDG_DATA_HOME")
        if data_home:
            return Path(data_home) / "awsprowl"
        return Path.home() / ".local" / "share" / "awsprowl"

    def get_cache_dir(self) -> Path:
        """Get the cache directory."""
        cache_home = os.environ.get("XDG_CACHE_HOME")
        if cache_home:
            return Path(cache_home) / "awsprowl"
        return Path.home() / ".cache" / "awsprowl"


# Global config instance
_config: Config | None = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def load_config(config_path: Path | str | None = None) -> Config:
    """Load configuration from file or create default."""
    global _config

    # Try config file locations in order
    search_paths = []

    if config_path:
        search_paths.append(Path(config_path))

    # XDG config directory
    config_dir = Path.home() / ".config" / "awsprowl"
    search_paths.append(config_dir / "config.yaml")

    # Current directory
    search_paths.append(Path.cwd() / "awsprowl.yaml")
    search_paths.append(Path.cwd() / ".awsprowl.yaml")

    for path in search_paths:
        if path.exists():
            _config = Config.load_from_file(path)
            return _config

    # No config file found, create default
    _config = Config()
    return _config


def save_config(config: Config | None = None, path: Path | str | None = None) -> None:
    """Save configuration to file."""
    if config is None:
        config = get_config()

    if path is None:
        path = config.get_config_dir() / "config.yaml"

    config.save_to_file(path)


def reset_config() -> None:
    """Reset global configuration."""
    global _config
    _config = None
