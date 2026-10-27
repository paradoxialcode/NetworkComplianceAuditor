from __future__ import annotations

import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


class Vendor(str, Enum):
    """Supported device vendors."""

    Cisco = "Cisco"
    Fortinet = "Fortinet"
    Juniper = "Juniper"
    PaloAlto = "PaloAlto"
    SONiC = "SONiC"
    Unknown = "Unknown"


class SecurityState(str, Enum):
    """Tri-state security status."""

    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"


class DeviceMetadata(BaseModel):
    """Device identity and source metadata."""

    hostname: str
    vendor: Vendor
    platform: str
    version: str | None = None
    sha256: str | None = None
    filename: str | None = None

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, value: str | None) -> str | None:
        if value is None:
            return value

        if not _SHA256_RE.fullmatch(value):
            raise ValueError(
                "sha256 must be a 64-character hexadecimal SHA-256 hash"
            )

        return value


class Evidence(BaseModel):
    """Evidence supporting a parsed finding."""

    text: str
    line: int | None = None
    json_path: str | None = None
    mapping_id: str | None = None
    confidence: float | None = None

    @field_validator("line")
    @classmethod
    def validate_line(cls, value: int | None) -> int | None:
        if value is not None and value <= 0:
            raise ValueError("line must be greater than 0")
        return value

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, value: float | None) -> float | None:
        if value is None:
            return value

        if not 0.0 <= value <= 1.0:
            raise ValueError(
                "confidence must be between 0 and 1 inclusive"
            )

        return value


class ManagementAccess(BaseModel):
    """Management protocol access settings."""

    ssh: SecurityState
    telnet: SecurityState
    http: SecurityState
    https: SecurityState


class AuthenticationSettings(BaseModel):
    """Authentication and authorization configuration."""

    local: SecurityState | None = None
    aaa: SecurityState | None = None
    authz: SecurityState | None = None
    method: str | None = None


class LoggingSettings(BaseModel):
    """Logging configuration."""

    enabled: SecurityState
    destinations: list[str] = Field(default_factory=list)
    level: str | None = None


class TimeSync(BaseModel):
    """Time synchronization configuration."""

    enabled: SecurityState
    servers: list[str] = Field(default_factory=list)


class NetworkInterface(BaseModel):
    """Normalized network interface."""

    name: str
    description: str | None = None
    admin_state: SecurityState
    addresses: list[str] = Field(default_factory=list)


class NetworkPolicy(BaseModel):
    """Normalized network security policy."""

    id: str | None = None
    action: str | None = None
    src: str | None = None
    dst: str | None = None
    protocol: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)


class SecurityFact(BaseModel):
    """Generic normalized security fact."""

    key: str
    value: Any
    state: SecurityState | None = None
    evidence: Evidence | None = None


class UnrecognizedConfig(BaseModel):
    """Configuration content that could not be parsed."""

    text: str
    vendor: Vendor | None = None
    location: str | None = None
    reason: str | None = None


class SecurityBaseline(BaseModel):
    """Top-level normalized security baseline."""

    device: DeviceMetadata
    management: ManagementAccess
    auth: AuthenticationSettings
    logging: LoggingSettings
    time_sync: TimeSync

    interfaces: list[NetworkInterface] = Field(default_factory=list)
    policies: list[NetworkPolicy] = Field(default_factory=list)
    facts: list[SecurityFact] = Field(default_factory=list)
    unrecognized: list[UnrecognizedConfig] = Field(default_factory=list)