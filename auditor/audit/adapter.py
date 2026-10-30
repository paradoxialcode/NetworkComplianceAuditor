from __future__ import annotations

from pathlib import PurePath
from typing import Final

from auditor.parsers import normalizer as parsed
from auditor.schema import baseline as schema

_VENDORS: Final = {
    parsed.Vendor.CISCO_IOS: schema.Vendor.Cisco,
    parsed.Vendor.FORTIOS: schema.Vendor.Fortinet,
}
_PLATFORMS: Final = {
    parsed.Vendor.CISCO_IOS: "Cisco IOS",
    parsed.Vendor.FORTIOS: "FortiOS",
}
_FALLBACK_HOSTNAME: Final = "unknown-device"
_MAX_NAME_LEN: Final = 255
_MAX_TEXT_LEN: Final = 500
_BUILTIN_CONFIDENCE: Final = 1.0

_State = schema.SecurityState


def _clip(text: str, limit: int = _MAX_TEXT_LEN) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _basename(name: str | None) -> str | None:
    if not name:
        return None
    base = PurePath(name.replace("\\", "/")).name
    return base[:_MAX_NAME_LEN] or None


def _state(fact: parsed.Fact[bool] | None) -> schema.SecurityState:
    if fact is None:
        return _State.UNKNOWN
    return _State.ENABLED if fact.value else _State.DISABLED


def _admin_state(fact: parsed.Fact[bool] | None) -> schema.SecurityState:
    if fact is None:
        return _State.UNKNOWN
    return _State.DISABLED if fact.value else _State.ENABLED


def _evidence(evidence: parsed.Evidence, vendor: parsed.Vendor) -> schema.Evidence:
    return schema.Evidence(
        text=_clip(evidence.raw),
        line=evidence.line_number,
        mapping_id=f"builtin:{vendor.value}",
        confidence=_BUILTIN_CONFIDENCE,
    )


def _facts(result: parsed.SecurityBaseline) -> list[schema.SecurityFact]:
    facts: list[schema.SecurityFact] = []
    for key, fact in (
        ("telnet_enabled", result.telnet_enabled),
        ("http_management_enabled", result.http_management_enabled),
        ("password_encryption", result.password_encryption),
    ):
        if fact is not None:
            facts.append(
                schema.SecurityFact(
                    key=key,
                    value=fact.value,
                    state=_state(fact),
                    evidence=_evidence(fact.evidence, result.vendor),
                )
            )
    if result.local_users:
        facts.append(
            schema.SecurityFact(
                key="local_users",
                value=[user.value for user in result.local_users],
                state=_State.ENABLED,
                evidence=_evidence(result.local_users[0].evidence, result.vendor),
            )
        )
    return facts


def to_schema_baseline(
    result: parsed.SecurityBaseline,
    *,
    filename: str | None = None,
    sha256: str | None = None,
) -> schema.SecurityBaseline:
    if not isinstance(result, parsed.SecurityBaseline):
        raise TypeError(f"expected a normalizer SecurityBaseline, got {type(result).__name__}")

    vendor = _VENDORS.get(result.vendor, schema.Vendor.Unknown)
    source = _basename(filename) or _basename(result.source_file)
    hostname = result.hostname.value[:_MAX_NAME_LEN] if result.hostname else None
    ntp = [server.value for server in result.ntp_servers]
    syslog = [server.value for server in result.syslog_servers]

    return schema.SecurityBaseline(
        device=schema.DeviceMetadata(
            hostname=hostname or _FALLBACK_HOSTNAME,
            vendor=vendor,
            platform=_PLATFORMS.get(result.vendor, "Unknown"),
            sha256=sha256,
            filename=source,
        ),
        management=schema.ManagementAccess(
            ssh=_State.UNKNOWN,
            telnet=_state(result.telnet_enabled),
            http=_state(result.http_management_enabled),
            https=_State.UNKNOWN,
        ),
        auth=schema.AuthenticationSettings(local=_State.ENABLED if result.local_users else None),
        logging=schema.LoggingSettings(
            enabled=_State.ENABLED if syslog else _State.UNKNOWN,
            destinations=syslog,
        ),
        time_sync=schema.TimeSync(
            enabled=_State.ENABLED if ntp else _State.UNKNOWN,
            servers=ntp,
        ),
        interfaces=[
            schema.NetworkInterface(
                name=_clip(interface.name.value, _MAX_NAME_LEN),
                description=_clip(interface.description.value) if interface.description else None,
                admin_state=_admin_state(interface.admin_down),
            )
            for interface in result.interfaces
        ],
        facts=_facts(result),
        unrecognized=[
            schema.UnrecognizedConfig(
                text=_clip(warning.message),
                vendor=vendor,
                location=f"line {warning.line_number}",
                reason="normalizer warning",
            )
            for warning in result.warnings
        ],
    )
