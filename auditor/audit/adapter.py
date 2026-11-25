from __future__ import annotations

from pathlib import PurePath
from typing import Final

from auditor.parsers import normalizer as parsed
from auditor.schema import baseline as schema

_VENDORS: Final = {
    parsed.Vendor.CISCO_IOS: schema.Vendor.Cisco,
    parsed.Vendor.FORTIOS: schema.Vendor.Fortinet,
    parsed.Vendor.JUNOS: schema.Vendor.Juniper,
}
_PLATFORMS: Final = {
    parsed.Vendor.CISCO_IOS: "Cisco IOS",
    parsed.Vendor.FORTIOS: "FortiOS",
    parsed.Vendor.JUNOS: "Junos",
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


_PROMOTED: Final = frozenset(
    {"ssh_enabled", "https_enabled", "aaa_enabled", "logging_enabled", "os_version"}
)


def _named(result: parsed.SecurityBaseline, key: str) -> parsed.NamedFact | None:
    return next((fact for fact in result.facts if fact.key == key), None)


def _named_state(result: parsed.SecurityBaseline, key: str) -> schema.SecurityState | None:
    fact = _named(result, key)
    if fact is None or not isinstance(fact.value, bool):
        return None
    return _State.ENABLED if fact.value else _State.DISABLED


def _named_facts(result: parsed.SecurityBaseline) -> list[schema.SecurityFact]:
    facts: list[schema.SecurityFact] = []
    for named in result.facts:
        if named.key in _PROMOTED:
            continue
        facts.append(
            schema.SecurityFact(
                key=named.key,
                value=named.value,
                state=_named_state(result, named.key),
                evidence=_evidence(named.evidence, result.vendor) if named.evidence else None,
            )
        )
    if result.ntp_servers:
        facts.append(
            schema.SecurityFact(
                key="ntp_server_count",
                value=len(result.ntp_servers),
                evidence=_evidence(result.ntp_servers[0].evidence, result.vendor),
            )
        )
    return facts


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
    facts.extend(_named_facts(result))
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
    logging_state = _named_state(result, "logging_enabled")
    if syslog:
        logging_state = _State.ENABLED
    version = _named(result, "os_version")

    return schema.SecurityBaseline(
        device=schema.DeviceMetadata(
            hostname=hostname or _FALLBACK_HOSTNAME,
            vendor=vendor,
            platform=_PLATFORMS.get(result.vendor, "Unknown"),
            sha256=sha256,
            filename=source,
            version=_clip(str(version.value), _MAX_NAME_LEN) if version else None,
        ),
        management=schema.ManagementAccess(
            ssh=_named_state(result, "ssh_enabled") or _State.UNKNOWN,
            telnet=_state(result.telnet_enabled),
            http=_state(result.http_management_enabled),
            https=_named_state(result, "https_enabled") or _State.UNKNOWN,
        ),
        auth=schema.AuthenticationSettings(
            local=_State.ENABLED if result.local_users else None,
            aaa=_named_state(result, "aaa_enabled"),
        ),
        logging=schema.LoggingSettings(
            enabled=logging_state or _State.UNKNOWN,
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
