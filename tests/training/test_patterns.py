"""Tests for auditor.parsers.patterns."""

from __future__ import annotations

import dataclasses
import math
import random
import re
import unicodedata
import warnings
from typing import Any

import pytest

from auditor.training import patterns as pat
from auditor.parsers.normalizer import SecurityBaseline, Vendor
from auditor.training.patterns import (
    TARGET_FIELD_TYPES,
    MatchMethod,
    PatternRule,
    RuleSource,
    ensure_unique_rule_ids,
)

EXACT, PREFIX, REGEX = MatchMethod.EXACT, MatchMethod.PREFIX, MatchMethod.REGEX


def make(**overrides: Any) -> PatternRule:
    base: dict[str, Any] = {
        "rule_id": "cisco-http-server",
        "vendor": Vendor.CISCO_IOS,
        "method": EXACT,
        "expression": "ip http server",
        "target_field": "http_management_enabled",
        "suggested_value": True,
        "confidence": 0.9,
        "explanation": "Clear-text HTTP management is enabled.",
    }
    base.update(overrides)
    return PatternRule(**base)


def rebuild(rule: PatternRule) -> PatternRule:
    return PatternRule(
        rule_id=rule.rule_id,
        vendor=rule.vendor,
        method=rule.method,
        expression=rule.expression,
        target_field=rule.target_field,
        suggested_value=rule.suggested_value,
        confidence=rule.confidence,
        explanation=rule.explanation,
        source=rule.source,
    )


# ============================================================ construction ====
def test_valid_rule_for_every_method_and_vendor() -> None:
    for vendor in Vendor:
        for method, expression in ((EXACT, "ip http server"), (PREFIX, "ip http"), (REGEX, r"^ip http \S+$")):
            rule = make(vendor=vendor, method=method, expression=expression)
            assert rule.vendor is vendor
            assert rule.method is method
            assert rule.expression == expression


def test_all_fields_are_normalized() -> None:
    rule = make(
        rule_id="  Cisco-HTTP-Server ",
        vendor=" CISCO_IOS ",
        method="Exact",
        expression="  ip http server\n",
        explanation="  Clear-text \n\t HTTP   management  ",
        confidence=1,
        source=RuleSource(name="  CIS   IOS  Benchmark ", reference=" §1.2 ", version=" 4.0 "),
    )
    assert rule.rule_id == "cisco-http-server"
    assert rule.vendor is Vendor.CISCO_IOS
    assert rule.method is EXACT
    assert rule.expression == "ip http server"
    assert rule.explanation == "Clear-text HTTP management"
    assert rule.confidence == 1.0 and isinstance(rule.confidence, float)
    assert rule.source == RuleSource("CIS IOS Benchmark", "§1.2", "4.0")


def test_unicode_is_nfc_normalized() -> None:
    rule = make(expression="hostname cafe\u0301")
    assert rule.expression == unicodedata.normalize("NFC", "hostname cafe\u0301") == "hostname café"
    assert make(explanation="cafe\u0301 policy").explanation == "café policy"


def test_normalization_is_idempotent() -> None:
    rule = make(rule_id="MiXeD.1", explanation=" a   b ", confidence=1)
    assert rebuild(rule) == rule
    assert rebuild(rebuild(rule)) == rule


# ================================================================ enums ====
@pytest.mark.parametrize(
    "value", [Vendor.FORTIOS, "fortios", " FortiOS ", "FORTIOS"]
)
def test_vendor_accepted_forms(value: object) -> None:
    target = make(vendor=value, target_field="telnet_enabled")
    assert target.vendor is Vendor.FORTIOS


@pytest.mark.parametrize("value", ["palo", "", "cisco", "cisco ios", "xml"])
def test_unsupported_vendor_is_rejected_without_echo(value: str) -> None:
    with pytest.raises(ValueError, match="unsupported vendor; expected one of: cisco_ios, fortios, junos") as info:
        make(vendor=value)
    if value:
        assert value not in str(info.value).replace("cisco_ios", "").replace("fortios", "")


@pytest.mark.parametrize("value", [None, 1, 1.5, b"fortios", ["fortios"]])
def test_vendor_wrong_type(value: object) -> None:
    with pytest.raises(TypeError, match="vendor must be a Vendor or str"):
        make(vendor=value)


@pytest.mark.parametrize(
    ("value", "expected"),
    [("exact", EXACT), (" PREFIX ", PREFIX), ("Regex", REGEX), (REGEX, REGEX)],
)
def test_method_accepted_forms(value: object, expected: MatchMethod) -> None:
    expression = r"^ip http \S+$" if expected is REGEX else "ip http server"
    assert make(method=value, expression=expression).method is expected


@pytest.mark.parametrize("value", ["glob", "", "contains"])
def test_unsupported_method(value: str) -> None:
    with pytest.raises(ValueError, match="unsupported method; expected one of: exact, prefix, regex"):
        make(method=value)


def test_method_wrong_type() -> None:
    with pytest.raises(TypeError, match="method must be a MatchMethod or str"):
        make(method=None)


def test_match_method_values() -> None:
    assert [m.value for m in MatchMethod] == ["exact", "prefix", "regex"]


# ============================================================== rule_id ====
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("a", "a"),
        ("Rule_01", "rule_01"),
        ("cis-1.1.2", "cis-1.1.2"),
        ("a:b", "a:b"),
        ("0abc", "0abc"),
        ("x" * 64, "x" * 64),
        ("a\n", "a"),
    ],
)
def test_valid_rule_ids(raw: str, expected: str) -> None:
    assert make(rule_id=raw).rule_id == expected


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "-abc", ".abc", "_abc", "a b", "a/b", "é", "x" * 65, "a\nb", "a\u200bb", "a$b"],
)
def test_invalid_rule_ids(raw: str) -> None:
    with pytest.raises(ValueError, match="rule_id"):
        make(rule_id=raw)


@pytest.mark.parametrize("raw", [None, 123, b"abc"])
def test_rule_id_wrong_type(raw: object) -> None:
    with pytest.raises(TypeError, match="rule_id must be a str"):
        make(rule_id=raw)


# ============================================================ text fields ====
@pytest.mark.parametrize("field", ["expression", "explanation"])
@pytest.mark.parametrize("value", ["", "   ", "\n\t"])
def test_empty_text_is_rejected(field: str, value: str) -> None:
    with pytest.raises(ValueError, match=f"{field} must not be empty"):
        make(**{field: value})


@pytest.mark.parametrize("field", ["expression", "explanation", "target_field"])
@pytest.mark.parametrize("value", [None, 5, b"x", ["x"]])
def test_text_wrong_type(field: str, value: object) -> None:
    with pytest.raises(TypeError, match=f"{field} must be a str"):
        make(**{field: value})


def test_length_limits() -> None:
    assert make(expression="x" * 256).expression == "x" * 256
    with pytest.raises(ValueError, match="expression must be at most 256 characters"):
        make(expression="x" * 257)
    assert len(make(explanation="x" * 500).explanation) == 500
    with pytest.raises(ValueError, match="explanation must be at most 500 characters"):
        make(explanation="x" * 501)
    with pytest.raises(ValueError, match="suggested_value must be at most 255 characters"):
        make(target_field="hostname", suggested_value="x" * 256)


@pytest.mark.parametrize(
    "value",
    ["ip\thttp server", "ip http\x00server", "ip http\u202eserver", "ip http\u200bserver", "ip\nhttp"],
)
def test_control_and_invisible_characters_are_rejected(value: str) -> None:
    with pytest.raises(ValueError, match="control or invisible characters"):
        make(expression=value)
    with pytest.raises(ValueError, match="control or invisible characters"):
        make(explanation=value.replace("\t", "\x07").replace("\n", "\x07"))


def test_non_space_whitespace_inside_expression_is_rejected() -> None:
    with pytest.raises(ValueError, match="non-space whitespace"):
        make(expression="ip\u00a0http server")
    # but it is harmless at the edges and collapsed in prose
    assert make(expression="\u00a0ip http server\u00a0").expression == "ip http server"
    assert make(explanation="a\u00a0\u00a0b").explanation == "a b"


# ================================================================ regex ====
@pytest.mark.parametrize(
    "expression", [r"^ip http server$", r"^ntp server (\S+)", r"(?i)^HOSTNAME\b", r"^interface (Gi|Te)\S+$"]
)
def test_valid_regex(expression: str) -> None:
    assert make(method=REGEX, expression=expression).expression == expression


@pytest.mark.parametrize(
    "expression", ["(", "[a-", "*a", "a{2,1}", "(?P<n>x)(?P<n>y)", "\\", "(?P<1a>x)", "\\9"]
)
def test_malformed_regex_is_rejected(expression: str) -> None:
    with pytest.raises(ValueError, match="not a valid regular expression"):
        make(method=REGEX, expression=expression)


def test_regex_overflow_and_missing_position_are_handled() -> None:
    with pytest.raises(ValueError, match="pattern too complex or repeat count too large"):
        make(method=REGEX, expression="a{99999999999}")
    with pytest.raises(ValueError, match="look-behind requires fixed-width") as info:
        make(method=REGEX, expression="(?<=a*)b")
    assert "None" not in str(info.value)
    with pytest.raises(ValueError, match=r"at position \d+"):
        make(method=REGEX, expression="[a-")


@pytest.mark.parametrize("expression", [".*", "a*", "foo|", "^$", "(?:)", "(a|)"])
def test_regex_matching_the_empty_string_is_rejected(expression: str) -> None:
    with pytest.raises(ValueError, match="must not match the empty string"):
        make(method=REGEX, expression=expression)


@pytest.mark.parametrize("method", [EXACT, PREFIX])
@pytest.mark.parametrize("expression", ["(", "[a-", "*a", ".*"])
def test_regex_rules_do_not_apply_to_other_methods(method: MatchMethod, expression: str) -> None:
    assert make(method=method, expression=expression).expression == expression


@pytest.mark.parametrize(
    "expression", ["[[a]", "[a[b]", "[a--b]", "[a&&b]", "[a~~b]", "[a||b]", "[^[a]", r"x[a-z[]"]
)
def test_ambiguous_character_class_syntax_is_rejected(expression: str) -> None:
    with pytest.raises(ValueError, match="character-class syntax whose meaning is ambiguous"):
        make(method=REGEX, expression=expression)


@pytest.mark.parametrize(
    "expression",
    [r"[\[a]", "[]a]", "[^]a]", "[a-z-]", r"[a\-b]", r"[a-z]+\d", r"\[a--b\]", "a--b", r"a\|\|b", "a&&b"],
)
def test_unambiguous_character_classes_are_allowed(expression: str) -> None:
    assert make(method=REGEX, expression=expression).expression == expression


def test_ambiguous_scan_covers_everything_cpython_warns_about() -> None:
    rng = random.Random(24680)
    pool = ["[", "]", "^", "-", "&", "~", "|", "a", "b", "\\", "(", ")", "+"]
    warned = 0
    for _ in range(30_000):
        expression = "".join(rng.choice(pool) for _ in range(rng.randint(1, 9)))
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                re.compile(expression)
            except re.error:
                continue
        if any(issubclass(w.category, FutureWarning) for w in caught):
            warned += 1
            assert pat._has_ambiguous_set_syntax(expression), expression
    assert warned > 30  # the property really was exercised


# ========================================================= target / value ====
@pytest.mark.parametrize(
    ("target", "value"),
    [
        ("hostname", "core-r1"),
        ("ntp_servers", "10.0.0.1"),
        ("syslog_servers", "10.0.1.1"),
        ("local_users", "admin"),
        ("telnet_enabled", False),
        ("http_management_enabled", True),
        ("password_encryption", True),
    ],
)
def test_every_target_field(target: str, value: object) -> None:
    assert make(target_field=target, suggested_value=value).target_field == target


@pytest.mark.parametrize("target", ["interfaces", "vendor", "warnings", "source_file", "nope", "Hostname "])
def test_unsupported_target_field(target: str) -> None:
    if target == "Hostname ":
        with pytest.raises(ValueError, match="unsupported target_field"):
            make(target_field=target, suggested_value="x")
        return
    with pytest.raises(ValueError, match="unsupported target_field; expected one of: hostname"):
        make(target_field=target, suggested_value="x")


def test_target_surrounding_whitespace_is_stripped() -> None:
    assert make(target_field=" hostname ", suggested_value="r1").target_field == "hostname"


def test_vendor_specific_target() -> None:
    assert make(target_field="password_encryption", vendor=Vendor.CISCO_IOS).vendor is Vendor.CISCO_IOS
    with pytest.raises(ValueError, match="'password_encryption' is not available for vendor fortios"):
        make(target_field="password_encryption", vendor=Vendor.FORTIOS)


@pytest.mark.parametrize("value", ["true", "True", 1, 0, None, 1.0, [True]])
def test_bool_targets_require_a_real_bool(value: object) -> None:
    with pytest.raises(TypeError, match="suggested_value for 'telnet_enabled' must be a bool"):
        make(target_field="telnet_enabled", suggested_value=value)


@pytest.mark.parametrize("value", [True, False, 5, None, b"x"])
def test_text_targets_require_text(value: object) -> None:
    with pytest.raises(TypeError, match="suggested_value must be a str"):
        make(target_field="hostname", suggested_value=value)


def test_text_suggestion_is_normalized_and_validated() -> None:
    assert make(target_field="hostname", suggested_value="  core   r1 ").suggested_value == "core r1"
    with pytest.raises(ValueError, match="suggested_value must not be empty"):
        make(target_field="hostname", suggested_value="  ")
    with pytest.raises(ValueError, match="control or invisible characters"):
        make(target_field="hostname", suggested_value="a\x00b")


def test_target_tables_are_consistent_with_the_baseline() -> None:
    baseline_fields = {f.name for f in dataclasses.fields(SecurityBaseline)}
    assert set(TARGET_FIELD_TYPES) <= baseline_fields
    assert set(TARGET_FIELD_TYPES.values()) == {str, bool}
    assert set(pat._FIELD_VENDORS) <= set(TARGET_FIELD_TYPES)
    for vendors in pat._FIELD_VENDORS.values():
        assert vendors <= set(Vendor)
    pat._verify_targets(baseline_fields)


def test_verify_targets_detects_drift() -> None:
    with pytest.raises(RuntimeError, match="missing from SecurityBaseline: telnet_enabled"):
        pat._verify_targets(name for name in TARGET_FIELD_TYPES if name != "telnet_enabled")


def test_target_table_is_read_only() -> None:
    with pytest.raises(TypeError):
        TARGET_FIELD_TYPES["extra"] = str  # type: ignore[index]


# ============================================================ confidence ====
@pytest.mark.parametrize(
    ("value", "expected"), [(0, 0.0), (1, 1.0), (0.0, 0.0), (1.0, 1.0), (0.5, 0.5), (1e-9, 1e-9)]
)
def test_valid_confidence(value: float, expected: float) -> None:
    rule = make(confidence=value)
    assert rule.confidence == expected
    assert isinstance(rule.confidence, float)


def test_negative_zero_is_normalized() -> None:
    assert math.copysign(1.0, make(confidence=-0.0).confidence) == 1.0


@pytest.mark.parametrize(
    "value", [-0.01, 1.01, 2, -1, float("nan"), float("inf"), float("-inf"), 10**400, -(10**400)]
)
def test_confidence_out_of_range(value: float) -> None:
    with pytest.raises(ValueError, match="confidence must be between 0.0 and 1.0"):
        make(confidence=value)


@pytest.mark.parametrize("value", [True, False, "0.5", None, [0.5]])
def test_confidence_wrong_type(value: object) -> None:
    with pytest.raises(TypeError, match="confidence must be a number"):
        make(confidence=value)


# ================================================================ secrets ====
REJECTED_EXPRESSIONS: list[tuple[MatchMethod, str, str]] = [
    (EXACT, "username admin secret hunter2", "hunter2"),
    (EXACT, "enable password 7 0822455D0A16", "0822455D0A16"),
    (PREFIX, "snmp-server community public", "public"),
    (EXACT, 'username a password "hunter2"', "hunter2"),
    (EXACT, "ENABLE SECRET hunter2", "hunter2"),
    (EXACT, "username admin secret 9 $9$abcdefgh", "abcdefgh"),
    (REGEX, r"^username \S+ password 7 0822455D0A16$", "0822455D0A16"),
    (REGEX, r"^enable secret \$9\$abcdefgh$", "abcdefgh"),
    (EXACT, "-----BEGIN RSA PRIVATE KEY-----", "RSA PRIVATE"),
    (EXACT, "set psksecret ENC SH2" + "a" * 40, "SH2aaaa"),
    (EXACT, "x " + "a1" * 20, "a1a1a1a1"),
    (EXACT, "x " + "0123456789abcdef" * 3, "0123456789abcdef"),
    (EXACT, "x " + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=" , "QUJDREVG"),
    (EXACT, "fetch https://admin:s3cr3t@host/path", "s3cr3t"),
    (EXACT, "fetch https://host/path?token=abc123def", "abc123def"),
    (EXACT, "set password ENC", "ENC"),
    # regression: regex punctuation glued to the keyword must not hide it
    (REGEX, r"^password hunter2", "hunter2"),
    (REGEX, r"(?:password) hunter2", "hunter2"),
    (REGEX, r"^enable password hunter2$", "hunter2"),
    (REGEX, r"(password|secret) hunter2", "hunter2"),
    (REGEX, r"(password hunter2|x)", "hunter2"),
    (REGEX, r"(?i)^username \S+ SECRET hunter2$", "hunter2"),
]


@pytest.mark.parametrize(("method", "expression", "secret"), REJECTED_EXPRESSIONS)
def test_secrets_in_expressions_are_rejected_without_echo(
    method: MatchMethod, expression: str, secret: str
) -> None:
    with pytest.raises(ValueError, match="expression must not contain a secret") as info:
        make(method=method, expression=expression)
    assert secret not in str(info.value)


@pytest.mark.parametrize(
    ("method", "expression"),
    [
        (EXACT, "service password-encryption"),
        (EXACT, "no service password-encryption"),
        (PREFIX, "username admin secret"),
        (PREFIX, "enable secret"),
        (EXACT, "set password"),
        (REGEX, r"^username \S+ secret \d \S+$"),
        (REGEX, r"^snmp-server community \S+ (RO|RW)$"),
        (EXACT, "set hostname core-router-datacenter-primary-01"),
        (EXACT, "ntp server 10.0.0.1"),
        (EXACT, "ip http server"),
        (REGEX, r"[A-Za-z0-9+/=]{32,}"),
        (REGEX, r"^enable secret (5|9) \S+$"),
        (REGEX, r"^username \S+ password \S+$"),
        (REGEX, r"^(password|secret) \S+$"),
        (REGEX, r"^enable secret .*"),
    ],
)
def test_legitimate_expressions_are_allowed(method: MatchMethod, expression: str) -> None:
    assert make(method=method, expression=expression).expression == expression


def test_documented_false_positive_is_pinned() -> None:
    # A secret keyword followed by a literal word is rejected even when the
    # word is only a type indicator; end the expression at the keyword.
    with pytest.raises(ValueError, match="credential value"):
        make(expression="enable secret 9")


@pytest.mark.parametrize(
    ("field", "text"),
    [
        ("explanation", "-----BEGIN PRIVATE KEY----- abc"),
        ("explanation", "stored as $6$saltsalt$hashhashhash"),
        ("explanation", "see https://user:pw@host/x"),
        ("explanation", "see https://example.com/doc?token=abc123"),
        ("explanation", "key is " + "A1" * 20),
    ],
)
def test_secrets_in_explanations_are_rejected(field: str, text: str) -> None:
    with pytest.raises(ValueError, match="explanation must not contain a secret"):
        make(**{field: text})


@pytest.mark.parametrize(
    "text",
    [
        "Enable password encryption so stored passwords are obfuscated.",
        "Use a strong secret and rotate community strings regularly.",
        "Telnet sends the password in clear text.",
    ],
)
def test_prose_about_passwords_is_allowed(text: str) -> None:
    assert make(explanation=text).explanation == text


def test_secret_in_suggested_value_is_rejected() -> None:
    with pytest.raises(ValueError, match="suggested_value must not contain a secret") as info:
        make(target_field="hostname", suggested_value="password hunter2")
    assert "hunter2" not in str(info.value)
    with pytest.raises(ValueError, match="suggested_value must not contain a secret"):
        make(target_field="local_users", suggested_value="$9$abcdefgh")


def test_secret_scan_runs_before_regex_compile() -> None:
    # A regex that is both malformed and secret-bearing must report the
    # secret, never a compile error that could quote the pattern.
    with pytest.raises(ValueError, match="must not contain a secret"):
        make(method=REGEX, expression="(password hunter2")


def test_valid_rules_expose_no_secret_in_repr() -> None:
    rule = make(
        method=REGEX,
        expression=r"^username \S+ secret \d \S+$",
        source=RuleSource("CIS", "https://www.cisco.com/c/en/us/support", "4.0"),
    )
    assert "hunter2" not in repr(rule)
    assert "-----" not in repr(rule)


# ================================================================ source ====
def test_rule_source_fields() -> None:
    assert RuleSource("Runbook") == RuleSource("  Runbook ", None, None)
    source = RuleSource("CIS Cisco IOS 17 Benchmark", "https://www.cisco.com/c/en/us/support", "v2.0")
    assert (source.name, source.version) == ("CIS Cisco IOS 17 Benchmark", "v2.0")


@pytest.mark.parametrize("kwargs", [{"name": ""}, {"name": "  "}, {"name": "n", "reference": " "}, {"name": "n", "version": ""}])
def test_rule_source_empty_text(kwargs: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        RuleSource(**kwargs)


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"name": "x" * 101}, "source name must be at most 100"),
        ({"name": "n", "reference": "x" * 301}, "source reference must be at most 300"),
        ({"name": "n", "version": "x" * 51}, "source version must be at most 50"),
    ],
)
def test_rule_source_length_limits(kwargs: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        RuleSource(**kwargs)


@pytest.mark.parametrize("kwargs", [{"name": 1}, {"name": "n", "reference": 2}, {"name": "n", "version": b"v"}])
def test_rule_source_wrong_type(kwargs: dict[str, Any]) -> None:
    with pytest.raises(TypeError, match="must be a str"):
        RuleSource(**kwargs)


@pytest.mark.parametrize(
    "reference",
    ["https://user:pw@host/x", "https://example.com/doc?api_key=abcdef", "-----BEGIN CERTIFICATE-----"],
)
def test_rule_source_rejects_secrets(reference: str) -> None:
    with pytest.raises(ValueError, match="source reference must not contain a secret"):
        RuleSource("n", reference)


def test_rule_source_type_is_checked_on_rules() -> None:
    with pytest.raises(TypeError, match="source must be a RuleSource or None"):
        make(source="CIS")
    assert make(source=None).source is None


# ================================================================ unique ids ====
def test_ensure_unique_rule_ids() -> None:
    ensure_unique_rule_ids([])
    ensure_unique_rule_ids([make(rule_id="a"), make(rule_id="b")])
    ensure_unique_rule_ids(make(rule_id=name) for name in ("x", "y"))  # any iterable


def test_duplicate_ids_are_reported_once_each() -> None:
    rules = [make(rule_id="a"), make(rule_id="B"), make(rule_id="A"), make(rule_id="b"), make(rule_id="b")]
    with pytest.raises(ValueError, match="duplicate rule_id values: a, b$"):
        ensure_unique_rule_ids(rules)


def test_ensure_unique_rule_ids_type_check() -> None:
    with pytest.raises(TypeError, match="rules must contain only PatternRule, got str"):
        ensure_unique_rule_ids(["rule"])  # type: ignore[list-item]


# ============================================================== immutability ====
def test_models_are_frozen_slotted_and_hashable() -> None:
    rule = make(source=RuleSource("CIS"))
    with pytest.raises(dataclasses.FrozenInstanceError):
        rule.confidence = 0.1  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        rule.source.name = "other"  # type: ignore[union-attr, misc]
    assert not hasattr(rule, "__dict__")
    assert not hasattr(rule.source, "__dict__")
    assert {rule, make(source=RuleSource("CIS"))} == {rule}
    assert make() != make(confidence=0.1)


def test_replace_revalidates_and_renormalizes() -> None:
    rule = make()
    with pytest.raises(ValueError, match="confidence must be between"):
        dataclasses.replace(rule, confidence=2.0)
    assert dataclasses.replace(rule, rule_id="NEW-ID").rule_id == "new-id"


def test_module_is_limited_to_modelling() -> None:
    assert set(pat.__all__) == {
        "MatchMethod",
        "RuleSource",
        "PatternRule",
        "TARGET_FIELD_TYPES",
        "clean_captured_value",
        "ensure_unique_rule_ids",
    }
    public_methods = {name for name in vars(PatternRule) if not name.startswith("_")}
    assert not {"match", "matches", "evaluate", "save", "load", "train"} & public_methods


# ================================================================ fuzzing ====
TEXT_POOL = [
    "a", "b", "1", "-", " ", "\t", "\n", "é", "\u0301", "\u200b", "\u202e", "\x00", "\u00a0",
    "password", "secret", "$9$abc", "-----BEGIN", "hunter2", "ip http server", "https://u:p@h",
]
REGEX_POOL = [
    "a", "b", ".", "*", "+", "?", "(", ")", "[", "]", "{", "}", "|", "^", "$", "\\", "\\d",
    "(?:", "(?P<", "x{2,3}", "\\1", "(?i)", "{99999999999}", "(?<=a)", "[a-z]",
]


def random_text(rng: random.Random, pool: list[str]) -> str:
    return "".join(rng.choice(pool) for _ in range(rng.randint(0, 8)))


def test_fuzz_construction_only_raises_validation_errors_and_is_idempotent() -> None:
    rng = random.Random(8642)
    successes = 0
    for _ in range(4000):
        target = rng.choice([*TARGET_FIELD_TYPES, "nope"])
        is_bool = TARGET_FIELD_TYPES.get(target) is bool
        if rng.random() < 0.75:
            suggested: object = rng.choice([True, False]) if is_bool else "core-r1"
        else:
            suggested = rng.choice([True, "x", 5, None, "", random_text(rng, TEXT_POOL)])
        method = rng.choice([*MatchMethod, "glob"])
        expression = (
            random_text(rng, REGEX_POOL) if method == "regex" or method is REGEX else random_text(rng, TEXT_POOL)
        )
        if rng.random() < 0.5:
            expression = rng.choice(["ip http server", "^ip http \\S+$", "ntp server"])
        kwargs: dict[str, Any] = {
            "rule_id": rng.choice(["r1", "R-2", "bad id", "", random_text(rng, TEXT_POOL)]),
            "vendor": rng.choice([Vendor.CISCO_IOS, "fortios", "junos", None]),
            "method": method,
            "expression": expression,
            "target_field": target,
            "suggested_value": suggested,
            "confidence": rng.choice([0.5, 0, 1, 2, -1, float("nan"), "x", True]),
            "explanation": rng.choice(["Because.", "", random_text(rng, TEXT_POOL)]),
            "source": rng.choice([None, RuleSource("CIS")]),
        }
        for key in ("rule_id", "vendor", "method", "confidence", "explanation"):
            if rng.random() < 0.6:
                kwargs[key] = make().__getattribute__(key) if key != "rule_id" else "r1"
        try:
            rule = PatternRule(**kwargs)
        except (ValueError, TypeError):
            continue
        successes += 1
        assert rebuild(rule) == rule
        assert 0.0 <= rule.confidence <= 1.0
        assert rule.expression == rule.expression.strip() and rule.expression
        assert not any(unicodedata.category(c).startswith("C") for c in rule.expression)
        if rule.method is REGEX:
            assert re.compile(rule.expression).search("") is None
    assert successes > 20


def test_fuzz_regex_construction_never_leaks_other_exceptions() -> None:
    rng = random.Random(97531)
    compiled = 0
    for _ in range(3000):
        expression = "".join(rng.choice(REGEX_POOL) for _ in range(rng.randint(1, 12)))
        try:
            rule = make(method=REGEX, expression=expression)
        except ValueError:
            continue
        compiled += 1
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            assert re.compile(rule.expression).search("") is None
    assert compiled > 10