import json
import time

import pytest

from auditor.parsers.normalizer import Vendor
from auditor.training import matcher
from auditor.training.patterns import MatchMethod, PatternRule, clean_captured_value
from auditor.training.store import load_rules, save_rules


def rule(**overrides):
    base = {
        "rule_id": "junos-ntp",
        "vendor": Vendor.JUNOS,
        "method": MatchMethod.REGEX,
        "expression": r"set system ntp server (\S+)",
        "target_field": "ntp_servers",
        "suggested_value": None,
        "confidence": 0.9,
        "explanation": "NTP server",
        "capture_group": 1,
    }
    base.update(overrides)
    return PatternRule(**base)


def flag_rule(**overrides):
    base = {
        "rule_id": "junos-telnet",
        "vendor": Vendor.JUNOS,
        "method": MatchMethod.PREFIX,
        "expression": "set system services telnet",
        "target_field": "telnet_enabled",
        "suggested_value": True,
        "confidence": 0.9,
        "explanation": "Telnet enabled",
        "absent_value": False,
    }
    base.update(overrides)
    return PatternRule(**base)


def test_junos_is_a_vendor_without_a_builtin_normalizer():
    assert Vendor.JUNOS.value == "junos"
    assert PatternRule(
        rule_id="x", vendor="junos", method="exact", expression="set system services telnet",
        target_field="telnet_enabled", suggested_value=True, confidence=0.9, explanation="x",
    ).vendor is Vendor.JUNOS


def test_new_fields_default_to_none():
    plain = PatternRule(
        rule_id="x", vendor="cisco_ios", method="exact", expression="ip http server",
        target_field="http_management_enabled", suggested_value=True, confidence=0.9, explanation="x",
    )
    assert plain.capture_group is None
    assert plain.absent_value is None


@pytest.mark.parametrize(
    "overrides, error",
    [
        ({"method": MatchMethod.PREFIX, "expression": "set system ntp server"}, "requires method 'regex'"),
        ({"target_field": "telnet_enabled", "suggested_value": None}, "requires a text target_field"),
        ({"capture_group": 0}, "between 1 and 1"),
        ({"capture_group": 2}, "between 1 and 1"),
        ({"suggested_value": "10.0.0.1"}, "must be None when capture_group is set"),
        ({"capture_group": True}, TypeError),
        ({"capture_group": "1"}, TypeError),
    ],
)
def test_capture_group_validation(overrides, error):
    with pytest.raises(TypeError if error is TypeError else ValueError, match=None if error is TypeError else error):
        rule(**overrides)


@pytest.mark.parametrize(
    "overrides, error",
    [
        ({"target_field": "hostname", "suggested_value": "x"}, "requires a boolean target_field"),
        ({"absent_value": "false"}, TypeError),
        ({"absent_value": 0}, TypeError),
    ],
)
def test_absent_value_validation(overrides, error):
    with pytest.raises(TypeError if error is TypeError else ValueError, match=None if error is TypeError else error):
        flag_rule(**overrides)


def test_suggested_value_is_still_required_without_a_capture_group():
    with pytest.raises((TypeError, ValueError)):
        rule(capture_group=None)


@pytest.mark.parametrize("expression", [r"(a|aa)+$", r"^(\d|\d\d)+$"])
def test_catastrophic_backtracking_patterns_are_rejected_at_creation(expression):
    with pytest.raises(ValueError, match="catastrophic backtracking"):
        flag_rule(method=MatchMethod.REGEX, expression=expression, absent_value=None)


def test_safe_patterns_are_accepted():
    assert rule().capture_group == 1


def test_matching_is_bounded_even_when_a_pattern_passes_the_probes():
    slow = flag_rule(method=MatchMethod.REGEX, expression=r"(x|xx)+y", absent_value=None)
    started = time.monotonic()
    with pytest.raises(ValueError, match="timed out"):
        matcher.matches(slow, "x" * 45)
    assert time.monotonic() - started < 2


def test_old_exponential_pattern_no_longer_blocks_the_matcher():
    legacy = flag_rule(method=MatchMethod.REGEX, expression=r"(a+)+$", absent_value=None)
    started = time.monotonic()
    try:
        matcher.matches(legacy, "a" * 5000 + "!")
    except ValueError:
        pass
    assert time.monotonic() - started < 2


def test_resolve_constant_and_capture():
    constant = flag_rule()
    assert matcher.resolve(constant, "set system services telnet") == matcher.Resolution(True, True)
    assert matcher.resolve(constant, "set system services ssh") == matcher.Resolution(False, None)
    capturing = rule()
    assert matcher.resolve(capturing, "set system ntp server 10.0.0.1") == matcher.Resolution(True, "10.0.0.1")
    assert matcher.resolve(capturing, "set system ntp peer 10.0.0.1") == matcher.Resolution(False, None)


def test_capture_requires_the_whole_line_to_match():
    assert matcher.resolve(rule(), "set system ntp server 10.0.0.1 prefer").matched is False


@pytest.mark.parametrize("captured", ["$6$abc$def123", "-----BEGIN KEY", "x" * 300])
def test_unsafe_captured_text_is_dropped_but_still_counts_as_a_match(captured):
    result = matcher.resolve(rule(expression=r"set system ntp server (.+)"), f"set system ntp server {captured}")
    assert result == matcher.Resolution(True, None)


@pytest.mark.parametrize("value", ["", "   ", None, 5, "a\x00b", "password hunter2"])
def test_clean_captured_value_rejects_unusable_text(value):
    assert clean_captured_value(value) is None


def test_clean_captured_value_normalizes_whitespace():
    assert clean_captured_value("  fw  1 ") == "fw 1"


def test_store_round_trip_keeps_the_new_fields(tmp_path):
    path = tmp_path / "rules.json"
    rules = (rule(), flag_rule())
    save_rules(path, rules)
    assert load_rules(path) == rules


def test_legacy_rule_files_without_the_new_fields_still_load(tmp_path):
    path = tmp_path / "rules.json"
    save_rules(path, (flag_rule(absent_value=None),))
    document = json.loads(path.read_text(encoding="utf-8"))
    for item in document["rules"]:
        item.pop("capture_group")
        item.pop("absent_value")
    path.write_text(json.dumps(document), encoding="utf-8")
    loaded = load_rules(path)
    assert loaded[0].capture_group is None
    assert loaded[0].absent_value is None


def test_store_rejects_bad_new_field_types(tmp_path):
    path = tmp_path / "rules.json"
    save_rules(path, (flag_rule(),))
    document = json.loads(path.read_text(encoding="utf-8"))
    document["rules"][0]["absent_value"] = "false"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError):
        load_rules(path)
