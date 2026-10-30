import time

import pytest

from auditor import regex_safety
from auditor.regex_safety import UnsafePatternError, compile_pattern, fullmatch, search


@pytest.fixture(autouse=True)
def fresh_cache():
    compile_pattern.cache_clear()
    yield
    compile_pattern.cache_clear()


@pytest.mark.parametrize(
    "pattern",
    [r"^aes(128|256)", r"\d+", r"ntp\s+server\s+\S+", r"^(?:no\s+)?ip\s+http", r"[A-Za-z0-9._-]+"],
)
def test_ordinary_patterns_are_accepted(pattern):
    assert compile_pattern(pattern) is not None


@pytest.mark.parametrize("pattern", [r"(a|aa)+$", r"(a|a)+$", r"^(a|aa)+$"])
def test_catastrophic_patterns_are_rejected(pattern):
    start = time.time()
    with pytest.raises(UnsafePatternError):
        compile_pattern(pattern)
    assert time.time() - start < 1.0


def test_unsafe_pattern_error_is_a_value_error():
    assert issubclass(UnsafePatternError, ValueError)


@pytest.mark.parametrize("pattern", ["(unclosed", "[a-", "*abc"])
def test_invalid_patterns_raise_value_error(pattern):
    with pytest.raises(ValueError) as info:
        compile_pattern(pattern)
    assert not isinstance(info.value, UnsafePatternError)


def test_non_string_pattern_is_a_type_error():
    with pytest.raises(TypeError):
        compile_pattern(5)


def test_search_and_fullmatch_semantics():
    assert search(r"aes(128|256)", "cipher aes256-cbc") is True
    assert search(r"^aes", "cipher aes256") is False
    assert fullmatch(r"ntp server \S+", "ntp server 10.0.0.1") is True
    assert fullmatch(r"ntp server", "ntp server 10.0.0.1") is False


def test_runtime_timeout_stops_a_slow_match(monkeypatch):
    monkeypatch.setattr(regex_safety, "_PROBES", ())
    start = time.time()
    with pytest.raises(TimeoutError):
        search(r"(a|aa)+$", "a" * 60 + "!")
    assert time.time() - start < 1.0


def test_results_are_cached_after_success():
    first = compile_pattern(r"\d+")
    assert compile_pattern(r"\d+") is first
