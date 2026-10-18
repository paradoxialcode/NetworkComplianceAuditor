"""Tests for auditor.parsers.tokenizers.flat."""

from __future__ import annotations

import dataclasses
import random
import re
import time
from typing import Any

import pytest

from auditor.parsers.tokenizers.flat import (
    DEFAULT_PROFILE,
    DEFAULT_SENSITIVE_WORDS,
    FlatKind,
    FlatParseError,
    FlatProfile,
    FlatToken,
    tokenize_flat,
)

K = FlatKind

FIXTURE = r'''# exported 2026-10-17
set system host-name FW-1

set interfaces ge-0/0/0 description "uplink to core"
set system root-authentication encrypted-password "$6$abc"
set security policies from-zone trust to-zone untrust policy p1 match application any
delete interfaces ge-0/0/9
deactivate protocols ospf'''

# (line, kind, verb, args, sensitive)
EXPECTED: list[tuple[int, FlatKind, str, tuple[str, ...], bool]] = [
    (1, K.COMMENT, "", (), False),
    (2, K.COMMAND, "set", ("system", "host-name", "FW-1"), False),
    (3, K.BLANK, "", (), False),
    (4, K.COMMAND, "set", ("interfaces", "ge-0/0/0", "description", "uplink to core"), False),
    (5, K.COMMAND, "set", ("system", "root-authentication", "encrypted-password", "$6$abc"), True),
    (
        6,
        K.COMMAND,
        "set",
        (
            "security", "policies", "from-zone", "trust", "to-zone", "untrust",
            "policy", "p1", "match", "application", "any",
        ),
        False,
    ),
    (7, K.COMMAND, "delete", ("interfaces", "ge-0/0/9"), False),
    (8, K.COMMAND, "deactivate", ("protocols", "ospf"), False),
]


def one(line: str) -> FlatToken:
    (token,) = tokenize_flat(line)
    return token


def make_token(**overrides: Any) -> FlatToken:
    base: dict[str, Any] = {
        "line_number": 1,
        "raw": "set a b",
        "text": "set a b",
        "kind": K.COMMAND,
        "verb": "set",
        "args": ("a", "b"),
    }
    base.update(overrides)
    return FlatToken(**base)


# 1. Fixture -------------------------------------------------------------------
def test_fixture_table() -> None:
    tokens = tokenize_flat(FIXTURE)
    assert len(tokens) == len(EXPECTED) == 8
    for token, (line, kind, verb, args, sensitive) in zip(tokens, EXPECTED):
        assert (token.line_number, token.kind, token.verb, token.args, token.sensitive) == (
            line,
            kind,
            verb,
            args,
            sensitive,
        )


def test_raw_and_text_preservation() -> None:
    tokens = tokenize_flat(FIXTURE)
    assert tokens[4].raw == 'set system root-authentication encrypted-password "$6$abc"'
    assert tokens[0].raw == "# exported 2026-10-17"
    assert tokens[2].raw == ""

    token = one('\t  set a "b c"  ')
    assert token.raw == '\t  set a "b c"  '
    assert token.text == 'set a "b c"'
    assert token.args == ("a", "b c")


def test_words_property() -> None:
    tokens = tokenize_flat(FIXTURE)
    assert tokens[1].words == ("set", "system", "host-name", "FW-1")
    assert tokens[0].words == ()
    assert tokens[2].words == ()


def test_verb_is_not_normalized() -> None:
    assert one("SET a b").verb == "SET"
    assert one('"set" a').verb == "set"


# 2. Classification ------------------------------------------------------------
@pytest.mark.parametrize(
    ("line", "kind"),
    [
        ("", K.BLANK),
        ("   ", K.BLANK),
        ("\t \t", K.BLANK),
        ("# note", K.COMMENT),
        ("   # indented note", K.COMMENT),
        ("#", K.COMMENT),
        ("set a b", K.COMMAND),
        ("set a # not a comment", K.COMMAND),
        ('"# x" y', K.COMMAND),
    ],
)
def test_classification(line: str, kind: FlatKind) -> None:
    tokens = tokenize_flat(line + "\n")
    assert [t.kind for t in tokens] == [kind]


def test_comment_keeps_full_text() -> None:
    token = one("  ## SECRET-DATA password x")
    assert token.kind is K.COMMENT
    assert token.text == "## SECRET-DATA password x"
    assert token.verb == ""
    assert token.args == ()
    assert token.sensitive is False


def test_custom_comment_prefixes() -> None:
    profile = FlatProfile(("!", "//"), frozenset())
    kinds = [t.kind for t in tokenize_flat("! a\n// b\n# c\nset d", profile=profile)]
    assert kinds == [K.COMMENT, K.COMMENT, K.COMMAND, K.COMMAND]


def test_no_comment_prefixes() -> None:
    profile = FlatProfile((), frozenset())
    token = tokenize_flat("# looks like a comment", profile=profile)[0]
    assert token.kind is K.COMMAND
    assert (token.verb, token.args) == ("#", ("looks", "like", "a", "comment"))


# 3. Quotes and escapes --------------------------------------------------------
@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (r'set v "a b"', ("v", "a b")),
        (r"set v a b", ("v", "a", "b")),
        (r'set v ""', ("v", "")),
        (r'set v "a\"b"', ("v", 'a"b')),
        (r'set v "a\\b"', ("v", "a\\b")),
        (r'set v "a\db"', ("v", "a\\db")),
        (r"set v a\b", ("v", "a\\b")),
        (r"set v a#b", ("v", "a#b")),
        (r'set v "# x"', ("v", "# x")),
        (r'set v a"b', ("v", 'a"b')),
        (r'set v "a" "b"', ("v", "a", "b")),
        ('set   v\t"a b"\t x', ("v", "a b", "x")),
        (r'set v "a  b"', ("v", "a  b")),
        (r'set "my v" x', ("my v", "x")),
    ],
)
def test_quotes_and_escapes(line: str, expected: tuple[str, ...]) -> None:
    assert one(line).args == expected


def test_quoted_and_unquoted_are_identical() -> None:
    assert one('set v "abc"').args == one("set v abc").args


@pytest.mark.parametrize("char", ["\x0b", "\x0c", "\x1c", "\x85", "\u2028", "\u2029"])
def test_unusual_whitespace(char: str) -> None:
    inside = tokenize_flat(f'set v "x{char}y"\nset w 1\n')
    assert inside[0].args == ("v", f"x{char}y")
    assert inside[1].line_number == 2
    assert len(inside) == 2

    outside = tokenize_flat(f"set v x{char}y\nset w 1\n")
    assert outside[0].args == ("v", "x", "y")
    assert outside[1].line_number == 2
    assert len(outside) == 2


# 4. Errors --------------------------------------------------------------------
ERROR_CASES: list[tuple[str, str, int]] = [
    ('set v "abc', "unterminated quoted value at line 1", 1),
    ('set a b\nset v "abc\nset c d', "unterminated quoted value at line 2", 2),
    ('set v "abc\\', "unterminated quoted value at line 1", 1),
    ('set v "a\\"', "unterminated quoted value at line 1", 1),
    ('set v "a"b', "unexpected text after closing quote at line 1", 1),
    ('set a\nset v "a"b', "unexpected text after closing quote at line 2", 2),
    ('""', "empty verb at line 1", 1),
    ('"" x', "empty verb at line 1", 1),
    ('set a\n  "" x', "empty verb at line 2", 2),
    # first error wins
    ('set v "a"b\nset x "abc', "unexpected text after closing quote at line 1", 1),
    ('""\nset v "a', "empty verb at line 1", 1),
]


@pytest.mark.parametrize(("content", "message", "line"), ERROR_CASES)
def test_parse_errors(content: str, message: str, line: int) -> None:
    with pytest.raises(FlatParseError, match=f"^{re.escape(message)}$") as info:
        tokenize_flat(content)
    assert info.value.line_number == line


# 5. Input handling ------------------------------------------------------------
@pytest.mark.parametrize("newline", ["\r\n", "\r"])
def test_line_endings(newline: str) -> None:
    assert tokenize_flat(FIXTURE.replace("\n", newline)) == tokenize_flat(FIXTURE)


def test_trailing_newlines() -> None:
    base = tokenize_flat(FIXTURE)
    assert tokenize_flat(FIXTURE + "\n") == base
    extra = tokenize_flat(FIXTURE + "\n\n")
    assert len(extra) == len(base) + 1
    assert extra[-1].kind is K.BLANK
    assert extra[-1].line_number == 9


def test_single_newline_and_empty() -> None:
    assert [t.kind for t in tokenize_flat("\n")] == [K.BLANK]
    assert tokenize_flat("") == []


def test_bom() -> None:
    token = one("\ufeffset a b")
    assert token.raw == "set a b"
    assert token.verb == "set"
    assert one("set a x\ufeffy").args == ("a", "x\ufeffy")
    assert tokenize_flat("\ufeff") == []


def test_line_numbers_are_consecutive() -> None:
    tokens = tokenize_flat(FIXTURE)
    assert [t.line_number for t in tokens] == list(range(1, 9))


# 6. Sensitive heuristic -------------------------------------------------------
@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('set system root-authentication encrypted-password "$6$x"', True),
        ('set security ike policy P1 pre-shared-key ascii-text "k"', True),
        ("set protocols ospf area 0 interface ge-0/0/0 authentication md5 1 key k", False),
        ("set protocols bgp group g authentication-key abc", True),
        ("delete system root-authentication encrypted-password", False),
        ("set system login user bob class super-user", False),
        ("set system radius-server 10.0.0.1 secret abc", True),
        ("set system radius-server 10.0.0.1 secret", False),
        # Documented over-flagging: a user literally named "secret".
        ("set system login user secret class admin", True),
    ],
)
def test_sensitive_heuristic(line: str, expected: bool) -> None:
    assert one(line).sensitive is expected


def test_sensitive_never_alters_raw() -> None:
    line = 'set system root-authentication encrypted-password "$6$x"'
    assert one(line).raw == line


def test_custom_sensitive_words() -> None:
    profile = FlatProfile(("#",), frozenset({"community"}))
    assert tokenize_flat("set snmp community public", profile=profile)[0].sensitive
    assert not tokenize_flat("set a password b", profile=profile)[0].sensitive
    empty = FlatProfile(("#",), frozenset())
    assert not tokenize_flat("set a password b", profile=empty)[0].sensitive


def test_default_sensitive_words_is_frozenset() -> None:
    assert isinstance(DEFAULT_SENSITIVE_WORDS, frozenset)
    assert {"password", "encrypted-password", "secret", "pre-shared-key"} <= DEFAULT_SENSITIVE_WORDS


# 7. Profile validation --------------------------------------------------------
@pytest.mark.parametrize(
    ("args", "exc"),
    [
        ((["#"], frozenset()), TypeError),
        (("#", frozenset()), TypeError),
        (((1,), frozenset()), TypeError),
        ((("",), frozenset()), ValueError),
        ((("#",), {"a"}), TypeError),
        ((("#",), frozenset({1})), TypeError),
        ((("#",), frozenset({""})), ValueError),
    ],
)
def test_profile_validation(args: tuple[Any, ...], exc: type[Exception]) -> None:
    with pytest.raises(exc):
        FlatProfile(*args)


def test_default_profile() -> None:
    assert DEFAULT_PROFILE.comment_prefixes == ("#",)
    assert DEFAULT_PROFILE.sensitive_words == DEFAULT_SENSITIVE_WORDS


# 8. Token validation ----------------------------------------------------------
def test_baseline_token_is_valid() -> None:
    assert make_token().words == ("set", "a", "b")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"line_number": 0}, "line_number must be >= 1"),
        ({"verb": ""}, "command verb must not be empty"),
        ({"kind": K.BLANK, "text": "", "verb": "x", "args": ()}, "blank/comment verb must be empty"),
        ({"kind": K.COMMENT, "verb": "", "args": ("a",)}, "blank/comment args must be empty"),
        (
            {"kind": K.COMMENT, "verb": "", "args": (), "sensitive": True},
            "blank/comment cannot be sensitive",
        ),
        ({"kind": K.BLANK, "verb": "", "args": (), "text": "x"}, "blank text must be empty"),
    ],
)
def test_token_validation(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=re.escape(message)):
        make_token(**overrides)


def test_token_is_frozen_and_hashable() -> None:
    token = make_token()
    with pytest.raises(dataclasses.FrozenInstanceError):
        token.text = "other"  # type: ignore[misc]
    assert isinstance(hash(token), int)


# 9. API validation ------------------------------------------------------------
@pytest.mark.parametrize("bad", [None, b"set a b", 123, ["set a b"]])
def test_non_str_content(bad: object) -> None:
    with pytest.raises(TypeError, match="content must be a str"):
        tokenize_flat(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [123, b"f.cfg", ["f.cfg"]])
def test_bad_source_file(bad: object) -> None:
    with pytest.raises(TypeError, match="source_file must be a str or None"):
        tokenize_flat("set a b", source_file=bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [None, "default", ("#",)])
def test_bad_profile(bad: object) -> None:
    with pytest.raises(TypeError, match="profile must be a FlatProfile"):
        tokenize_flat("set a b", profile=bad)  # type: ignore[arg-type]


def test_validation_applies_to_empty_content() -> None:
    with pytest.raises(TypeError):
        tokenize_flat("", source_file=1)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        tokenize_flat("", profile="x")  # type: ignore[arg-type]


def test_source_file_propagation() -> None:
    tokens = tokenize_flat(FIXTURE, source_file="srx.set")
    assert {t.source_file for t in tokens} == {"srx.set"}
    assert {t.source_file for t in tokenize_flat(FIXTURE)} == {None}


# 10. Enum and exception -------------------------------------------------------
def test_enum_and_exception_behaviour() -> None:
    assert str(FlatKind.COMMAND) == "command"
    assert f"{FlatKind.BLANK}" == "blank"
    assert FlatKind.COMMENT == "comment"  # type: ignore[comparison-overlap]
    assert issubclass(FlatParseError, ValueError)
    assert FlatParseError("m", 4).line_number == 4


# 11. Property and fuzz tests --------------------------------------------------
def test_fuzz_only_raises_parse_errors_and_round_trips() -> None:
    rng = random.Random(4321)
    pieces = [
        "set", "delete", "x", "1", '"', "\\", "#", " ", "\t", "\n", "\n",
        "\r\n", "\u2028", "\x0c", "password", "secret",
    ]
    parsed = 0
    for _ in range(3000):
        content = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 40)))
        try:
            tokens = tokenize_flat(content)
        except FlatParseError:
            continue
        parsed += 1
        assert [t.line_number for t in tokens] == list(range(1, len(tokens) + 1))
        if tokens:
            rebuilt = "\n".join(t.raw for t in tokens) + "\n"
            assert tokenize_flat(rebuilt) == tokens
    assert parsed > 0


# 12. Performance guards -------------------------------------------------------
# Regression guards against accidental O(n^2) behaviour, NOT benchmarks.
def test_large_config_is_fast() -> None:
    content = "".join(
        f'set interfaces ge-0/0/{i} description "d{i}"\n' for i in range(200_000)
    )
    start = time.perf_counter()
    tokens = tokenize_flat(content)
    assert time.perf_counter() - start < 10
    assert len(tokens) == 200_000


def test_very_long_quoted_value_is_fast() -> None:
    content = 'set v "' + "a" * 1_000_000 + '"'
    start = time.perf_counter()
    token = one(content)
    assert time.perf_counter() - start < 10
    assert len(token.args[1]) == 1_000_000