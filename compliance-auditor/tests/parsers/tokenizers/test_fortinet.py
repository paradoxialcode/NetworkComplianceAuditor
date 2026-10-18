"""Tests for auditor.parsers.tokenizers.fortinet."""

from __future__ import annotations

import dataclasses
import random
import re
import time
from typing import Any

import pytest

from auditor.parsers.tokenizers.fortinet import (
    SENSITIVE_KEYS,
    FortiKind,
    FortiParseError,
    FortiToken,
    tokenize_fortinet,
)

K = FortiKind

FIXTURE_A = r'''#config-version=FGT60F-7.2.5-FW-build1517-230606:opmode=0:vdom=0:user=admin
config system global
    set hostname "FW-HQ-01"
end
config system admin
    edit "admin"
        set password ENC SH2abc==
        set comments "uses # and \"quotes\""
    next
end
config firewall policy
    edit 1
        set name "allow web"
        set srcaddr "net-a" "net-b"

    next
end'''

# (line, kind, path, parent_line, args)
EXPECTED_A: list[tuple[int, FortiKind, tuple[str, ...], int | None, tuple[str, ...]]] = [
    (1, K.COMMENT, (), None, ()),
    (2, K.CONFIG, (), None, ("system", "global")),
    (3, K.SET, ("system global",), 2, ("hostname", "FW-HQ-01")),
    (4, K.END, ("system global",), 2, ()),
    (5, K.CONFIG, (), None, ("system", "admin")),
    (6, K.EDIT, ("system admin",), 5, ("admin",)),
    (7, K.SET, ("system admin", "admin"), 6, ("password", "ENC", "SH2abc==")),
    (8, K.SET, ("system admin", "admin"), 6, ("comments", 'uses # and "quotes"')),
    (9, K.NEXT, ("system admin", "admin"), 6, ()),
    (10, K.END, ("system admin",), 5, ()),
    (11, K.CONFIG, (), None, ("firewall", "policy")),
    (12, K.EDIT, ("firewall policy",), 11, ("1",)),
    (13, K.SET, ("firewall policy", "1"), 12, ("name", "allow web")),
    (14, K.SET, ("firewall policy", "1"), 12, ("srcaddr", "net-a", "net-b")),
    (15, K.BLANK, ("firewall policy", "1"), 12, ()),
    (16, K.NEXT, ("firewall policy", "1"), 12, ()),
    (17, K.END, ("firewall policy",), 11, ()),
]

CERT_VALUE = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDxTCCAq2gAwIBAgIBADANBgkq\n"
    "-----END CERTIFICATE-----\n"
)

FIXTURE_CERT = (
    "config vpn certificate local\n"
    '    edit "Fortinet_Factory"\n'
    '        set certificate "-----BEGIN CERTIFICATE-----\n'
    "MIIDxTCCAq2gAwIBAgIBADANBgkq\n"
    "-----END CERTIFICATE-----\n"
    '"\n'
    "    next\n"
    "end\n"
)


def sig(t: FortiToken) -> tuple[Any, ...]:
    return (
        t.line_number,
        t.end_line_number,
        t.kind,
        t.keyword,
        t.args,
        t.path,
        t.parent_line,
        t.sensitive,
    )


def make_token(**overrides: Any) -> FortiToken:
    base: dict[str, Any] = {
        "line_number": 2,
        "end_line_number": 2,
        "raw": "set a b",
        "text": "set a b",
        "kind": K.SET,
        "keyword": "set",
        "args": ("a", "b"),
        "path": ("x",),
        "parent_line": 1,
    }
    base.update(overrides)
    return FortiToken(**base)


def wrap(line: str) -> str:
    return "config t\n" + line + "\nend"


def set_token(content: str) -> FortiToken:
    return next(t for t in tokenize_fortinet(content) if t.kind is K.SET)


# 1. Fixture A -----------------------------------------------------------------
def test_fixture_a_full_table() -> None:
    tokens = tokenize_fortinet(FIXTURE_A)
    assert len(tokens) == len(EXPECTED_A) == 17
    for token, (line, kind, path, parent, args) in zip(tokens, EXPECTED_A):
        assert (token.line_number, token.kind, token.path, token.parent_line, token.args) == (
            line,
            kind,
            path,
            parent,
            args,
        )
        assert token.end_line_number == token.line_number
        assert token.depth == len(token.path)


def test_fixture_a_sensitive_and_raw() -> None:
    tokens = tokenize_fortinet(FIXTURE_A)
    assert [t.line_number for t in tokens if t.sensitive] == [7]
    assert tokens[6].raw == "        set password ENC SH2abc=="
    assert tokens[0].raw == FIXTURE_A.split("\n")[0]
    assert tokens[2].text == 'set hostname "FW-HQ-01"'


# 2. Quotes and escapes --------------------------------------------------------
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
    ],
)
def test_quotes_and_escapes(line: str, expected: tuple[str, ...]) -> None:
    assert set_token(wrap(line)).args == expected


def test_quoted_and_unquoted_forms_are_identical() -> None:
    assert set_token(wrap('set v "abc"')).args == set_token(wrap("set v abc")).args


def test_text_after_closing_quote_raises() -> None:
    with pytest.raises(FortiParseError, match="unexpected text after closing quote"):
        tokenize_fortinet(wrap('set v "a"b'))


# 3. Multi-line values ---------------------------------------------------------
def test_certificate_is_one_token() -> None:
    tokens = tokenize_fortinet(FIXTURE_CERT)
    assert len(tokens) == 5  # config, edit, set (lines 3-6), next, end
    cert = tokens[2]
    assert (cert.line_number, cert.end_line_number) == (3, 6)
    assert cert.args == ("certificate", CERT_VALUE)
    assert cert.raw == "\n".join(FIXTURE_CERT.split("\n")[2:6])
    assert cert.raw.startswith("        set certificate")
    assert tokens[3].line_number == 7
    assert tokens[3].kind is K.NEXT
    assert tokens[2].path == ("vpn certificate local", "Fortinet_Factory")


def test_hash_line_inside_quote_is_content() -> None:
    tokens = tokenize_fortinet('config t\nset v "a\n# not a comment\nb"\nend')
    assert [t.kind for t in tokens] == [K.CONFIG, K.SET, K.END]
    assert tokens[1].args == ("v", "a\n# not a comment\nb")
    assert tokens[1].end_line_number == 4
    assert tokens[2].line_number == 5


def test_trailing_backslash_inside_quote_is_kept() -> None:
    token = set_token('config t\nset v "a\\\nb"\nend')
    assert token.args == ("v", "a\\\nb")


def test_blank_line_inside_quote_is_preserved() -> None:
    token = set_token('config t\nset v "a\n\nb"\nend')
    assert token.args == ("v", "a\n\nb")


@pytest.mark.parametrize("newline", ["\r\n", "\r"])
def test_certificate_with_other_line_endings(newline: str) -> None:
    converted = FIXTURE_CERT.replace("\n", newline)
    assert tokenize_fortinet(converted) == tokenize_fortinet(FIXTURE_CERT)


# 4. Structure -----------------------------------------------------------------
def test_nested_vdom_structure() -> None:
    content = "\n".join(
        [
            "config vdom",
            "edit root",
            "config system interface",
            'edit "port1"',
            "set ip 10.0.0.1 255.255.255.0",
            "next",
            "end",
            "next",
            "end",
        ]
    )
    got = [(t.line_number, t.path, t.parent_line) for t in tokenize_fortinet(content)]
    assert got == [
        (1, (), None),
        (2, ("vdom",), 1),
        (3, ("vdom", "root"), 2),
        (4, ("vdom", "root", "system interface"), 3),
        (5, ("vdom", "root", "system interface", "port1"), 4),
        (6, ("vdom", "root", "system interface", "port1"), 4),
        (7, ("vdom", "root", "system interface"), 3),
        (8, ("vdom", "root"), 2),
        (9, ("vdom",), 1),
    ]


def test_empty_config_block() -> None:
    tokens = tokenize_fortinet("config x\nend")
    assert [t.kind for t in tokens] == [K.CONFIG, K.END]
    assert tokens[1].path == ("x",)
    assert tokens[1].parent_line == 1


def test_sibling_edits_share_parent() -> None:
    tokens = tokenize_fortinet("config a\nedit 1\nnext\nedit 2\nnext\nend")
    edits = [t for t in tokens if t.kind is K.EDIT]
    assert [t.parent_line for t in edits] == [1, 1]
    assert [t.args for t in edits] == [("1",), ("2",)]


def test_config_directly_inside_config() -> None:
    tokens = tokenize_fortinet("config a\nconfig b\nend\nend")
    assert tokens[1].path == ("a",)
    assert tokens[2].path == ("a", "b")


def test_config_inside_edit() -> None:
    tokens = tokenize_fortinet("config a\nedit 1\nconfig b\nend\nnext\nend")
    assert tokens[2].path == ("a", "1")
    assert tokens[2].parent_line == 2


def test_consecutive_top_level_configs() -> None:
    tokens = tokenize_fortinet("config a\nend\nconfig b\nend")
    assert [t.parent_line for t in tokens] == [None, 1, None, 3]


@pytest.mark.parametrize("keyword", ["purge", "rename", "unselect"])
def test_unknown_keywords_are_other(keyword: str) -> None:
    tokens = tokenize_fortinet(f"{keyword} x to y\nconfig a\nedit 1\n{keyword} z\nnext\nend")
    others = [t for t in tokens if t.kind is K.OTHER]
    assert [(t.keyword, t.line_number) for t in others] == [(keyword, 1), (keyword, 4)]
    assert others[0].args == ("x", "to", "y")
    assert others[0].path == ()
    assert others[1].path == ("a", "1")
    assert len(tokens) == 6  # no stack effect, nothing dropped


# 5. Errors --------------------------------------------------------------------
ERROR_CASES: list[tuple[str, str, int]] = [
    # E1 arity
    ("config\nend", "'config' at line 1 requires at least one argument", 1),
    ("config a\nedit\nnext\nend", "'edit' at line 2 requires exactly one argument", 2),
    ("config a\nedit 1 2\nnext\nend", "'edit' at line 2 requires exactly one argument", 2),
    ("config a\nset\nend", "'set' at line 2 requires at least one argument", 2),
    ("config a\nunset\nend", "'unset' at line 2 requires at least one argument", 2),
    ("config a\nend x", "'end' at line 2 takes no arguments", 2),
    ("config a\nedit 1\nnext x\nend", "'next' at line 3 takes no arguments", 3),
    # E2 edit placement
    ("edit 1", "'edit' at line 1 must appear directly inside a 'config' block", 1),
    ("config a\nedit 1\nedit 2", "'edit' at line 3 must appear directly inside a 'config' block", 3),
    # E3 set placement
    ("set x 1", "'set' at line 1 must appear inside a 'config' or 'edit' block", 1),
    ("append x 1", "'append' at line 1 must appear inside a 'config' or 'edit' block", 1),
    ("select x", "'select' at line 1 must appear inside a 'config' or 'edit' block", 1),
    # E4 no open block
    ("end", "'end' at line 1 has no matching open block", 1),
    ("next", "'next' at line 1 has no matching open block", 1),
    # E5 mismatch
    ("config a\nedit 1\nend", "'end' at line 3 does not match 'edit' opened at line 2", 3),
    ("config a\nnext", "'next' at line 2 does not match 'config' opened at line 1", 2),
    # E6 text after quote
    ('config a\nset v "a"b\nend', "unexpected text after closing quote at line 2", 2),
    # E7 unterminated quote
    ('config a\nset v "abc\nend', "unterminated quoted value starting at line 2", 2),
    ('config a\nset v "abc\ndef\nghi', "unterminated quoted value starting at line 2", 2),
    # E8 unclosed blocks
    (
        "config firewall policy\nedit 1\n set x 1",
        "unclosed block(s) at end of input: 'config firewall policy' (line 1), 'edit 1' (line 2)",
        2,
    ),
    ("config a", "unclosed block(s) at end of input: 'config a' (line 1)", 1),
    # E9 empty keyword
    ('config a\n""\nend', "empty keyword at line 2", 2),
    ('config a\n"" x\nend', "empty keyword at line 2", 2),
    # first error wins
    ('config a\nset v "x"y\nend\nend\nend', "unexpected text after closing quote at line 2", 2),
    ('end\nset v "a', "'end' at line 1 has no matching open block", 1),
]


@pytest.mark.parametrize(("content", "message", "line"), ERROR_CASES)
def test_parse_errors(content: str, message: str, line: int) -> None:
    with pytest.raises(FortiParseError, match=f"^{re.escape(message)}$") as info:
        tokenize_fortinet(content)
    assert info.value.line_number == line


# 6. Indentation independence --------------------------------------------------
def reindent(text: str, style: str, rng: random.Random) -> str:
    out: list[str] = []
    for line in text.split("\n"):
        body = line.lstrip()
        if style == "none":
            prefix = ""
        elif style == "tabs":
            prefix = "\t" * rng.randint(0, 3)
        else:
            prefix = "".join(rng.choice(" \t") for _ in range(rng.randint(0, 8)))
        out.append(prefix + body)
    return "\n".join(out)


@pytest.mark.parametrize("style", ["none", "tabs", "mixed"])
def test_indentation_independence(style: str) -> None:
    rng = random.Random(20240601)
    baseline = [sig(t) for t in tokenize_fortinet(FIXTURE_A)]
    for _ in range(10):
        variant = reindent(FIXTURE_A, style, rng)
        assert [sig(t) for t in tokenize_fortinet(variant)] == baseline


# 7. Input handling ------------------------------------------------------------
@pytest.mark.parametrize("newline", ["\r\n", "\r"])
def test_fixture_a_other_line_endings(newline: str) -> None:
    converted = FIXTURE_A.replace("\n", newline)
    assert tokenize_fortinet(converted) == tokenize_fortinet(FIXTURE_A)


def test_trailing_newlines() -> None:
    base = tokenize_fortinet(FIXTURE_A)
    assert tokenize_fortinet(FIXTURE_A + "\n") == base
    extra = tokenize_fortinet(FIXTURE_A + "\n\n")
    assert len(extra) == len(base) + 1
    assert extra[-1].kind is K.BLANK
    assert extra[-1].line_number == 18


def test_single_newline_and_empty() -> None:
    assert [t.kind for t in tokenize_fortinet("\n")] == [K.BLANK]
    assert tokenize_fortinet("") == []


def test_bom_handling() -> None:
    tokens = tokenize_fortinet("\ufeffconfig a\nend")
    assert tokens[0].raw == "config a"
    assert tokens[0].text == "config a"
    mid = set_token("config a\nset v x\ufeffy\nend")
    assert mid.args == ("v", "x\ufeffy")
    assert tokenize_fortinet("\ufeff") == []


UNUSUAL = ["\x0b", "\x0c", "\x1c", "\x85", "\u2028", "\u2029"]


@pytest.mark.parametrize("char", UNUSUAL)
def test_unusual_whitespace_inside_quotes(char: str) -> None:
    tokens = tokenize_fortinet(f'config a\nset v "x{char}y"\nend\n')
    assert len(tokens) == 3
    assert tokens[1].args == ("v", f"x{char}y")
    assert tokens[2].line_number == 3


@pytest.mark.parametrize("char", UNUSUAL)
def test_unusual_whitespace_outside_quotes(char: str) -> None:
    tokens = tokenize_fortinet(f"config a\nset v x{char}y\nend\n")
    assert len(tokens) == 3
    assert tokens[1].args == ("v", "x", "y")
    assert tokens[2].line_number == 3


# 8. Comments and blanks -------------------------------------------------------
def test_comment_and_blank_tokens() -> None:
    header = tokenize_fortinet(FIXTURE_A)[0]
    assert header.kind is K.COMMENT
    assert header.keyword == ""
    assert header.args == ()

    tokens = tokenize_fortinet("config a\n  # note\n\nend")
    assert tokens[1].kind is K.COMMENT
    assert tokens[2].kind is K.BLANK
    for t in tokens[1:3]:
        assert t.path == ("a",)
        assert t.parent_line == 1


# 9. Invariants ----------------------------------------------------------------
@pytest.mark.parametrize("content", [FIXTURE_A, FIXTURE_CERT])
def test_invariants(content: str) -> None:
    tokens = tokenize_fortinet(content)
    by_line = {t.line_number: t for t in tokens}
    previous = 0
    for t in tokens:
        assert t.line_number > previous
        assert t.end_line_number >= t.line_number
        assert t.depth == len(t.path)
        previous = t.end_line_number
        if t.parent_line is not None:
            assert t.parent_line < t.line_number
            assert by_line[t.parent_line].kind in (K.CONFIG, K.EDIT)
        if t.kind is K.NEXT:
            assert t.parent_line is not None
            assert by_line[t.parent_line].kind is K.EDIT
        if t.kind is K.END:
            assert t.parent_line is not None
            assert by_line[t.parent_line].kind is K.CONFIG


def test_fuzz_only_raises_parse_errors() -> None:
    rng = random.Random(1234)
    pieces = [
        "config", "edit", "set", "unset", "next", "end", "x", "1",
        '"', "\\", "#", " ", "\t", "\n", "\n", "\r\n", "\u2028",
    ]
    parsed = 0
    for _ in range(3000):
        content = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 40)))
        try:
            tokens = tokenize_fortinet(content)
        except FortiParseError:
            continue
        parsed += 1
        kinds = [t.kind for t in tokens]
        assert kinds.count(K.CONFIG) == kinds.count(K.END)
        assert kinds.count(K.EDIT) == kinds.count(K.NEXT)
    assert parsed > 0


# 10. Token validation ---------------------------------------------------------
def test_baseline_token_is_valid() -> None:
    assert make_token().depth == 1


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"line_number": 0, "parent_line": None, "path": ()}, "line_number must be >= 1"),
        ({"end_line_number": 1}, "end_line_number must be >= line_number"),
        ({"parent_line": None}, "parent_line/path relationship invalid"),
        ({"path": ()}, "parent_line/path relationship invalid"),
        ({"parent_line": 2}, "parent_line must be less than line_number"),
        ({"kind": K.BLANK, "keyword": "x", "args": ()}, "blank/comment keyword must be empty"),
        ({"kind": K.COMMENT, "keyword": "", "args": ("a",)}, "blank/comment args must be empty"),
        ({"keyword": ""}, "keyword must not be empty"),
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


# 11. API validation -----------------------------------------------------------
@pytest.mark.parametrize("bad", [None, b"config a", 123, ["config a"]])
def test_non_str_content(bad: object) -> None:
    with pytest.raises(TypeError, match="content must be a str"):
        tokenize_fortinet(bad)  # type: ignore[arg-type]


@pytest.mark.parametrize("bad", [123, b"f.cfg", ["f.cfg"]])
def test_bad_source_file(bad: object) -> None:
    with pytest.raises(TypeError, match="source_file must be a str or None"):
        tokenize_fortinet("config a\nend", source_file=bad)  # type: ignore[arg-type]


def test_validation_applies_to_empty_content() -> None:
    with pytest.raises(TypeError):
        tokenize_fortinet("", source_file=1)  # type: ignore[arg-type]


def test_source_file_propagation() -> None:
    tokens = tokenize_fortinet(FIXTURE_A, source_file="fw.conf")
    assert {t.source_file for t in tokens} == {"fw.conf"}
    assert {t.source_file for t in tokenize_fortinet(FIXTURE_A)} == {None}


# 12. Enum and exception -------------------------------------------------------
def test_enum_and_exception_behaviour() -> None:
    assert str(FortiKind.SET) == "set"
    assert f"{FortiKind.END}" == "end"
    assert FortiKind.SET == "set"  # type: ignore[comparison-overlap]
    assert issubclass(FortiParseError, ValueError)
    assert FortiParseError("m", 3).line_number == 3
    assert isinstance(SENSITIVE_KEYS, frozenset)
    assert {"password", "psksecret"} <= SENSITIVE_KEYS


def test_sensitive_only_for_set_and_append() -> None:
    tokens = tokenize_fortinet(
        "config a\nset password x\nappend secret y\nunset password\nset name z\nend"
    )
    assert [t.sensitive for t in tokens] == [False, True, True, False, False, False]


# 13. Performance guard --------------------------------------------------------
# Regression guard against accidental O(n^2) behaviour, NOT a benchmark.
def test_large_config_is_fast() -> None:
    body = "".join(
        f'edit {i}\n set name "p{i}"\n set srcaddr "a" "b"\nnext\n' for i in range(25000)
    )
    content = "config firewall policy\n" + body + "end\n"
    start = time.perf_counter()
    tokens = tokenize_fortinet(content)
    assert time.perf_counter() - start < 10
    assert len(tokens) == 100002


def test_huge_multiline_value_is_fast() -> None:
    content = 'config a\nedit 1\nset c "' + "x\n" * 50000 + '"\nnext\nend'
    start = time.perf_counter()
    tokens = tokenize_fortinet(content)
    assert time.perf_counter() - start < 10
    assert len(tokens) == 5
    # The first "x" shares line 3 with `set c "`; the closing quote is line 50003.
    assert tokens[2].end_line_number == 50003