"""Tests for auditor.parsers.tokenizers.indented."""
 
from __future__ import annotations
 
import dataclasses
 
import pytest
 
from auditor.parsers.tokenizers.indented import (
    CISCO_PROFILE,
    HUAWEI_PROFILE,
    ConfigToken,
    TokenKind,
    TokenizerProfile,
    tokenize_indented,
)
 
C = TokenKind
 
 
def kinds(tokens: list[ConfigToken]) -> list[TokenKind]:
    return [t.kind for t in tokens]
 
 
def parents(tokens: list[ConfigToken]) -> list[int | None]:
    return [t.parent_line for t in tokens]
 
 
# 1. Documented example ------------------------------------------------------
def test_documented_example() -> None:
    tokens = tokenize_indented(
        "hostname Router1\n!\n interface GigabitEthernet0/0\n  shutdown"
    )
    assert kinds(tokens) == [C.COMMAND, C.SEPARATOR, C.COMMAND, C.COMMAND]
    assert [t.indent for t in tokens] == [0, 0, 1, 2]
    assert [t.line_number for t in tokens] == [1, 2, 3, 4]
    assert parents(tokens) == [None, None, None, 3]
    assert tokens[2].raw == " interface GigabitEthernet0/0"
    assert tokens[2].text == "interface GigabitEthernet0/0"
 
 
# 2. Blank/comment lines do not break hierarchy -------------------------------
def test_blank_and_comment_do_not_break_block() -> None:
    content = "interface Gi0/0\n description x\n\n! note\n shutdown"
    tokens = tokenize_indented(content)
    assert kinds(tokens) == [C.COMMAND, C.COMMAND, C.BLANK, C.COMMENT, C.COMMAND]
    assert parents(tokens) == [None, 1, None, None, 1]
 
 
# 3. Separator clears hierarchy ----------------------------------------------
def test_separator_clears_hierarchy() -> None:
    tokens = tokenize_indented("interface Gi0/0\n!\n shutdown")
    assert tokens[1].kind is C.SEPARATOR
    assert tokens[2].parent_line is None
 
 
def test_separator_without_reset_keeps_hierarchy() -> None:
    profile = TokenizerProfile("!", ("!",), separator_resets_hierarchy=False)
    tokens = tokenize_indented("interface Gi0/0\n!\n shutdown", profile=profile)
    assert tokens[2].parent_line == 1
 
 
def test_nested_hierarchy_and_dedent() -> None:
    content = "a\n b\n  c\n d\ne"
    assert parents(tokenize_indented(content)) == [None, 1, 2, 1, None]
 
 
# 4. Tabs ---------------------------------------------------------------------
@pytest.mark.parametrize(
    ("raw", "tab_size", "expected"),
    [
        ("\tshutdown", 4, 4),
        ("\tshutdown", 8, 8),
        ("\t  shutdown", 4, 6),
        (" \tshutdown", 4, 4),  # space then tab lands on next tab stop
        ("    shutdown", 4, 4),
    ],
)
def test_tab_indentation(raw: str, tab_size: int, expected: int) -> None:
    (token,) = tokenize_indented(raw, tab_size=tab_size)
    assert token.indent == expected
    assert token.raw == raw  # tabs preserved in raw
 
 
def test_tab_and_space_children_share_parent() -> None:
    tokens = tokenize_indented("interface Gi0/0\n\tshutdown\n    no ip address")
    assert parents(tokens) == [None, 1, 1]
 
 
# 5. Line endings -------------------------------------------------------------
def test_line_endings_and_trailing_newline() -> None:
    tokens = tokenize_indented("a\r\nb\rc\nd\n")
    assert [t.raw for t in tokens] == ["a", "b", "c", "d"]
    assert [t.line_number for t in tokens] == [1, 2, 3, 4]
 
 
def test_only_one_trailing_empty_line_is_dropped() -> None:
    tokens = tokenize_indented("a\n\n")
    assert kinds(tokens) == [C.COMMAND, C.BLANK]
 
 
def test_single_newline_is_one_blank_token() -> None:
    assert kinds(tokenize_indented("\n")) == [C.BLANK]
 
 
@pytest.mark.parametrize("sep", ["\x0c", "\x0b", "\x1c", "\x85", "\u2028", "\u2029"])
def test_unusual_separators_do_not_split_lines(sep: str) -> None:
    tokens = tokenize_indented(f"a{sep}b")
    assert len(tokens) == 1
    assert tokens[0].raw == f"a{sep}b"
 
 
# 6. BOM ----------------------------------------------------------------------
def test_bom_is_removed() -> None:
    (token,) = tokenize_indented("\ufeffhostname R1")
    assert token.raw == "hostname R1"
    assert token.text == "hostname R1"
 
 
# 7. Empty / whitespace -------------------------------------------------------
def test_empty_string() -> None:
    assert tokenize_indented("") == []
 
 
def test_whitespace_only_line_is_blank_with_indent() -> None:
    tokens = tokenize_indented("a\n   ")
    assert tokens[1].kind is C.BLANK
    assert tokens[1].indent == 3
    assert tokens[1].raw == "   "
    assert tokens[1].text == ""
 
 
# 8. Profiles -----------------------------------------------------------------
@pytest.mark.parametrize(
    ("profile", "line", "expected"),
    [
        (CISCO_PROFILE, "!", C.SEPARATOR),
        (CISCO_PROFILE, "  !  ", C.SEPARATOR),
        (CISCO_PROFILE, "! note", C.COMMENT),
        (CISCO_PROFILE, "#", C.COMMAND),
        (HUAWEI_PROFILE, "#", C.SEPARATOR),
        (HUAWEI_PROFILE, "! note", C.COMMAND),
        (HUAWEI_PROFILE, "# note", C.COMMAND),
    ],
)
def test_profile_classification(
    profile: TokenizerProfile, line: str, expected: TokenKind
) -> None:
    (token,) = tokenize_indented(line, profile=profile)
    assert token.kind is expected
 
 
def test_profile_without_separator() -> None:
    profile = TokenizerProfile(None, ("#",), False)
    (token,) = tokenize_indented("#", profile=profile)
    assert token.kind is C.COMMENT
 
 
# 9. Validation ---------------------------------------------------------------
@pytest.mark.parametrize("bad", [None, b"hostname", 123, ["a"]])
def test_non_str_content(bad: object) -> None:
    with pytest.raises(TypeError, match="content must be a str"):
        tokenize_indented(bad)  # type: ignore[arg-type]
 
 
@pytest.mark.parametrize("bad", [0, -1, True, "4", 4.0])
def test_bad_tab_size(bad: object) -> None:
    with pytest.raises(ValueError):
        tokenize_indented("a", tab_size=bad)  # type: ignore[arg-type]
 
 
def test_bad_source_file() -> None:
    with pytest.raises(TypeError):
        tokenize_indented("a", source_file=123)  # type: ignore[arg-type]
 
 
def test_bad_profile() -> None:
    with pytest.raises(TypeError):
        tokenize_indented("a", profile="cisco")  # type: ignore[arg-type]
 
 
def test_validation_happens_even_for_empty_content() -> None:
    with pytest.raises(ValueError):
        tokenize_indented("", tab_size=0)
 
 
# TokenizerProfile validation -------------------------------------------------
@pytest.mark.parametrize(
    ("args", "exc"),
    [
        ((None, ("",), True), ValueError),
        (("", ("!",), True), ValueError),
        ((1, ("!",), True), TypeError),
        (("!", "!", True), TypeError),  # bare str instead of tuple
        (("!", (1,), True), TypeError),
        (("!", ("!",), 1), TypeError),
    ],
)
def test_profile_validation(args: tuple[object, ...], exc: type[Exception]) -> None:
    with pytest.raises(exc):
        TokenizerProfile(*args)  # type: ignore[arg-type]
 
 
# 10. Immutability and token validation --------------------------------------
def test_token_is_frozen() -> None:
    (token,) = tokenize_indented("a")
    with pytest.raises(dataclasses.FrozenInstanceError):
        token.text = "b"  # type: ignore[misc]
 
 
@pytest.mark.parametrize(("line_number", "indent"), [(0, 0), (-1, 0), (1, -1)])
def test_token_post_init_rejects_bad_values(line_number: int, indent: int) -> None:
    with pytest.raises(ValueError):
        ConfigToken(line_number, "a", "a", indent, C.COMMAND)
 
 
# 11. source_file -------------------------------------------------------------
def test_source_file_propagated() -> None:
    tokens = tokenize_indented("a\n\n! c", source_file="r1.cfg")
    assert {t.source_file for t in tokens} == {"r1.cfg"}
 
 
def test_source_file_default_none() -> None:
    assert tokenize_indented("a")[0].source_file is None
 
 
# 12. StrEnum -----------------------------------------------------------------
def test_token_kind_str() -> None:
    assert str(TokenKind.COMMAND) == "command"
    assert f"{TokenKind.BLANK}" == "blank"
    assert TokenKind.COMMENT == "comment"