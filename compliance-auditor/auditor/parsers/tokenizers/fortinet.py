"""
FortiOS tokenizer for the compliance auditor.

FortiOS configuration structure is defined by the keywords ``config``,
``edit``, ``next`` and ``end``, not by indentation (exports are often
re-indented or flattened). This module converts FortiOS configuration text
into :class:`FortiToken` objects that are consumed by
``auditor/parsers/normalizer.py``. A quote-aware lexer is required because
values may be quoted, may contain spaces, ``#`` and escaped quotes, and may
span several physical lines (for example certificates and private keys).

Malformed input always raises :class:`FortiParseError` carrying the line
number. A compliance auditor that silently mis-parses a configuration could
report false compliance, so no error recovery is attempted.

Context rule:
    Every token (including blank lines, comments, ``next`` and ``end``)
    carries the block context that existed BEFORE its own stack effect is
    applied. ``path`` holds the labels of all open blocks, outermost first,
    and ``parent_line`` is the line of the innermost open block. A ``next``
    or ``end`` therefore still references the block it is about to close.

Known limitations:
    - Only the first error is reported.
    - Whitespace follows ``str.isspace()``, so an unquoted value containing
      a non-breaking space would be split; FortiOS quotes such values.
    - Unknown keywords are kept as ``FortiKind.OTHER`` without validation.
    - A quoted first word is treated exactly like an unquoted one.
    - CRLF and lone CR inside multi-line values are normalized to "\\n".

Example:
    >>> cfg = (
    ...     "config system global\\n"
    ...     "    set hostname \\"FW-HQ-01\\"\\n"
    ...     "end\\n"
    ...     "config firewall policy\\n"
    ...     "    edit 1\\n"
    ...     "        set name \\"allow web\\"\\n"
    ...     "    next\\n"
    ...     "end"
    ... )
    >>> tokens = tokenize_fortinet(cfg)
    >>> [(t.line_number, t.kind.value, t.parent_line) for t in tokens]
    [(1, 'config', None), (2, 'set', 1), (3, 'end', 1), (4, 'config', None), (5, 'edit', 4), (6, 'set', 5), (7, 'next', 5), (8, 'end', 4)]
    >>> tokens[5].path
    ('firewall policy', '1')
    >>> tokens[5].args
    ('name', 'allow web')
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "FortiKind",
    "FortiParseError",
    "SENSITIVE_KEYS",
    "FortiToken",
    "tokenize_fortinet",
]


class FortiKind(StrEnum):
    """FortiOS token kinds."""

    BLANK = "blank"
    COMMENT = "comment"
    CONFIG = "config"
    EDIT = "edit"
    SET = "set"
    UNSET = "unset"
    APPEND = "append"
    SELECT = "select"
    NEXT = "next"
    END = "end"
    OTHER = "other"


class FortiParseError(ValueError):
    """Raised for malformed FortiOS input.

    Attributes:
        line_number: One-based line number the error refers to.
    """

    def __init__(self, message: str, line_number: int) -> None:
        super().__init__(message)
        self.line_number = line_number


SENSITIVE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "psksecret",
        "psksecret-remote",
        "secret",
        "private-key",
        "auth-pwd",
        "priv-pwd",
        "md5-key",
    }
)


@dataclass(frozen=True, slots=True)
class FortiToken:
    """One logical FortiOS configuration line.

    Attributes:
        line_number: First physical line (1-based).
        end_line_number: Last physical line; greater than ``line_number``
            only for multi-line quoted values.
        raw: Original text of all physical lines, joined with "\\n".
        text: ``raw`` stripped of surrounding whitespace.
        kind: Token classification.
        keyword: First word ("" for blank and comment lines).
        args: Remaining words, unquoted and unescaped.
        path: Labels of the open blocks before this token, outermost first.
        parent_line: Line of the innermost open block, or None.
        sensitive: True for ``set``/``append`` of a key in SENSITIVE_KEYS.
        source_file: Optional source filename.
    """

    line_number: int
    end_line_number: int
    raw: str
    text: str
    kind: FortiKind
    keyword: str
    args: tuple[str, ...]
    path: tuple[str, ...]
    parent_line: int | None
    sensitive: bool = False
    source_file: str | None = None

    @property
    def depth(self) -> int:
        """Number of open blocks around this token."""
        return len(self.path)

    def __post_init__(self) -> None:
        if self.line_number < 1:
            raise ValueError("line_number must be >= 1")

        if self.end_line_number < self.line_number:
            raise ValueError("end_line_number must be >= line_number")

        if (self.parent_line is None) != (len(self.path) == 0):
            raise ValueError("parent_line/path relationship invalid")

        if self.parent_line is not None and self.parent_line >= self.line_number:
            raise ValueError("parent_line must be less than line_number")

        if self.kind in (FortiKind.BLANK, FortiKind.COMMENT):
            if self.keyword != "":
                raise ValueError("blank/comment keyword must be empty")
            if self.args != ():
                raise ValueError("blank/comment args must be empty")
        elif self.keyword == "":
            raise ValueError("keyword must not be empty")


@dataclass(slots=True)
class _Frame:
    """An open ``config`` or ``edit`` block."""

    keyword: str
    label: str
    line_number: int


_KEYWORD_MAP: dict[str, FortiKind] = {
    "config": FortiKind.CONFIG,
    "edit": FortiKind.EDIT,
    "set": FortiKind.SET,
    "unset": FortiKind.UNSET,
    "append": FortiKind.APPEND,
    "select": FortiKind.SELECT,
    "next": FortiKind.NEXT,
    "end": FortiKind.END,
}

_KEY_VALUE_KINDS = frozenset(
    {FortiKind.SET, FortiKind.UNSET, FortiKind.APPEND, FortiKind.SELECT}
)


def _make_token(
    *,
    line_number: int,
    end_line_number: int,
    raw: str,
    kind: FortiKind,
    keyword: str,
    args: tuple[str, ...],
    path: tuple[str, ...],
    parent_line: int | None,
    source_file: str | None,
) -> FortiToken:
    """Build a token, deriving ``text`` and ``sensitive``."""

    sensitive = (
        kind in (FortiKind.SET, FortiKind.APPEND)
        and len(args) >= 1
        and args[0] in SENSITIVE_KEYS
    )

    return FortiToken(
        line_number=line_number,
        end_line_number=end_line_number,
        raw=raw,
        text=raw.strip(),
        kind=kind,
        keyword=keyword,
        args=args,
        path=path,
        parent_line=parent_line,
        sensitive=sensitive,
        source_file=source_file,
    )


def _split_lines(content: str) -> list[str]:
    """Strip a BOM, normalize line endings and split on "\\n" only."""

    if content.startswith("\ufeff"):
        content = content[1:]

    content = content.replace("\r\n", "\n").replace("\r", "\n")
    lines = content.split("\n")

    # A trailing newline yields one empty final element; drop it.
    if lines[-1] == "":
        lines.pop()

    return lines


def _lex_logical_line(lines: list[str], start: int) -> tuple[list[str], int]:
    """Lex the logical line that begins at ``lines[start]``.

    State is carried across physical lines, so a multi-line quoted value is
    scanned exactly once.

    Args:
        lines: All physical lines.
        start: Index of the first physical line of the logical line.

    Returns:
        The words of the logical line and the index of its last physical
        line.

    Raises:
        FortiParseError: On text after a closing quote or an unterminated
            quoted value.
    """

    words: list[str] = []
    current: list[str] = []
    in_quote = False
    quote_start_line = 0
    index = start

    while True:
        line = lines[index]

        if not in_quote and '"' not in line:
            words.extend(line.split())
            return words, index

        pos = 0
        length = len(line)

        while pos < length:
            ch = line[pos]

            if in_quote:
                if ch == "\\" and pos + 1 < length:
                    nxt = line[pos + 1]
                    current.append(nxt if nxt in ('"', "\\") else ch + nxt)
                    pos += 2
                elif ch == '"':
                    in_quote = False
                    pos += 1
                    if pos < length and not line[pos].isspace():
                        raise FortiParseError(
                            "unexpected text after closing quote at line "
                            f"{index + 1}",
                            index + 1,
                        )
                    words.append("".join(current))
                    current.clear()
                else:
                    current.append(ch)
                    pos += 1
            elif ch.isspace():
                if current:
                    words.append("".join(current))
                    current.clear()
                pos += 1
            elif ch == '"' and not current:
                in_quote = True
                quote_start_line = index + 1
                pos += 1
            else:
                current.append(ch)
                pos += 1

        if in_quote:
            current.append("\n")
            index += 1
            if index >= len(lines):
                raise FortiParseError(
                    f"unterminated quoted value starting at line {quote_start_line}",
                    quote_start_line,
                )
            continue

        if current:
            words.append("".join(current))

        return words, index


def _apply_structure(
    kind: FortiKind,
    keyword: str,
    args: tuple[str, ...],
    line_number: int,
    stack: list[_Frame],
) -> None:
    """Validate a command against the block stack and update the stack.

    Checks run in order: arity, placement, matching.

    Raises:
        FortiParseError: If the command violates the FortiOS grammar.
    """

    if kind is FortiKind.CONFIG:
        if not args:
            raise FortiParseError(
                f"'config' at line {line_number} requires at least one argument",
                line_number,
            )
        stack.append(_Frame("config", " ".join(args), line_number))

    elif kind is FortiKind.EDIT:
        if len(args) != 1:
            raise FortiParseError(
                f"'edit' at line {line_number} requires exactly one argument",
                line_number,
            )
        if not stack or stack[-1].keyword != "config":
            raise FortiParseError(
                f"'edit' at line {line_number} must appear directly inside "
                "a 'config' block",
                line_number,
            )
        stack.append(_Frame("edit", args[0], line_number))

    elif kind in _KEY_VALUE_KINDS:
        if not args:
            raise FortiParseError(
                f"'{keyword}' at line {line_number} requires at least one argument",
                line_number,
            )
        if not stack:
            raise FortiParseError(
                f"'{keyword}' at line {line_number} must appear inside a "
                "'config' or 'edit' block",
                line_number,
            )

    elif kind is FortiKind.NEXT or kind is FortiKind.END:
        if args:
            raise FortiParseError(
                f"'{keyword}' at line {line_number} takes no arguments",
                line_number,
            )
        if not stack:
            raise FortiParseError(
                f"'{keyword}' at line {line_number} has no matching open block",
                line_number,
            )
        frame = stack[-1]
        expected = "edit" if kind is FortiKind.NEXT else "config"
        if frame.keyword != expected:
            raise FortiParseError(
                f"'{keyword}' at line {line_number} does not match "
                f"'{frame.keyword}' opened at line {frame.line_number}",
                line_number,
            )
        stack.pop()


def tokenize_fortinet(
    content: str,
    *,
    source_file: str | None = None,
) -> list[FortiToken]:
    """Tokenize FortiOS configuration text.

    Args:
        content: Full configuration text.
        source_file: Optional filename attached to every token.

    Returns:
        One FortiToken per logical line, in source order.

    Raises:
        TypeError: If ``content`` is not a str or ``source_file`` is neither
            a str nor None.
        FortiParseError: On malformed FortiOS input.
    """

    if not isinstance(content, str):
        raise TypeError(f"content must be a str, got {type(content).__name__}")

    if source_file is not None and not isinstance(source_file, str):
        raise TypeError("source_file must be a str or None")

    if content == "":
        return []

    lines = _split_lines(content)
    tokens: list[FortiToken] = []
    stack: list[_Frame] = []
    index = 0

    while index < len(lines):
        line_number = index + 1
        first = lines[index]

        # Context rule: capture the stack BEFORE this token's own effect.
        path = tuple(frame.label for frame in stack)
        parent_line = stack[-1].line_number if stack else None

        stripped = first.strip()

        if stripped == "" or stripped.startswith("#"):
            tokens.append(
                _make_token(
                    line_number=line_number,
                    end_line_number=line_number,
                    raw=first,
                    kind=FortiKind.BLANK if stripped == "" else FortiKind.COMMENT,
                    keyword="",
                    args=(),
                    path=path,
                    parent_line=parent_line,
                    source_file=source_file,
                )
            )
            index += 1
            continue

        words, last = _lex_logical_line(lines, index)

        if not words or words[0] == "":
            raise FortiParseError(
                f"empty keyword at line {line_number}", line_number
            )

        keyword = words[0]
        args = tuple(words[1:])
        kind = _KEYWORD_MAP.get(keyword, FortiKind.OTHER)

        _apply_structure(kind, keyword, args, line_number, stack)

        tokens.append(
            _make_token(
                line_number=line_number,
                end_line_number=last + 1,
                raw="\n".join(lines[index : last + 1]),
                kind=kind,
                keyword=keyword,
                args=args,
                path=path,
                parent_line=parent_line,
                source_file=source_file,
            )
        )
        index = last + 1

    if stack:
        parts = ", ".join(
            f"'{frame.keyword} {frame.label}' (line {frame.line_number})"
            for frame in stack
        )
        raise FortiParseError(
            f"unclosed block(s) at end of input: {parts}",
            stack[-1].line_number,
        )

    return tokens


if __name__ == "__main__":
    import doctest

    doctest.testmod()