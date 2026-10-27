"""
Tokenizer for flat, one-command-per-line network configurations.

Flat formats (Junos ``display set``, PAN-OS and VyOS set mode, and similar)
have no blocks and no meaningful indentation: every line is a complete
command whose hierarchy is carried by its own words, for example
``set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24``. This
module converts such text into :class:`FlatToken` objects for
``auditor/parsers/normalizer.py``. Original lines are preserved in ``raw`` so
findings can cite exact evidence.

Values may be double-quoted (to contain spaces or ``#``) with ``\\"`` and
``\\\\`` escapes. Malformed input always raises :class:`FlatParseError` with
the line number; a compliance auditor that silently mis-parses a line could
report false compliance, so no error recovery is attempted.

Known limitations:
    - Each command must fit on one physical line; a quoted value cannot span
      lines, and an unterminated quote is an error.
    - Only a line that STARTS with a comment prefix is a comment. A ``#``
      later in a line is ordinary content (flat formats have no inline
      comments).
    - The verb is the first word, kept exactly as written; verbs are not
      validated or case-folded.
    - A quoted first word is treated exactly like an unquoted one.
    - ``sensitive`` is a heuristic: a configured word followed by at least
      one more argument marks the line sensitive. It can over-flag, for
      example a user literally named ``secret``, and never alters ``raw``.
    - Whitespace follows ``str.isspace()``. Only the first error is reported.

Example:
    >>> cfg = (
    ...     "# exported config\\n"
    ...     "set system host-name FW-1\\n"
    ...     "\\n"
    ...     "set interfaces ge-0/0/0 description \\"uplink to core\\"\\n"
    ...     "set system root-authentication encrypted-password \\"$6$abc\\""
    ... )
    >>> tokens = tokenize_flat(cfg)
    >>> [(t.line_number, t.kind.value, t.verb) for t in tokens]
    [(1, 'comment', ''), (2, 'command', 'set'), (3, 'blank', ''), (4, 'command', 'set'), (5, 'command', 'set')]
    >>> tokens[3].args
    ('interfaces', 'ge-0/0/0', 'description', 'uplink to core')
    >>> tokens[4].sensitive
    True
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = [
    "FlatKind",
    "FlatParseError",
    "FlatProfile",
    "DEFAULT_SENSITIVE_WORDS",
    "DEFAULT_PROFILE",
    "FlatToken",
    "tokenize_flat",
]


class FlatKind(StrEnum):
    """Flat-config token kinds."""

    BLANK = "blank"
    COMMENT = "comment"
    COMMAND = "command"


class FlatParseError(ValueError):
    """Raised for malformed flat-config input.

    Attributes:
        line_number: One-based line number the error refers to.
    """

    def __init__(self, message: str, line_number: int) -> None:
        super().__init__(message)
        self.line_number = line_number


DEFAULT_SENSITIVE_WORDS: frozenset[str] = frozenset(
    {
        "password",
        "encrypted-password",
        "authentication-password",
        "privacy-password",
        "secret",
        "pre-shared-key",
        "authentication-key",
        "private-key",
        "md5-key",
    }
)


@dataclass(frozen=True, slots=True)
class FlatProfile:
    """Tokenizer behavior profile.

    Attributes:
        comment_prefixes: A line whose trimmed text starts with any of these
            is a comment. May be empty.
        sensitive_words: Words that introduce a secret value.
    """

    comment_prefixes: tuple[str, ...]
    sensitive_words: frozenset[str]

    def __post_init__(self) -> None:
        if not isinstance(self.comment_prefixes, tuple):
            raise TypeError("comment_prefixes must be a tuple of str")
        for prefix in self.comment_prefixes:
            if not isinstance(prefix, str):
                raise TypeError("comment_prefixes must contain only str")
            if prefix == "":
                raise ValueError("comment_prefixes must not contain empty strings")

        if not isinstance(self.sensitive_words, frozenset):
            raise TypeError("sensitive_words must be a frozenset of str")
        for word in self.sensitive_words:
            if not isinstance(word, str):
                raise TypeError("sensitive_words must contain only str")
            if word == "":
                raise ValueError("sensitive_words must not contain empty strings")


DEFAULT_PROFILE = FlatProfile(
    comment_prefixes=("#",),
    sensitive_words=DEFAULT_SENSITIVE_WORDS,
)


@dataclass(frozen=True, slots=True)
class FlatToken:
    """One physical line of a flat configuration.

    Attributes:
        line_number: One-based line number.
        raw: Original line text without a line ending (whitespace preserved).
        text: ``raw`` stripped of surrounding whitespace.
        kind: Token classification.
        verb: First word of a command ("" for blank and comment lines).
        args: Remaining words, unquoted and unescaped.
        sensitive: True if the command appears to carry a secret value.
        source_file: Optional source filename.
    """

    line_number: int
    raw: str
    text: str
    kind: FlatKind
    verb: str
    args: tuple[str, ...]
    sensitive: bool = False
    source_file: str | None = None

    @property
    def words(self) -> tuple[str, ...]:
        """Verb followed by arguments; empty for blank and comment lines."""
        return (self.verb, *self.args) if self.verb else ()

    def __post_init__(self) -> None:
        if self.line_number < 1:
            raise ValueError("line_number must be >= 1")

        if self.kind is FlatKind.COMMAND:
            if self.verb == "":
                raise ValueError("command verb must not be empty")
            return

        if self.verb != "":
            raise ValueError("blank/comment verb must be empty")
        if self.args != ():
            raise ValueError("blank/comment args must be empty")
        if self.sensitive:
            raise ValueError("blank/comment cannot be sensitive")
        if self.kind is FlatKind.BLANK and self.text != "":
            raise ValueError("blank text must be empty")


def _split_lines(content: str) -> list[str]:
    """Strip a BOM, normalize line endings and split on "\\n" only.

    ``str.splitlines()`` is avoided because it also splits on ``\\x0b``,
    ``\\x0c``, ``\\x85``, ``\\u2028`` and ``\\u2029``, which would corrupt
    line numbers.
    """

    if content.startswith("\ufeff"):
        content = content[1:]

    content = content.replace("\r\n", "\n").replace("\r", "\n")
    lines = content.split("\n")

    # A trailing newline yields one empty final element; drop it.
    if lines[-1] == "":
        lines.pop()

    return lines


def _lex_line(line: str, line_number: int) -> list[str]:
    """Split one line into words, honoring double quotes.

    Outside quotes whitespace separates words and a ``"`` that starts a word
    opens a quoted value (``""`` yields an empty word). A ``"`` in the middle
    of a word is literal. Inside quotes ``\\"`` and ``\\\\`` are unescaped and
    any other backslash sequence is kept verbatim.

    Raises:
        FlatParseError: On text after a closing quote or an unterminated
            quote.
    """

    if '"' not in line:
        return line.split()

    words: list[str] = []
    current: list[str] = []
    in_quote = False
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
                    raise FlatParseError(
                        f"unexpected text after closing quote at line {line_number}",
                        line_number,
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
            pos += 1
        else:
            current.append(ch)
            pos += 1

    if in_quote:
        raise FlatParseError(
            f"unterminated quoted value at line {line_number}", line_number
        )

    if current:
        words.append("".join(current))

    return words


def _is_sensitive(args: tuple[str, ...], profile: FlatProfile) -> bool:
    """True if a sensitive word is followed by at least one more argument."""

    return any(word in profile.sensitive_words for word in args[:-1])


def tokenize_flat(
    content: str,
    *,
    source_file: str | None = None,
    profile: FlatProfile = DEFAULT_PROFILE,
) -> list[FlatToken]:
    """Tokenize flat, one-command-per-line configuration text.

    Args:
        content: Full configuration text.
        source_file: Optional filename attached to every token.
        profile: Comment and sensitive-word behavior.

    Returns:
        One FlatToken per physical line, in source order.

    Raises:
        TypeError: If ``content`` is not a str, ``source_file`` is neither a
            str nor None, or ``profile`` is not a FlatProfile.
        FlatParseError: On an unterminated quote, text after a closing
            quote, or an empty verb.
    """

    if not isinstance(content, str):
        raise TypeError(f"content must be a str, got {type(content).__name__}")

    if source_file is not None and not isinstance(source_file, str):
        raise TypeError("source_file must be a str or None")

    if not isinstance(profile, FlatProfile):
        raise TypeError("profile must be a FlatProfile")

    if content == "":
        return []

    tokens: list[FlatToken] = []

    for line_number, raw in enumerate(_split_lines(content), start=1):
        text = raw.strip()

        if text == "":
            kind = FlatKind.BLANK
        elif text.startswith(profile.comment_prefixes):
            kind = FlatKind.COMMENT
        else:
            kind = FlatKind.COMMAND

        if kind is not FlatKind.COMMAND:
            tokens.append(
                FlatToken(
                    line_number=line_number,
                    raw=raw,
                    text=text,
                    kind=kind,
                    verb="",
                    args=(),
                    source_file=source_file,
                )
            )
            continue

        words = _lex_line(raw, line_number)

        if not words or words[0] == "":
            raise FlatParseError(f"empty verb at line {line_number}", line_number)

        args = tuple(words[1:])
        tokens.append(
            FlatToken(
                line_number=line_number,
                raw=raw,
                text=text,
                kind=kind,
                verb=words[0],
                args=args,
                sensitive=_is_sensitive(args, profile),
                source_file=source_file,
            )
        )

    return tokens


if __name__ == "__main__":
    import doctest

    doctest.testmod()