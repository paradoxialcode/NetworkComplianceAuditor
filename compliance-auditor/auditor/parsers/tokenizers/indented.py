"""
Line tokenizer for indentation-based network configurations.
 
This tokenizer converts configuration text into a sequence of ConfigToken
objects while preserving original line content for evidence tracking. The
resulting tokens are intended to feed into auditor/parsers/normalizer.py
for construction of normalized security baseline models.
 
Known limitations:
    Multiline blocks (for example banners, certificates, and similar
    constructs) are not specially handled and are tokenized line by line.
 
Example:
    >>> tokens = tokenize_indented(
    ...     "hostname Router1\\n!\\n interface GigabitEthernet0/0\\n  shutdown"
    ... )
    >>> for t in tokens:
    ...     print(t)
    ConfigToken(line_number=1, raw='hostname Router1', text='hostname Router1', indent=0, kind=<TokenKind.COMMAND: 'command'>, source_file=None, parent_line=None)
    ConfigToken(line_number=2, raw='!', text='!', indent=0, kind=<TokenKind.SEPARATOR: 'separator'>, source_file=None, parent_line=None)
    ConfigToken(line_number=3, raw=' interface GigabitEthernet0/0', text='interface GigabitEthernet0/0', indent=1, kind=<TokenKind.COMMAND: 'command'>, source_file=None, parent_line=None)
    ConfigToken(line_number=4, raw='  shutdown', text='shutdown', indent=2, kind=<TokenKind.COMMAND: 'command'>, source_file=None, parent_line=3)
"""
 
from __future__ import annotations
 
from dataclasses import dataclass
from enum import StrEnum
 
__all__ = [
    "TokenKind",
    "TokenizerProfile",
    "CISCO_PROFILE",
    "HUAWEI_PROFILE",
    "ConfigToken",
    "tokenize_indented",
]
 
 
class TokenKind(StrEnum):
    """Supported token classifications."""
 
    BLANK = "blank"
    SEPARATOR = "separator"
    COMMENT = "comment"
    COMMAND = "command"
 
 
@dataclass(frozen=True, slots=True)
class ConfigToken:
    """Represents a single configuration line.
 
    Attributes:
        line_number: One-based line number in the source content.
        raw: Original line text without a line ending (whitespace and tabs
            preserved).
        text: Trimmed form of ``raw``.
        indent: Leading indentation width in columns (tabs expanded).
        kind: Classified token type.
        source_file: Optional source filename.
        parent_line: Line number of the enclosing command, if any.
    """
 
    line_number: int
    raw: str
    text: str
    indent: int
    kind: TokenKind
    source_file: str | None = None
    parent_line: int | None = None
 
    def __post_init__(self) -> None:
        if self.line_number < 1:
            raise ValueError("line_number must be greater than or equal to 1")
 
        if self.indent < 0:
            raise ValueError("indent cannot be negative")
 
 
@dataclass(frozen=True, slots=True)
class TokenizerProfile:
    """Tokenizer behavior profile.
 
    Attributes:
        separator: Exact trimmed text that marks a separator line, or None
            to disable separators.
        comment_prefixes: Prefixes that mark a comment line.
        separator_resets_hierarchy: Whether a separator clears hierarchy
            state.
    """
 
    separator: str | None
    comment_prefixes: tuple[str, ...]
    separator_resets_hierarchy: bool
 
    def __post_init__(self) -> None:
        if self.separator is not None:
            if not isinstance(self.separator, str):
                raise TypeError("separator must be a str or None")
            if self.separator == "":
                raise ValueError("separator must not be empty")
 
        if not isinstance(self.comment_prefixes, tuple):
            raise TypeError("comment_prefixes must be a tuple of str")
        for prefix in self.comment_prefixes:
            if not isinstance(prefix, str):
                raise TypeError("comment_prefixes must contain only str")
            if prefix == "":
                raise ValueError("comment_prefixes must not contain empty strings")
 
        if not isinstance(self.separator_resets_hierarchy, bool):
            raise TypeError("separator_resets_hierarchy must be a bool")
 
 
CISCO_PROFILE = TokenizerProfile(
    separator="!",
    comment_prefixes=("!",),
    separator_resets_hierarchy=True,
)
 
HUAWEI_PROFILE = TokenizerProfile(
    separator="#",
    comment_prefixes=(),
    separator_resets_hierarchy=True,
)
 
 
def _classify(text: str, profile: TokenizerProfile) -> TokenKind:
    """Classify a trimmed line."""
 
    if text == "":
        return TokenKind.BLANK
 
    if profile.separator is not None and text == profile.separator:
        return TokenKind.SEPARATOR
 
    for prefix in profile.comment_prefixes:
        if text.startswith(prefix):
            return TokenKind.COMMENT
 
    return TokenKind.COMMAND
 
 
def tokenize_indented(
    content: str,
    *,
    source_file: str | None = None,
    tab_size: int = 4,
    profile: TokenizerProfile = CISCO_PROFILE,
) -> list[ConfigToken]:
    """Tokenize indentation-based configuration text.
 
    Args:
        content: Full configuration text.
        source_file: Optional source filename attached to every token.
        tab_size: Tab stop width used when expanding tab characters.
        profile: Tokenizer behavior profile.
 
    Returns:
        List of ConfigToken objects in source order.
 
    Raises:
        TypeError: If content, source_file, or profile have invalid types.
        ValueError: If tab_size is not a positive integer.
    """
 
    if not isinstance(content, str):
        raise TypeError(f"content must be a str, got {type(content).__name__}")
 
    if source_file is not None and not isinstance(source_file, str):
        raise TypeError("source_file must be a str or None")
 
    if isinstance(tab_size, bool) or not isinstance(tab_size, int):
        raise ValueError("tab_size must be a positive integer")
 
    if tab_size < 1:
        raise ValueError("tab_size must be greater than 0")
 
    if not isinstance(profile, TokenizerProfile):
        raise TypeError("profile must be a TokenizerProfile")
 
    if content == "":
        return []
 
    if content.startswith("\ufeff"):
        content = content[1:]
 
    content = content.replace("\r\n", "\n").replace("\r", "\n")
 
    lines = content.split("\n")
 
    # A trailing newline yields one empty final element; drop it.
    if lines[-1] == "":
        lines.pop()
 
    tokens: list[ConfigToken] = []
    indent_stack: list[tuple[int, int]] = []
 
    for line_number, raw in enumerate(lines, start=1):
        text = raw.strip()
 
        expanded = raw.expandtabs(tab_size) if "\t" in raw else raw
        indent = len(expanded) - len(expanded.lstrip(" "))
 
        kind = _classify(text, profile)
 
        parent_line: int | None = None
 
        if kind is TokenKind.COMMAND:
            while indent_stack and indent_stack[-1][0] >= indent:
                indent_stack.pop()
 
            if indent_stack:
                parent_line = indent_stack[-1][1]
 
            indent_stack.append((indent, line_number))
 
        elif kind is TokenKind.SEPARATOR and profile.separator_resets_hierarchy:
            indent_stack.clear()
 
        tokens.append(
            ConfigToken(
                line_number=line_number,
                raw=raw,
                text=text,
                indent=indent,
                kind=kind,
                source_file=source_file,
                parent_line=parent_line,
            )
        )
 
    return tokens
 
 
if __name__ == "__main__":
    import doctest
 
    doctest.testmod()