"""Free text that people send us, checked once, the same way, before it reaches the database or the log.

PostgreSQL refuses U+0000 in `text`; the other C0 controls are legal but have no business in a message,
a title or a note. One rule for every field (XE-0080): tab, newline and carriage return pass, nothing else
below U+0020, and U+007F (DEL) is out too. Lone surrogates (U+D800..U+DFFF, which JSON `\\ud800` decodes
to) are not UTF-8 and fail at the database driver, so they are refused here as well (XE-0878). Format
characters are refused too (XE-1099): the bidi controls reorder what a reader sees, and the rest of
category Cf is invisible; the only ones that carry meaning in ordinary text are the joiners (ZWJ, ZWNJ,
which emoji and some scripts need) and the emoji variation selectors. The Unicode line and paragraph
separators are line breaks and are stored as such.

What is refused is what draws nothing, whatever category Unicode files it under (XE-14692). Category Cf
is most of it and not all: the combining grapheme joiner and the Mongolian variation selectors are marks,
the Hangul fillers are letters, the other variation selectors are marks too, and the braille blank is a
symbol. Two titles that differ only by one of these read the same and are not the same, which is what the
rule is for. Unicode keeps its own list of them (Default_Ignorable_Code_Point), and `_INVISIBLE` is that
list outside Cf, with the braille blank and two that draw nothing by their own definition. Spaces are not
on the list. A no-break or an ideographic space is a space, and looks like one.

Some of them do draw, by changing what stands beside them, and those pass where they have something to
act on and nowhere else (`_acts`): the two joiners, the emoji selectors, the Mongolian selectors, the
ideographic selectors and the braille blank. A joiner at the end of a Latin title, between two Latin
letters or beside another joiner joins nothing; a selector after a letter it has no form for selects
nothing; each draws nothing there, like the rest. What each needs:

  an emoji selector    the symbol before it (or a digit it makes a keycap of)
  a Mongolian selector the Mongolian letter before it
  an ideographic one   the ideograph before it
  a joiner             something drawn before it, and a letter, mark or symbol outside ASCII on one side
                       (Persian writes one after a Latin word and before a full stop, and Malayalam ends a
                       word with one, so both sides are not asked for)
  the braille blank    a braille cell on one side: it is the space of braille text

That is read from each neighbour's category and block and no further. Which scripts join is not looked
up, nor which symbols have a second form, so a joiner beside a Cyrillic letter and a selector after a
symbol with one form still pass. The other variation selectors (1 to 14) are refused everywhere: the
sequences that use them are rare, and nothing here can tell one from padding.

A payload field that the code is about to treat as a string goes through `field_text` first (XE-0966,
XE-1010): a list where a hash was expected is a 400 that names the field, not an AttributeError.
"""

from __future__ import annotations

import unicodedata

from fastapi import HTTPException

_ALLOWED_CONTROL = {"\t", "\n", "\r"}
_JOINERS = {"\u200c", "\u200d"}                               # ZWNJ, ZWJ
_SELECTORS = {"\ufe0e", "\ufe0f"}                             # VS15, VS16: the text and the emoji form
_ALLOWED_FORMAT = _JOINERS | _SELECTORS
_MONGOLIAN_SELECTORS = {"\u180b", "\u180c", "\u180d", "\u180f"}
_BRAILLE_BLANK = "\u2800"
_KEYCAP_BASES = frozenset("0123456789#*")
_KEYCAP = "\u20e3"
# Default_Ignorable_Code_Point where the category is not Cf (DerivedCoreProperties.txt), and U+2800
_INVISIBLE = frozenset((
    0x034F,                           # combining grapheme joiner
    0x115F, 0x1160, 0x3164, 0xFFA0,   # Hangul fillers
    0x17B4, 0x17B5,                   # Khmer inherent vowels
    0x180B, 0x180C, 0x180D, 0x180F,   # Mongolian free variation selectors (in context, below)
    0x2065,                           # reserved, among the invisible operators
    0x2800,                           # braille pattern blank (in context, below)
    0x16FE4, 0x1D159,                 # Khitan small script filler, musical null notehead: nothing, by definition
    *range(0xFE00, 0xFE10),           # variation selectors 1 to 16 (15 and 16 in context, below)
    *range(0xFFF0, 0xFFF9),           # reserved, before the interlinear annotation controls
    *range(0xE0000, 0xE1000),         # tags and variation selectors 17 to 256 (those in context, below), and the reserved range around them
))
_LINE_SEPARATORS = {"\u2028": "\n", "\u2029": "\n"}


def _ideographic_selector(c: str) -> bool:
    return 0xE0100 <= ord(c) <= 0xE01EF


def _in_context(c: str) -> bool:
    """One that passes only where it acts on what is beside it (`_acts`)."""
    return c in _ALLOWED_FORMAT or c in _MONGOLIAN_SELECTORS or c == _BRAILLE_BLANK or _ideographic_selector(c)


def _bad(c: str) -> bool:
    """Refused wherever it stands."""
    o = ord(c)
    if o < 0x20:
        return c not in _ALLOWED_CONTROL
    if o == 0x7F or 0x80 <= o <= 0x9F or 0xD800 <= o <= 0xDFFF:   # DEL, the C1 controls (XE-1688), surrogates
        return True
    if o < 0xAD or _in_context(c):
        return False
    return o in _INVISIBLE or unicodedata.category(c) == "Cf"


def _drawn(c: str) -> bool:
    """A character that is there and draws something of its own: not a space or a break, not one refused, not one
    that only acts on its neighbour."""
    return bool(c) and not c.isspace() and not _in_context(c) and not _bad(c)


def _joins(c: str) -> bool:
    return _drawn(c) and not c.isascii() and unicodedata.category(c)[0] in "LMS"


def _within(c: str, *ranges: tuple[int, int]) -> bool:
    return bool(c) and any(low <= ord(c) <= high for low, high in ranges)


def _acts(s: str, i: int) -> bool:
    """Whether the joiner, the selector or the blank at `i` has something to act on (see the module's note)."""
    c = s[i]
    before = s[i - 1] if i else ""
    after = s[i + 1] if i + 1 < len(s) else ""
    if c in _SELECTORS:
        if before in _KEYCAP_BASES:
            return after == _KEYCAP
        # the symbols with a text and an emoji form are symbols and punctuation, and the one letter U+2139
        return _drawn(before) and not before.isascii() and (unicodedata.category(before)[0] in "SP" or before == "\u2139")
    if c in _MONGOLIAN_SELECTORS:
        return _within(before, (0x1800, 0x18AF)) and unicodedata.category(before)[0] == "L"
    if _ideographic_selector(c):
        return _within(before, (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xF900, 0xFAFF), (0x20000, 0x323AF))
    if c == _BRAILLE_BLANK:
        return _within(before, (0x2801, 0x28FF)) or _within(after, (0x2801, 0x28FF))
    if before == "\ufe0f":           # an emoji in its emoji form, joined to the next
        return _joins(after)
    return _drawn(before) and (_joins(before) or _joins(after))


def _refused(s: str, i: int) -> bool:
    return _bad(s[i]) or (_in_context(s[i]) and not _acts(s, i))


def has_bad_control(s: str) -> bool:
    return any(_refused(s, i) for i in range(len(s)))


def _lines(s: str) -> str:
    return s.translate({ord(k): v for k, v in _LINE_SEPARATORS.items()})


def clean_text(value, field: str, *, max_len: int, required: bool = True, max_bytes: int | None = None) -> str:
    """Strip, bound, and refuse control characters. Raises 400 with the field named."""
    s = (value or "")
    if not isinstance(s, str):
        raise HTTPException(400, f"{field} must be a string")
    s = _lines(s).strip()
    if required and not s:
        raise HTTPException(400, f"{field} is required (max {max_len} chars)")
    if len(s) > max_len:
        raise HTTPException(400, f"{field} is too long (max {max_len} chars)")
    if has_bad_control(s):
        raise HTTPException(400, f"{field} contains a control or format character that is not allowed")
    if max_bytes is not None and len(s.encode("utf-8")) > max_bytes:
        raise HTTPException(400, f"{field} is too long (max {max_bytes} bytes)")
    return s


def field_text(payload: dict, field: str, *, max_len: int = 256) -> str:
    """A payload field the code will compare, lower-case or look up: a string, bounded, controls refused;
    absent is the empty string. Anything else is a 400 naming the field, never a type error later."""
    value = payload.get(field)
    if value is None:
        return ""
    if not isinstance(value, str):
        raise HTTPException(400, f"{field} must be a string")
    if len(value) > max_len:
        raise HTTPException(400, f"{field} is too long (max {max_len} chars)")
    if has_bad_control(value):
        raise HTTPException(400, f"{field} contains a control or format character that is not allowed")
    return value


def scrub(s: str) -> str:
    """For text we did not ask for and cannot refuse (a signed chat envelope): make it storable, visibly."""
    s = _lines(s)
    return "".join("\ufffd" if _refused(s, i) else c for i, c in enumerate(s))
