"""Bounded exception diagnostics; this metadata never grants action authority."""
from __future__ import annotations

from itertools import islice

MAX_METADATA_ENTRIES = 64
UNKNOWN_NOTE = 'PUBLICATION_CUSTODY_UNKNOWN: denial restoration was not verified; inspection required.'


def metadata_snapshot(error: BaseException) -> tuple | None:
    """Copy bounded base storage before validation; never consult its live map again.

    Tuple entries retain object references without invoking their hash/equality or
    formatting hooks. A concurrent map change may refuse the observation. This is
    a bounded diagnostic observation, not a fence against arbitrary Python writers.
    """
    try:
        values = BaseException.__dict__['__dict__'].__get__(error, BaseException)
        return tuple(islice(dict.items(values), MAX_METADATA_ENTRIES + 1))
    except BaseException:
        return None


def mark_publication_unknown(error: BaseException) -> None:
    """Install a fresh plain namespace through the actual native storage slot.

    Safe bounded string-keyed attributes remain. Malformed/unreadable namespaces
    receive only the fixed diagnostic marker. Valid BaseException instances accept
    a plain dictionary here regardless of subtype properties or __setattr__.
    Catastrophic allocation/runtime failure has no annotation guarantee.
    """
    entries = metadata_snapshot(error)
    safe = (entries is not None and len(entries) <= MAX_METADATA_ENTRIES
            and all(type(key) is str for key, value in entries))
    values = {key: value for key, value in entries} if safe else {}
    notes = dict.get(values, '__notes__')
    # Exact list slicing and scalar checks never consult virtual notes methods.
    notes = notes[:MAX_METADATA_ENTRIES] if type(notes) is list else []
    values['__notes__'] = [note for note in notes if type(note) is str] + [UNKNOWN_NOTE]
    values['publication_state'] = 'unknown'
    BaseException.__dict__['__dict__'].__set__(error, values)
