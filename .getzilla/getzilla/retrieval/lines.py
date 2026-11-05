"""Original byte-line convention shared by extraction, hashes and packing.

Unicode separators inside UTF-8 literals are content, not source line breaks.
Keep terminators and all original bytes, as in the published extraction profile.
"""


def physical_lines(data: bytes) -> tuple[bytes, ...]:
    return tuple(data.splitlines(keepends=True))
