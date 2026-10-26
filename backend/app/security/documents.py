"""Shared filesystem guards used before authorization and again at read time."""

import stat
from os import stat_result
from pathlib import Path

from app.security.policies import PUBLIC_DOCUMENTS


class DocumentDenied(Exception):
    pass


def checked_document(root: Path, filename: str) -> tuple[Path, stat_result]:
    if filename not in PUBLIC_DOCUMENTS:
        raise DocumentDenied()
    candidate = root / filename
    try:
        if root.resolve(strict=True) != root or candidate.resolve(strict=True).parent != root:
            raise DocumentDenied()
        before = candidate.lstat()
        if (not stat.S_ISREG(before.st_mode) or candidate.is_symlink()
                or getattr(before, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 1024)
                or getattr(before, "st_nlink", 1) != 1):
            raise DocumentDenied()
    except (OSError, RuntimeError):
        raise DocumentDenied() from None
    return candidate, before
