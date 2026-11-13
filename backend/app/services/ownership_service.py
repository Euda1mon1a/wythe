"""Bounded source reads for an explicitly selected ownership hypothesis."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path, PurePosixPath

from app.adapters.python_ownership import inspect_ownership_source
from app.schemas.security import OwnershipReport

MAX_SOURCE_BYTES = 1_048_576


def read_ownership_source(root: Path, relative: str) -> bytes:
    """Read one regular Python file; no traversal, symlinks, imports, or recursive discovery.

    Descriptor-relative opens keep a swapped parent symlink from escaping the chosen root.
    Fail closed on platforms without these filesystem primitives.
    """
    path = PurePosixPath(relative)
    if (path.is_absolute() or ".." in path.parts or "\\" in relative
            or path.suffix != ".py" or "\x00" in relative):
        raise ValueError("Source must be a root-relative .py path without traversal")
    if os.open not in os.supports_dir_fd or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Ownership source reads require descriptor-relative, no-symlink OS support")
    directory = os.open(root.expanduser().resolve(strict=True), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory,
        )
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SOURCE_BYTES:
                raise ValueError("Source must be a regular file of at most 1 MiB")
            data = stream.read(MAX_SOURCE_BYTES + 1)
            if len(data) > MAX_SOURCE_BYTES:
                raise ValueError("Source exceeds 1 MiB")
            return data
    finally:
        os.close(directory)


def inspect_record_ownership(
    root: Path, *, handler: str, record: str, principal: str, owner_field: str,
) -> OwnershipReport:
    relative, separator, function = handler.rpartition(":")
    if not separator or not relative or not function:
        raise ValueError("Handler must have the form relative/path.py:function_name")
    data = read_ownership_source(root, relative)
    # Decode Python's declared source encoding without importing the selected file.
    import io
    import tokenize

    encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
    source = data.decode(encoding)
    return inspect_ownership_source(
        source, source_file=PurePosixPath(relative).as_posix(), handler=function,
        record=record, principal=principal, owner_field=owner_field,
        source_sha256=hashlib.sha256(data).hexdigest(),
    )
