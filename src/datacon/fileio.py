"""Bounded, symlink-safe helpers for paths that an attacker may control.

Files below ``DATACON_RUN_ROOT`` and inside an evidence bundle are untrusted.
Every reader opens the leaf with ``O_NOFOLLOW``/``O_NONBLOCK`` and checks the
resulting inode with ``fstat`` before touching the contents; every writer opens
the leaf with ``O_NOFOLLOW`` (or ``O_EXCL`` for temporary files) so a planted
symlink can neither redirect the write nor block the worker. These helpers are
deliberately small and shared by ``execution`` and ``evidence`` so both layers
apply the same rules.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
import stat


class UnsafeFileError(RuntimeError):
    """A path failed the regular-file / no-symlink / size-cap contract."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


def _final_flags(extra: int) -> int:
    return extra | getattr(os, "O_NOFOLLOW", 0)


def _assert_dir_fd_matches_parent(dir_fd: int, parent_path: Path | str) -> None:
    """Prove ``dir_fd`` still names the directory reached through ``parent_path``.

    The caller opens the parent with ``O_DIRECTORY|O_NOFOLLOW`` and keeps the
    descriptor. Before every operation that is performed relative to that
    descriptor, compare its ``(st_dev, st_ino)`` pair with the current path.
    A rename-and-replace after the check cannot redirect the descriptor, and a
    mismatch is reported instead of silently writing through a swapped path.
    """
    try:
        by_fd = os.fstat(dir_fd)
        by_path = os.lstat(parent_path)
    except OSError as error:
        raise UnsafeFileError(
            "PARENT_UNVERIFIED", f"write parent cannot be inspected: {error}"
        ) from error
    if not stat.S_ISDIR(by_path.st_mode):
        raise UnsafeFileError(
            "PARENT_CHANGED", f"write parent is not a real directory: {parent_path}"
        )
    if (by_fd.st_dev, by_fd.st_ino) != (by_path.st_dev, by_path.st_ino):
        raise UnsafeFileError(
            "PARENT_CHANGED",
            f"write parent changed after it was opened: {parent_path}",
        )


def _relative_name(path: Path | str) -> str:
    target = Path(path)
    if target.is_absolute() or target.parent != Path(".") or target.name in (
        "",
        ".",
        "..",
    ):
        raise UnsafeFileError(
            "UNSAFE_PATH", "dir_fd writes require a single relative file name"
        )
    return target.name


def read_regular_file_bounded(path: Path | str, *, max_bytes: int) -> bytes:
    """Return a regular file's bytes without following symlinks or blocking.

    ``O_NONBLOCK`` makes a FIFO return immediately; ``fstat`` then rejects it
    before any payload is read. A file that grows past ``max_bytes`` or changes
    size during the read is reported instead of being silently truncated.
    """
    flags = _final_flags(
        os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise UnsafeFileError(
                "SYMLINK", f"path is a symlink: {path}"
            ) from error
        raise UnsafeFileError(
            "UNREADABLE", f"path is not readable: {error}"
        ) from error
    try:
        try:
            info = os.fstat(descriptor)
        except OSError as error:
            raise UnsafeFileError(
                "UNREADABLE", f"path cannot be inspected: {error}"
            ) from error
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeFileError(
                "NOT_REGULAR", f"path is not a regular file: {path}"
            )
        if info.st_size > max_bytes:
            raise UnsafeFileError(
                "TOO_LARGE", f"file exceeds {max_bytes} bytes: {path}"
            )
        remaining = max_bytes + 1
        chunks: list[bytes] = []
        while remaining > 0:
            try:
                chunk = os.read(descriptor, remaining)
            except OSError as error:
                raise UnsafeFileError(
                    "UNREADABLE", f"file cannot be read: {error}"
                ) from error
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > max_bytes:
            raise UnsafeFileError(
                "TOO_LARGE", f"file grew past {max_bytes} bytes: {path}"
            )
        try:
            extra = os.read(descriptor, 1)
        except OSError as error:
            raise UnsafeFileError(
                "UNREADABLE", f"file cannot be read: {error}"
            ) from error
        if extra:
            raise UnsafeFileError("TOO_LARGE", f"file grew while reading: {path}")
        if len(data) != info.st_size:
            raise UnsafeFileError(
                "CHANGED", f"file changed size while reading: {path}"
            )
        return data
    finally:
        os.close(descriptor)


def _make_owner_writable(
    path: Path | str, *, dir_fd: int | None = None
) -> None:
    """Make an existing regular file owner-writable without following a link.

    A previous attempt may have written evidence with mode ``0555``. Opening
    read-only and using ``fchmod`` keeps the mode change bound to the inode that
    was checked, so a swapped symlink is never followed.
    """
    flags = _final_flags(os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    try:
        descriptor = os.open(path, flags, dir_fd=dir_fd)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise UnsafeFileError(
                "SYMLINK", f"path is a symlink: {path}"
            ) from error
        raise UnsafeFileError(
            "UNWRITABLE", f"existing file cannot be made writable: {error}"
        ) from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeFileError(
                "NOT_REGULAR", f"path is not a regular file: {path}"
            )
        # O_NOFOLLOW stops a symlink but not a hard link. A link planted inside
        # the run root would let this descriptor rewrite an inode that also has
        # a name outside it, so only a single-link file may be modified.
        if info.st_nlink != 1:
            raise UnsafeFileError(
                "HARDLINK", f"path has {info.st_nlink} hard links: {path}"
            )
        try:
            os.fchmod(descriptor, 0o600)
        except OSError as error:
            raise UnsafeFileError(
                "UNWRITABLE", f"existing file cannot be chmodded: {error}"
            ) from error
    finally:
        os.close(descriptor)


def write_regular_file(
    path: Path | str,
    data: bytes,
    *,
    mode: int,
    dir_fd: int | None = None,
    parent_path: Path | str | None = None,
) -> None:
    """Create or replace a regular file without following a symlink.

    The leaf is opened with ``O_NOFOLLOW``; the descriptor (not the path) is
    used for ``fchmod`` and the write, so a link swap after the open cannot
    redirect either operation. A read-only legacy file is made writable through
    its own descriptor and the open is retried once.
    """
    name: str | Path
    if dir_fd is not None:
        if parent_path is None:
            raise UnsafeFileError(
                "PARENT_UNVERIFIED", "dir_fd writes require parent_path"
            )
        _assert_dir_fd_matches_parent(dir_fd, parent_path)
        name = _relative_name(path)
    else:
        name = path
    # Deliberately *not* O_TRUNC: truncation happens only after fstat confirms
    # a single-link regular file. O_TRUNC would empty the inode (including an
    # externally hard-linked name) before the link check could reject it.
    flags = _final_flags(
        os.O_WRONLY | os.O_CREAT | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor: int | None = None
    try:
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=dir_fd)
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise UnsafeFileError(
                    "SYMLINK", f"path is a symlink: {path}"
                ) from error
            if error.errno not in (errno.EACCES, errno.EPERM):
                raise UnsafeFileError(
                    "UNWRITABLE", f"cannot write file: {error}"
                ) from error
            _make_owner_writable(name, dir_fd=dir_fd)
            try:
                descriptor = os.open(name, flags, 0o600, dir_fd=dir_fd)
            except OSError as retry_error:
                if retry_error.errno == errno.ELOOP:
                    raise UnsafeFileError(
                        "SYMLINK", f"path is a symlink: {path}"
                    ) from retry_error
                raise UnsafeFileError(
                    "UNWRITABLE", f"cannot write file: {retry_error}"
                ) from retry_error
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise UnsafeFileError(
                    "NOT_REGULAR", f"path is not a regular file: {path}"
                )
            # A hard link is invisible to O_NOFOLLOW: writing through it would
            # reach the same inode under a path outside the run root. Reject
            # every multi-link leaf before fchmod or any payload write.
            if info.st_nlink != 1:
                raise UnsafeFileError(
                    "HARDLINK", f"path has {info.st_nlink} hard links: {path}"
                )
            os.ftruncate(descriptor, 0)
            os.fchmod(descriptor, mode)
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise UnsafeFileError(
                        "UNWRITABLE", f"short write for file: {path}"
                    )
                view = view[written:]
        finally:
            os.close(descriptor)
            descriptor = None
    except UnsafeFileError:
        raise
    except OSError as error:
        raise UnsafeFileError(
            "UNWRITABLE", f"cannot write file: {error}"
        ) from error


def write_regular_file_atomic(
    path: Path | str,
    data: bytes,
    *,
    mode: int,
    suffix: str = ".tmp",
    dir_fd: int | None = None,
    parent_path: Path | str | None = None,
) -> None:
    """Atomically replace ``path`` through a ``O_EXCL|O_NOFOLLOW`` temp file.

    A stale temp entry is unlinked first (unlinking a symlink removes the link,
    not its target). ``O_EXCL`` then guarantees the create cannot follow a link
    planted between the unlink and the open; such a race fails closed. With
    ``dir_fd`` every unlink/open/replace is relative to the already-verified
    parent descriptor, so a rename of the parent after the check cannot
    redirect the operation.
    """
    target = Path(path)
    target_name: str | Path
    temporary_name: str | Path
    if dir_fd is not None:
        if parent_path is None:
            raise UnsafeFileError(
                "PARENT_UNVERIFIED", "dir_fd writes require parent_path"
            )
        _assert_dir_fd_matches_parent(dir_fd, parent_path)
        target_name = _relative_name(target)
        temporary_name = Path(target_name).with_suffix(suffix).name
    else:
        target_name = target
        temporary_name = target.with_suffix(suffix)
    try:
        os.unlink(temporary_name, dir_fd=dir_fd)
    except FileNotFoundError:
        pass
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise UnsafeFileError(
                "SYMLINK", f"temporary path is a symlink: {temporary_name}"
            ) from error
        raise UnsafeFileError(
            "UNWRITABLE", f"cannot clear temporary file: {error}"
        ) from error
    flags = _final_flags(
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(temporary_name, flags, 0o600, dir_fd=dir_fd)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise UnsafeFileError(
                "SYMLINK", f"temporary path is a symlink: {temporary_name}"
            ) from error
        raise UnsafeFileError(
            "UNWRITABLE", f"cannot create temporary file: {error}"
        ) from error
    try:
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise UnsafeFileError(
                    "NOT_REGULAR",
                    f"temporary path is not a regular file: {temporary_name}",
                )
            os.fchmod(descriptor, mode)
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise UnsafeFileError(
                        "UNWRITABLE",
                        f"short write for temporary file: {temporary_name}",
                    )
                view = view[written:]
        finally:
            os.close(descriptor)
        os.replace(
            temporary_name,
            target_name,
            src_dir_fd=dir_fd,
            dst_dir_fd=dir_fd,
        )
    except UnsafeFileError:
        try:
            os.unlink(temporary_name, dir_fd=dir_fd)
        except OSError:
            pass
        raise
    except OSError as error:
        try:
            os.unlink(temporary_name, dir_fd=dir_fd)
        except OSError:
            pass
        raise UnsafeFileError(
            "UNWRITABLE", f"cannot write temporary file: {error}"
        ) from error
    except BaseException:
        try:
            os.unlink(temporary_name, dir_fd=dir_fd)
        except OSError:
            pass
        raise
