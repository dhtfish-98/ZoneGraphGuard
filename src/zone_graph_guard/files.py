"""Anchored descriptor reads: only regular files under an explicit root."""

import os
import stat
from .contracts import Gap


def _parts(path, absolute=False):
    if not isinstance(path, str) or not path or "\x00" in path or ":" in path:
        raise Gap("invalid_local_path")
    if absolute != path.startswith("/"):
        raise Gap("invalid_local_path")
    parts = path[1:].split("/") if absolute else path.split("/")
    if absolute and path == "/":
        return []
    if len(parts) > 64 or any(p in ("", ".", "..") or len(p.encode()) > 255 for p in parts):
        raise Gap("invalid_local_path")
    return parts


class Reader:
    def __init__(self, root, limits):
        self.limits = limits
        self.total = 0
        self.count = 0
        self.fd = None
        required = ("O_NOFOLLOW", "O_DIRECTORY", "O_NONBLOCK")
        if any(type(getattr(os, flag, None)) is not int or getattr(os, flag, 0) <= 0
               for flag in required):
            raise Gap("safe_descriptor_reads_unavailable")
        if (type(getattr(os, "supports_dir_fd", None)) not in (set, frozenset)
                or os.open not in os.supports_dir_fd):
            raise Gap("safe_descriptor_reads_unavailable")
        parts = _parts(root, absolute=True)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open("/", flags)
        try:
            for part in parts:
                next_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            self.fd = fd
        except BaseException:
            os.close(fd)
            raise

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def read(self, path):
        parts = _parts(path)
        self.count += 1
        if self.count > self.limits.files:
            raise Gap("file_count_budget_exceeded")
        parent = os.dup(self.fd)
        file_fd = None
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=parent)
                os.close(parent)
                parent = next_fd
            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                              dir_fd=parent)
            before = os.fstat(file_fd)
            if not stat.S_ISREG(before.st_mode):
                raise Gap("regular_file_required")
            if before.st_size > self.limits.file_bytes:
                raise Gap("file_byte_budget_exceeded")
            if self.total + before.st_size > self.limits.total_bytes:
                raise Gap("total_byte_budget_exceeded")
            read_budget = min(self.limits.file_bytes, self.limits.total_bytes - self.total)
            with os.fdopen(file_fd, "rb") as handle:
                file_fd = None
                raw = handle.read(read_budget + 1)
                after = os.fstat(handle.fileno())
            self.total += len(raw)  # failed/changed reads still consume the byte budget
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if (identity(before) != identity(after) or not stat.S_ISREG(after.st_mode)
                    or len(raw) != after.st_size):
                raise Gap("input_changed_or_short_read")
            return raw
        finally:
            if file_fd is not None:
                os.close(file_fd)
            os.close(parent)
