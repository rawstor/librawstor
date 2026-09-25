from __future__ import annotations

from . import librawstor


class Object:
    """An opened object (Target.open()). Closed on exit from a `with`
    block, by close(), or (as a last resort) when garbage collected."""

    def __init__(self, handle):
        self._handle = handle

    def __enter__(self) -> "Object":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def pread(self, size: int, offset: int = 0) -> bytes:
        return librawstor.object_pread(self._handle, size, offset)

    def pwrite(
            self, data: bytes, offset: int = 0, sync: bool = False) -> int:
        """Raises OSError (EROFS) on an object opened READONLY."""
        return librawstor.object_pwrite(self._handle, data, offset, sync)

    def close(self) -> None:
        librawstor.object_close(self._handle)
