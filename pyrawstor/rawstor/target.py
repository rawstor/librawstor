from __future__ import annotations

from . import librawstor


class Target:
    def __init__(self, uri: str):
        self._uri = uri

    @property
    def uri(self):
        return self._uri

    def __hash__(self) -> int:
        return hash(self._uri)

    def __repr__(self) -> str:
        return f"<Target {repr(self._uri)}>"

    def __lt__(self, other: "Target") -> bool:
        if not isinstance(other, Target):
            return NotImplemented
        return self._uri < other._uri

    def __le__(self, other: "Target") -> bool:
        if not isinstance(other, Target):
            return NotImplemented
        return self._uri <= other._uri

    def __gt__(self, other: "Target") -> bool:
        if not isinstance(other, Target):
            return NotImplemented
        return self._uri > other._uri

    def __ge__(self, other: "Target") -> bool:
        if not isinstance(other, Target):
            return NotImplemented
        return self._uri >= other._uri

    def __eq__(self, other: "Target") -> bool:
        if not isinstance(other, Target):
            return NotImplemented
        return self._uri == other._uri

    def create(self, *, size: int, width: int, chunk_size: int = 0) -> None:
        librawstor.object_create(
            self._uri,
            librawstor.ObjectSpec(
                size=size, width=width, chunk_size=chunk_size))

    def spec(self) -> librawstor.ObjectSpec:
        return librawstor.object_spec(self._uri)

    def meta(self) -> list[librawstor.ObjectMeta | None]:
        """One entry per mirror in this target, in URI order: an
        ObjectMeta, or None for a mirror that didn't answer."""
        return librawstor.object_meta(self._uri)

    def set_sync_state(self, sync_state: librawstor.ObjectSyncState) -> None:
        """Write mirror consistency state to every mirror in this target.
        A sharp tool: setting this by hand can desynchronize a target's
        copies in ways the library's own quorum/reconciliation logic isn't
        designed to recover from automatically -- not meant for routine
        use."""
        librawstor.object_set_sync_state(self._uri, sync_state)

    def remove(self) -> None:
        librawstor.object_remove(self._uri)
