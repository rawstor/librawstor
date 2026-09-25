from __future__ import annotations

from . import librawstor
from .object import Object


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

    def create_snapshot(self, uuid: str | None = None) -> "Target":
        """Take a native CoW snapshot of this target's live version,
        returning the resulting Target (this target's own URI, with the
        version id actually used spliced onto it -- or this target
        itself, unchanged, if it already named a bound version). Three
        ways that id is picked (see rawstor_target_create_snapshot()'s
        own doc comment, <rawstor/target.h>):
        - This target's own URI already names a specific version of its
          own (e.g. as returned by a previous create_snapshot()) and
          `uuid` is None: that bound version IS the one taken.
        - This target names a plain object and `uuid` is None: a fresh
          id is generated.
        - `uuid` is given: that id is used verbatim -- but only if this
          target names a plain object; combining it with a target that
          already carries its own bound version raises OSError (EINVAL).
        """
        return Target(librawstor.object_create_snapshot(self._uri, uuid))

    def open(self, flags: int = 0) -> Object:
        """Open this (existing) target. `flags` is 0 or
        rawstor.READONLY: a target naming a bound snapshot version can
        only be opened READONLY (OSError/EINVAL otherwise); READONLY also
        lets a mirrored object open without a write quorum, and every
        write to the result fails with OSError/EROFS."""
        return Object(librawstor.object_open(self._uri, flags))

    def spec(self) -> librawstor.ObjectSpec:
        return librawstor.object_spec(self._uri)

    def meta(self, offset: int = 0) -> list[librawstor.ObjectMeta | None]:
        """One entry per mirror of the chunk at `offset` (0 for an
        ordinary, single-chunk target), in URI order: an ObjectMeta, or
        None for a mirror that didn't answer."""
        return librawstor.object_meta(self._uri, offset)

    def set_sync_state(
            self, sync_state: librawstor.ObjectSyncState,
            offset: int = 0) -> None:
        """Write mirror consistency state to every mirror of the chunk at
        `offset` (0 for an ordinary, single-chunk target). A sharp tool:
        setting this by hand can desynchronize a target's copies in ways
        the library's own quorum/reconciliation logic isn't designed to
        recover from automatically -- not meant for routine use."""
        librawstor.object_set_sync_state(self._uri, sync_state, offset)

    def remove(self) -> None:
        librawstor.object_remove(self._uri)
