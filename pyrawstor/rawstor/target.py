from __future__ import annotations

from collections.abc import Iterator

from . import librawstor
from .constants import FAILURE_DOMAINS, OBJ_DOMAIN_DEFAULT


def object_spec(
    *, size: int, width: int, chunk_size: int = 0, stripe_width: int = 0,
    failure_domain: int | str = OBJ_DOMAIN_DEFAULT
) -> librawstor.ObjectSpec:
    """Build an ObjectSpec for create(). stripe_width and failure_domain
    are mds:// placement policy (docs/mds.md); failure_domain is either an
    OBJ_DOMAIN_* value or its FAILURE_DOMAINS name ("dc", "row", "rack",
    "server", "ost")."""
    if isinstance(failure_domain, str):
        try:
            failure_domain = FAILURE_DOMAINS[failure_domain]
        except KeyError:
            raise ValueError(
                f"invalid failure domain: {failure_domain!r}") from None
    return librawstor.ObjectSpec(
        size=size, width=width, chunk_size=chunk_size,
        stripe_width=stripe_width, failure_domain=failure_domain)


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

    def create(
        self, *, size: int, width: int, chunk_size: int = 0,
        stripe_width: int = 0,
        failure_domain: int | str = OBJ_DOMAIN_DEFAULT
    ) -> None:
        librawstor.object_create(
            self._uri,
            object_spec(
                size=size, width=width, chunk_size=chunk_size,
                stripe_width=stripe_width, failure_domain=failure_domain))

    def create_version(self, uuid: str | None = None) -> "Target":
        """Take a native CoW version of this target's live version,
        returning the resulting Target (this target's own URI, with the
        version id actually used spliced onto it -- or this target
        itself, unchanged, if it already named a bound version). Three
        ways that id is picked (see rawstor_target_create_version()'s
        own doc comment, <rawstor/target.h>):
        - This target's own URI already names a specific version of its
          own (e.g. as returned by a previous create_version()) and
          `uuid` is None: that bound version IS the one taken.
        - This target names a plain object and `uuid` is None: a fresh
          id is generated.
        - `uuid` is given: that id is used verbatim -- but only if this
          target names a plain object; combining it with a target that
          already carries its own bound version raises OSError (EINVAL).
        """
        return Target(librawstor.object_create_version(self._uri, uuid))

    def spec(self) -> librawstor.ObjectSpec:
        return librawstor.object_spec(self._uri)

    def meta(self, offset: int = 0) -> list[librawstor.ObjectMeta | None]:
        """One entry per mirror of the chunk at `offset` (0 for an
        ordinary, single-chunk target), in URI order: an ObjectMeta, or
        None for a mirror that didn't answer."""
        return librawstor.object_meta(self._uri, offset)

    def set_member_config(
            self, config: librawstor.ObjectConfig,
            member_index: int = 0, offset: int = 0, flags: int = 0) -> None:
        """Write the chunk's configuration to one real member (position
        `member_index` in meta()'s own per-chunk order) of the chunk at
        `offset` (0 for an ordinary, single-chunk target). A sharp tool:
        setting this by hand can desynchronize a target's copies in ways
        the library's own quorum/reconciliation logic isn't designed to
        recover from automatically -- not meant for routine use. A caller
        wanting every member of the chunk written calls this once per
        member instead of relying on any fan-out here."""
        librawstor.object_set_member_config(
            self._uri, config, member_index, offset, flags)

    def chunks(self) -> list[int]:
        """Every chunk offset this target's object has, ascending (see
        rawstor_target_chunks(), <rawstor/target.h>)."""
        return librawstor.object_chunks(self._uri)

    def versions(self) -> Iterator["Target"]:
        """Every version of this target's object, oldest first, each as
        its own Target (see rawstor_target_versions(),
        <rawstor/target.h>)."""
        for version in librawstor.object_versions(self._uri):
            yield Target(version)

    def remove(self) -> None:
        librawstor.object_remove(self._uri)
