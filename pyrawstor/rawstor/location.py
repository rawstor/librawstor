from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from uuid import uuid4

from . import librawstor
from .constants import OBJ_DOMAIN_DEFAULT
from .target import Target, object_spec


class Location:
    def __init__(self, uri: str):
        self._uri = uri

    @property
    def uri(self):
        return self._uri

    def __hash__(self) -> int:
        return hash(self._uri)

    def __repr__(self) -> str:
        return f"<Location {repr(self._uri)}>"

    def __lt__(self, other: "Location") -> bool:
        if not isinstance(other, Location):
            return NotImplemented
        return self._uri < other._uri

    def __le__(self, other: "Location") -> bool:
        if not isinstance(other, Location):
            return NotImplemented
        return self._uri <= other._uri

    def __gt__(self, other: "Location") -> bool:
        if not isinstance(other, Location):
            return NotImplemented
        return self._uri > other._uri

    def __ge__(self, other: "Location") -> bool:
        if not isinstance(other, Location):
            return NotImplemented
        return self._uri >= other._uri

    def __eq__(self, other: "Location") -> bool:
        if not isinstance(other, Location):
            return NotImplemented
        return self._uri == other._uri

    def create(
        self, *, size: int, width: int, chunk_size: int = 0,
        stripe_width: int = 0,
        failure_domain: int | str = OBJ_DOMAIN_DEFAULT,
        uuid: str | None = None
    ) -> Target:
        return Target(
            librawstor.object_create_at(
                self._uri, uuid,
                object_spec(
                    size=size, width=width, chunk_size=chunk_size,
                    stripe_width=stripe_width,
                    failure_domain=failure_domain)))

    def create_from_file(
        self, path: str | os.PathLike, *, width: int, size: int = 0,
        chunk_size: int = 0, stripe_width: int = 0,
        failure_domain: int | str = OBJ_DOMAIN_DEFAULT,
        uuid: str | None = None,
        progress: Callable[[int], None] | None = None
    ) -> Target:
        """Create an object at this location and fill it with the contents of
        the file `path`; returns its Target. As for create(), `uuid` names it
        and a fresh one is generated if None. `size` of 0 is the size of the
        file (rounded up to `chunk_size` for an mds:// location); see
        Target.create_from_file() for that and `progress`. If anything fails
        once the object exists, it is removed again. See
        rawstor_location_create_from_file(), <rawstor/location.h>."""
        return Target(
            librawstor.object_create_at_from_file(
                self._uri, uuid, os.fspath(path),
                object_spec(
                    size=size, width=width, chunk_size=chunk_size,
                    stripe_width=stripe_width,
                    failure_domain=failure_domain),
                progress))

    def create_from(
        self, source: Target | str, *, width: int, size: int = 0,
        chunk_size: int = 0, stripe_width: int = 0,
        failure_domain: int | str = OBJ_DOMAIN_DEFAULT,
        uuid: str | None = None,
        progress: Callable[[int], None] | None = None
    ) -> Target:
        """Create an object at this location as a copy of `source`, another
        object or one of its versions; returns its Target. See
        create_from_file() and Target.create_from(). See
        rawstor_location_create_from_target(), <rawstor/location.h>."""
        if isinstance(source, Target):
            source = source.uri
        return Target(
            librawstor.object_create_at_from_target(
                self._uri, uuid, source,
                object_spec(
                    size=size, width=width, chunk_size=chunk_size,
                    stripe_width=stripe_width,
                    failure_domain=failure_domain),
                progress))

    def info(self) -> librawstor.LocationInfo:
        return librawstor.location_info(self._uri)

    def accounts(self) -> Iterator[str]:
        """Yield the accounts registered in the MDS this location names, as
        UUID strings in ascending order, a page at a time. Raises OSError
        (ENOTSUP) for a location that is not an mds:// one: only an MDS
        keeps an account registry (docs/accounts.md)."""
        token = None
        while True:
            page, token = librawstor.account_list(self._uri, 0, token)
            yield from page
            if token is None:
                break

    def locations(self) -> Iterator[str]:
        """Yield the location URIs of the topology of the MDS this location
        names, in ascending order of their topology ids, a page at a time.
        Raises OSError (ENOTSUP) for a location that is not an mds:// one:
        only an MDS has a topology. See rawstor_location_topology(),
        <rawstor/location.h>."""
        token = None
        while True:
            page, token = librawstor.location_topology(self._uri, 0, token)
            yield from page
            if token is None:
                break

    def create_account(self, account: str | None = None) -> str:
        """Register `account`, a UUID string (a random one if None), in the
        MDS this location names, and return it. Raises OSError: EEXIST if
        it is registered, EINVAL if it is not a UUID or is the nil one."""
        if account is None:
            account = str(uuid4())
        librawstor.account_create(self._uri, account)
        return account

    def remove_account(self, account: str) -> None:
        """Remove `account` from the MDS this location names. Raises
        OSError: ENOENT if it is not registered, EPERM for the default
        account (refused before anything is removed)."""
        librawstor.account_remove(self._uri, account)

    def objects(self, ost_id: str | None = None) -> Iterator[Target]:
        """Yield the objects of this location, a page at a time. A location
        that names an account yields that account's objects, any other every
        object (docs/accounts.md).

        `ost_id`, the topology id of an entry of the MDS this location
        names, a UUID string, limits them to the objects that have a slot or
        a version member on that entry: what it still holds before it can
        leave the topology (docs/migration.md). Raises OSError: ENOENT for an
        entry the MDS does not know, EINVAL for an `ost_id` that is not a
        UUID or a location that is not an mds:// one. See
        rawstor_location_list_held(), <rawstor/location.h>."""
        token = None
        while True:
            if ost_id is None:
                page, token = librawstor.object_list(self._uri, 0, token)
            else:
                page, token = librawstor.object_list_held(
                    self._uri, ost_id, 0, token)
            for target in page:
                yield Target(target)
            if token is None:
                break
