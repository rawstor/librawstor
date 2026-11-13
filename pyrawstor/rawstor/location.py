from __future__ import annotations

from collections.abc import Iterator
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

    def info(self) -> librawstor.LocationInfo:
        return librawstor.location_info(self._uri)

    def tenants(self) -> Iterator[str]:
        """Yield the tenants registered in the MDS this location names, as
        UUID strings in ascending order, a page at a time. Raises OSError
        (ENOTSUP) for a location that is not an mds:// one: only an MDS
        keeps a tenant registry (docs/tenants.md)."""
        token = None
        while True:
            page, token = librawstor.tenant_list(self._uri, 0, token)
            yield from page
            if token is None:
                break

    def create_tenant(self, tenant: str | None = None) -> str:
        """Register `tenant`, a UUID string (a random one if None), in the
        MDS this location names, and return it. Raises OSError: EEXIST if
        it is registered, EINVAL if it is not a UUID or is the nil one."""
        if tenant is None:
            tenant = str(uuid4())
        librawstor.tenant_create(self._uri, tenant)
        return tenant

    def remove_tenant(self, tenant: str) -> None:
        """Remove `tenant` from the MDS this location names. Raises
        OSError: ENOENT if it is not registered, EBUSY while it owns an
        object, EPERM for the default tenant."""
        librawstor.tenant_remove(self._uri, tenant)

    def objects(self) -> Iterator[Target]:
        """Yield the objects of this location, a page at a time. A location
        that names a tenant yields that tenant's objects, any other every
        object (docs/tenants.md)."""
        token = None
        while True:
            page, token = librawstor.object_list(self._uri, 0, token)
            for target in page:
                yield Target(target)
            if token is None:
                break
