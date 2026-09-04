from __future__ import annotations

from collections.abc import Iterator

from . import librawstor
from .target import Target


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
        self, *, size: int, mirror_count: int = 1, uuid: str | None = None
    ) -> Target:
        return Target(
            librawstor.object_create_at(
                self._uri, uuid,
                librawstor.ObjectSpec(size=size, mirror_count=mirror_count)))

    def info(self) -> librawstor.LocationInfo:
        return librawstor.location_info(self._uri)

    def __iter__(self) -> Iterator[Target]:
        token = None
        while True:
            page, token = librawstor.object_list(self._uri, 0, token)
            for target in page:
                yield Target(target)
            if token is None:
                break
