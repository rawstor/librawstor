from collections.abc import Iterator

from . import librawstor
from .target import Target


class Location:
    def __init__(self, uri: str):
        self._uri = uri

    @property
    def uri(self):
        return self._uri

    def __hash__(self):
        return hash(self._uri)

    def __repr__(self):
        return f"<Location {repr(self._uri)}>"

    def __lt__(self, other: Location):
        return self._uri < other._uri

    def __eq__(self, other: Location):
        return self._uri == other._uri

    def create(self, *, size: int, uuid: str | None = None) -> Target:
        return Target(
            librawstor.object_create_at(
                self._uri, uuid, librawstor.ObjectSpec(size=size)))

    def __iter__(self) -> Iterator[str]:
        token = None
        while True:
            page, token = librawstor.object_list(self._uri, 0, token)
            for target in page:
                yield Target(target)
            if token is None:
                break
