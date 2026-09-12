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

    def create(self, *, size: int, mirrors: int) -> None:
        librawstor.object_create(
            self._uri,
            librawstor.ObjectSpec(size=size, mirrors=mirrors))

    def spec(self) -> librawstor.ObjectSpec:
        return librawstor.object_spec(self._uri)

    def remove(self) -> None:
        librawstor.object_remove(self._uri)
