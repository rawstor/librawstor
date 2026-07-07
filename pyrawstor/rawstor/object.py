from collections.abc import Iterator

from . import librawstor


class Object:
    @staticmethod
    def list(location: str) -> Iterator[str]:
        marker = None
        while True:
            page, marker = librawstor.object_list(location, 0, marker)
            for target in page:
                yield target
            if marker is None:
                break

    @staticmethod
    def create(target: str, spec: librawstor.ObjectSpec) -> None:
        librawstor.object_create(target, spec)

    @staticmethod
    def create_at(
        location: str, spec: librawstor.ObjectSpec,
        uuid: str | None = None,
    ) -> str:
        return librawstor.object_create_at(location, uuid, spec)

    @staticmethod
    def spec(target: str) -> librawstor.ObjectSpec:
        return librawstor.object_spec(target)

    @staticmethod
    def remove(target: str) -> None:
        librawstor.object_remove(target)
