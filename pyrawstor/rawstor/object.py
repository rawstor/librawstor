from . import librawstor


class Object:
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
