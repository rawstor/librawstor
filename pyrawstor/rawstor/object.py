import os

from . import librawstor


class Object:
    @staticmethod
    def create(target: str):
        res = librawstor.object_create(target)
        if res < 0:
            raise OSError(-res, os.strerror(-res))

    @staticmethod
    def remove(target: str):
        res = librawstor.object_remove(target)
        if res < 0:
            raise OSError(-res, os.strerror(-res))
