from .constants import *  # noqa: F401,F403

# Target and Location load the librawstor extension, and loading it starts
# rawstor, which needs its TLS settings. They are imported when first used, so
# that `rawstor.pki` can make those settings before that.
_LAZY = {
    "Target": ".target",
    "Location": ".location",
}


def __getattr__(name):
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    value = getattr(importlib.import_module(module, __name__), name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(_LAZY))
