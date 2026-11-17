from .constants import *  # noqa: F401,F403

_initialize_insecure = False


def initialize(*, insecure=False):
    """Start rawstor, optionally without TLS or peer authentication.

    Call with insecure=True before importing Target or Location. TLS settings
    (RAWSTOR_TLS_*) must be unset in that mode. Repeated calls with the same
    mode are allowed; changing the mode after initialization raises RuntimeError.
    Without this call, Target and Location start rawstor with TLS enabled.
    """
    global _initialize_insecure
    import importlib
    import sys

    if not isinstance(insecure, bool):
        raise TypeError("insecure must be a bool")
    if __name__ + ".librawstor" in sys.modules:
        if insecure != _initialize_insecure:
            raise RuntimeError(
                "rawstor is already initialized with a different TLS mode"
            )
        return
    previous = _initialize_insecure
    _initialize_insecure = insecure
    try:
        importlib.import_module(".librawstor", __name__)
    except Exception:
        _initialize_insecure = previous
        raise


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
