# Runtime requirement

This is a thin binding: the `rawstor` wheel ships only the Python
extension module (`rawstor/librawstor.abi3.so`), built dynamically linked
against `librawstor`. It does **not** bundle `librawstor`, `liburing`, or
`libxxhash` -- those need to already be installed on the system, the same
way the `python3-rawstor` deb/rpm packages already depend on the
`librawstor` package rather than embedding it.

Install `librawstor` matching this wheel's version (see the wheel's
`METADATA` `Version` field) from
https://github.com/rawstor/librawstor/releases (`.deb`/`.rpm`) or build it
from source -- see https://github.com/rawstor/librawstor. Without it,
`import rawstor` fails with an `OSError` from the dynamic linker rather
than a `pip`-level dependency error, since PyPI wheels have no way to
declare a system-package dependency.
