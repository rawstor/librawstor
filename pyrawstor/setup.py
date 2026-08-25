from subprocess import check_output

from setuptools import setup, Extension

import os
from pathlib import Path


def get_config():
    ret = {}
    config_file = Path(__file__).parent / "config.py"
    with open(config_file, "r", encoding="utf-8") as f:
        exec(f.read(), ret)
    return ret

# Floor of the Py_LIMITED_API/abi3 build: a single "cp39-abi3" extension
# works unmodified on every CPython >= 3.9, so wheels don't need one build
# per Python version. Keep in sync with configure.ac's AM_PATH_PYTHON([3.9]).
PY_LIMITED_API = "0x03090000"

if __name__ == "__main__":
    config = get_config()

    cflags = os.getenv('CFLAGS', '')
    ldflags = os.getenv('LDFLAGS', '')

    setup(
        name="rawstor",
        version=config["package_version"],
        python_requires=">=3.9",
        license="LGPL-3.0-or-later",
        license_files=["COPYING", "NOTICE.md"],
        packages=[
            "rawstor",
        ],
        ext_modules=[
            Extension(
                "rawstor.librawstor",
                sources=[
                    "rawstor/librawstor/module.c",
                    "rawstor/librawstor/object_bindings.c",
                    "rawstor/librawstor/rawio_sync.c",
                ],
                depends=[
                    "rawstor/librawstor/object_bindings.h",
                    "rawstor/librawstor/rawio_sync.h",
                ],
                include_dirs=[
                    "../include",
                ],
                libraries=[
                    "rawstor",
                ],
                library_dirs=[
                    "../src/.libs",
                ],
                extra_compile_args=os.getenv('CFLAGS', '').split(),
                extra_link_args=os.getenv('LDFLAGS', '').split(),
                py_limited_api=True,
                define_macros=[("Py_LIMITED_API", PY_LIMITED_API)],
            ),
        ],
        options={
            "bdist_wheel": {"py_limited_api": "cp39"},
        },
    )
