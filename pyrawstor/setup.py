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

if __name__ == "__main__":
    config = get_config()

    cflags = os.getenv('CFLAGS', '')
    ldflags = os.getenv('LDFLAGS', '')

    setup(
        name="rawstor",
        version=config["package_version"],
        packages=[
            "rawstor",
        ],
        ext_modules=[
            Extension(
                "rawstor.librawstor",
                sources=[
                    "rawstor/librawstor/module.c",
                    "rawstor/librawstor/object_bindings.c",
                ],
                depends=[
                    "rawstor/librawstor/object_bindings.h",
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
                runtime_library_dirs=[
                    "../src/.libs"
                ],
            ),
        ],
    )
