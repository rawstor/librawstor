from subprocess import check_output

from setuptools import setup, Extension

from pathlib import Path


def get_config():
    ret = {}
    config_file = Path(__file__).parent / "config.py"
    with open(config_file, "r", encoding="utf-8") as f:
        exec(f.read(), ret)
    return ret

def call_pkg_config(module, *args):
    return check_output(["pkg-config", module, *args]).decode("utf-8")[:-1]


def pkg_config_include_dirs(module):
    includes = filter(
        lambda lib: lib,
        call_pkg_config(module, "--cflags-only-I").split(" "))
    return [include[2:] for include in includes]


def pkg_config_lib_dirs(module):
    libs = filter(
        lambda lib: lib,
        call_pkg_config(module, "--libs-only-L").split(" "))
    return [lib[2:] for lib in libs]


def pkg_config_libs(module):
    libs = filter(
        lambda lib: lib,
        call_pkg_config(module, "--libs-only-l").split(" "))
    return [lib[2:] for lib in libs]


if __name__ == "__main__":
    config = get_config()

    sources = [
        "rawstor/module.c",
        "rawstor/rawstor.c",
    ]

    depends = [
        "rawstor/rawstor.h",
    ]

    include_dirs = [
        "mip_solver/libmipsolver",
    ]

    libraries = [
    ]

    library_dirs = [
    ]

    extra_compile_args = [
        "-Werror",
    ]

    extensions = [
        Extension(
            "rawstor",
            sources=sources,
            depends=depends,
            include_dirs=include_dirs,
            libraries=libraries,
            library_dirs=library_dirs,
            extra_compile_args=extra_compile_args,
        ),
    ]

    setup(
        name="rawstor",
        version=config["package_version"],
        packages=[
            "rawstor",
        ],
        ext_modules=extensions,
    )
