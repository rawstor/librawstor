# Third-party notices

The `rawstor` PyPI wheel bundles a handful of shared libraries inside
`rawstor/rawstor.libs/` (vendored there by `auditwheel repair` at build
time, since PyPI installs cannot rely on a system package manager to
provide them):

| Library      | License               | Upstream source                              |
|--------------|------------------------|-----------------------------------------------|
| `librawstor` | LGPL-3.0-or-later      | https://github.com/rawstor/librawstor         |
| `liburing`   | MIT OR LGPL-2.1-or-later | https://github.com/axboe/liburing           |
| `libxxhash`  | BSD-2-Clause           | https://github.com/Cyan4973/xxHash            |

The exact `librawstor` build vendored into a given `rawstor` wheel is
built from the git tag/commit matching that wheel's version (see the
wheel's `METADATA` `Version` field and
https://github.com/rawstor/librawstor/tags). `librawstor`'s full source,
including the `COPYING` file distributed alongside it in this wheel, is
available there. Per LGPL-3.0 §4(d)/§6, you may relink this wheel's
extension module (`rawstor/librawstor.abi3.so`) against a modified build
of `librawstor` yourself -- build `librawstor` from that source and
either replace `rawstor/rawstor.libs/librawstor-*.so.*` in this
installation, or point `LD_LIBRARY_PATH` at your build.
