# Contributing to Rawstor

We love your contributions and want to make it as easy as possible to work
together. Please follow these guidelines when contributing to this project.

## Before You Start

For major features or significant changes, please open an issue first to
discuss your proposed changes with the maintainers. This helps ensure your
work aligns with the project direction and prevents duplicate effort.
For small fixes (typos, minor bugs), feel free to open a pull request directly.

The [documentation](docs/README.md) is the best place to get oriented:
[Concepts](docs/concepts.md) explains the Location/Target addressing model
everything else builds on, and [Architecture](docs/architecture.md) gives a
high-level overview of the components.

## Development Environment

### Dependencies

Rawstor builds with GNU Autotools and a C++20 compiler. It needs:

- `liburing` >= 2.3 (optional, see `--without-liburing` below; Ubuntu 22.04's
  2.1 is too old);
- `libxxhash` (optional, `--without-libxxhash`);
- `sqlite3` for `rawstor-mds` (optional, `--without-sqlite3`);
- GoogleTest for the test suites (optional, `--disable-tests`);
- Python 3 for the `pyrawstor` bindings (optional, `--without-python3`).

Ubuntu/Debian:

```bash
sudo apt-get install -y build-essential autoconf automake libtool pkg-config \
    liburing-dev libxxhash-dev libsqlite3-dev libgtest-dev python3-build
```

AlmaLinux/RHEL (`liburing-devel` and `gtest-devel` come from EPEL/CRB):

```bash
sudo dnf -y install epel-release
sudo dnf config-manager --set-enabled crb
sudo dnf -y install gcc-c++ make autoconf automake libtool pkgconfig \
    liburing-devel xxhash-devel sqlite-devel gtest-devel python3-devel
```

macOS is supported for everything except the io_uring backend and
`rawstor-vduse`: configure with `--without-liburing` there.

### Building

```bash
./autogen.sh
./configure --prefix=${HOME}/local
make -j$(nproc)
```

Useful `configure` flags for development:

| Flag | Effect |
|------|--------|
| `--enable-debug` / `--enable-trace` | More verbose logging. |
| `--enable-asan` | Build with AddressSanitizer. |
| `--without-liburing` | Use RawIO's portable `poll()` backend instead of io_uring. |
| `--disable-vduse-backend` | Skip `rawstor-vduse` (disabled automatically off Linux). |
| `--disable-tests` | Skip building the test suites. |

After editing `configure.ac` or any `Makefile.am`, run `autoreconf -fi` and
re-run `./configure` with the same flags (`./config.status --config` shows
the ones used last).

## Testing

```bash
make test
```

runs every suite: `librawstd`, `librawio`, `librawthread`, `vhost`, the top-level
`tests/`, `ost`, and, when built, `vduse`, `mds` and `pyrawstor`. Each suite is a GoogleTest binary
named `test_all` in its `tests/` directory; to run a single test:

```bash
./tests/test_all --gtest_filter=SuiteName.TestName
```

CI runs the tests with both RawIO backends, so if you touch `librawio` or
anything I/O-related, also check a `--without-liburing` build. If tests fail
with `io_uring` errors before reaching your code, see
[Troubleshooting](README.md#troubleshooting).

Please add tests for new functionality and a regression test for bug fixes
where practical.

## Code Style & Standards

* Follow the existing code style and patterns in the project.
* C/C++ code is formatted with `clang-format` (`.clang-format`: LLVM base,
  4-space indent). Before submitting, run:

  ```bash
  ./.github/tools/clang-format.sh
  ```

  It uses `clang-format-21` (falling back to `clang-format`), lists the
  files that need re-formatting and prints the command to fix them.
* Cross-directory includes use angle brackets and are namespaced by
  directory (`<rawio/queue.hpp>`, `<rawstor/object.h>`); same-directory
  private headers use quotes.
* Use plain `snake_case` names, including constants (no `k` or `m_`
  prefixes).
* Keep portable code buildable on macOS: avoid Linux-only APIs (e.g.
  `eventfd()`, `pipe2()`) outside the io_uring backend and other
  Linux-only components, or guard them with `RAWSTD_ON_LINUX`/
  `RAWSTD_ON_MACOS` from `<rawstd/gcc.h>`.
* Don't patch vendored code (`vhost-qemu/3rdparty/`,
  `include/stdheaders/`, except to update it from upstream).
* Include comments for complex logic. Comments describe the code as it is
  now; the history of a change belongs in the commit message.

## Documentation

Update documentation in the same pull request as the change:

* command-line options and environment variables are documented in
  [README.md](README.md);
* the wire protocol is defined by `include/rawstor/protocol.h`, and
  [docs/protocol.md](docs/protocol.md) must be kept in sync with it;
* design changes go to the matching document under [docs/](docs/README.md).

## ChangeLog

[ChangeLog.md](ChangeLog.md) follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Add an entry under the `## [x.y.z] - Unreleased` section (for a fix that is
going to be backported, the release branch's one, see
[Backporting](#backporting-to-release-branches)), in the matching
`### Added`/`Changed`/`Fixed`/`Removed` subsection, for user-visible,
notable changes only: new, changed or removed functionality, a bug a user
could have hit, a packaging change. Internal refactoring, test-only changes
and documentation tweaks don't need one. Keep each entry to one short
sentence; the details belong in the commit message. Mark breaking C API
changes as such. Don't edit `debian/changelog` or the rpm spec changelog:
they are generated from `ChangeLog.md`.

## Development Workflow

1. Fork the repository on GitHub

2. Clone your fork locally:

```bash
git clone https://github.com/<your-username>/librawstor.git
cd librawstor
```

3. Create a feature branch with a descriptive name:

```bash
# For new features:
git checkout -b add/feature-name

# For bug fixes:
git checkout -b fix/bug-description

# For refactoring:
git checkout -b ref/component-name

# For documentation:
git checkout -b docs/topic
```

4. Make your changes and commit them with clear, descriptive commit messages
   (see [Commit Messages](#commit-messages))

5. Push your branch to your fork:

```bash
git push origin <your-branch-name>
```

6. Submit a Pull Request from your branch to the `main` branch of the
   `rawstor/librawstor` repository

## Commit Messages

Commit subjects follow `<type>(<scope>): <summary>`, in lowercase and the
imperative mood:

```
fix(vhost): publish avail_event when EVENT_IDX is negotiated
add(mds): reload topology on SIGHUP
docs: describe write throttling
```

* `<type>` is one of `add`, `fix`, `ref`, `docs`, `test`, `del`.
* `<scope>` is usually the component directory (`librawio`, `vhost`, `ost`,
  `mds`, `ci`, ...), several may be comma-separated, and it is omitted for
  repository-wide changes.
* The body explains what changed and why.

Commits are authored by the people who wrote them: the CI rejects commits
that name an AI assistant as author or co-author.

## Pull Request Guidelines

* Provide a clear description of what the PR accomplishes
* Reference any related issues (e.g., "Fixes #123")
* Keep PRs focused on a single purpose - avoid mixing multiple features
* Ensure all tests pass (by running `make test`) and code meets quality
  standards

Every push runs the CI (`.github/workflows/`):

* `linter`: commit metadata and the `clang-format` check;
* `make distcheck`, so every new file must be listed in the relevant
  `Makefile.am` (`SOURCES`, `EXTRA_DIST`, ...);
* unit tests with both RawIO backends;
* deb/rpm packages built and installed on Ubuntu 24.04/26.04 and
  AlmaLinux 9/10;
* fio-based performance tests (`perftest.yml`).

## Backporting to Release Branches

Each supported minor release has its own branch, `releases/vX.Y` (e.g.
`releases/v0.2`), from which its patch releases (`vX.Y.Z` tags) are cut.
New features go to `main` only; bug fixes, and occasionally a small
change a fix depends on, are backported.

Changes always land on `main` first and are then backported:

1. If the fix should go to a release branch, its PR to `main` adds the
   ChangeLog entry under that release's own section, e.g.
   `## [0.2.13] - Unreleased` (create it below the `main` version's section
   if it isn't there yet), rather than under the `main` version. The
   backport then carries the same entry.

2. Once it is merged, create a branch from the release branch, named after
   the original one with the release suffix:

```bash
git checkout -b fix/bug-description-v0.2 origin/releases/v0.2
```

3. Cherry-pick the merged commit with `-x`, so the message records where it
   came from:

```bash
git cherry-pick -x <commit>
```

4. If the commit doesn't apply as is or has to be adapted to the release
   branch, resolve it there and describe what differs from the original in
   a `Backport notes:` paragraph after the `(cherry picked from commit ...)`
   line. Keep the original subject.

5. Build and run `make test` on the release branch, then open a Pull
   Request to `releases/vX.Y` referencing the original one.

Releases are cut by the maintainers: an `add: release X.Y.Z` commit on
`main` dates the release's ChangeLog section, is cherry-picked to the
release branch and tagged `vX.Y.Z` there.

## Need Help?

* Check existing issues
* Reach out to maintainers by mentioning them in issues

## License

Rawstor is licensed under the [GNU LGPL v3](COPYING). By contributing, you
agree that your contributions will be licensed under the same terms.

Thank you for contributing!
