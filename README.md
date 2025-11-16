# Rawstor client library

[![Unit Test Status](https://github.com/rawstor/librawstor/actions/workflows/unittest.yml/badge.svg?branch=main)](https://github.com/rawstor/librawstor/actions/workflows/unittest.yml)

## TL;DR
```
./autogen.sh
./configure --prefix=${HOME}/local
make
make install
```

## Configure

### Disable liburing

```
./configure --without-liburing
```

This will replace liburing with poll.

## Testing

```
make test
```

## Contributing

We love your contributions and want to make it as easy as possible to work together. Please follow these guidelines when contributing to this project.

### Before You Start

For major features or significant changes, please open an issue first to discuss your proposed changes with the maintainers. This helps ensure your work aligns with the project direction and prevents duplicate effort.
For small fixes (typos, minor bugs), feel free to open a pull request directly.

### Development Workflow

1. Fork the repository on GitHub

2. Clone your fork locally:

```bash
git clone git@github.com:<your-username>/librawstor.git
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
```

4. Make your changes and commit them with clear, descriptive commit messages

5. Push your branch to your fork:

```bash
git push origin your-branch-name
```

6. Submit a Pull Request from your branch to the main repository's main branch

### Code Style & Standards

* Follow the existing code style and patterns in the project
* Write clear, descriptive commit messages
* Include comments for complex logic
* Update documentation when necessary
* Add tests for new functionality

### Pull Request Guidelines

* Provide a clear description of what the PR accomplishes
* Reference any related issues (e.g., "Fixes #123")
* Ensure all tests pass and code meets quality standards
* Keep PRs focused on a single purpose - avoid mixing multiple features

### Need Help?

* Check existing issues and discussions
* Ask questions in the project's GitHub Discussions
* Reach out to maintainers by mentioning them in issues

Thank you for contributing!

## Troubleshooting

### Operation not permitted
```
io_uring_queue_init() failed: Operation not permitted
```

First check if `io_uring` is disabled or not in `sysctl`:
```bash
sysctl -a | grep io_uring
```

According to the documentation for the `sysctl` files in `/proc/sys/kernel/`:

> `io_uring_disabled`:
>
> Prevents all processes from creating new `io_uring` instances. Enabling this shrinks the kernel’s attack surface.
>
> `0` - All processes can create `io_uring` instances as normal. This is the default setting.
>
> `1` - `io_uring` creation is disabled (`io_uring_setup()` will fail with `-EPERM`) for unprivileged processes not in the `io_uring_group` group. Existing `io_uring` instances can still be used. See the documentation for `io_uring_group` for more information.
>
> `2` - `io_uring` creation is disabled for all processes. `io_uring_setup()` always fails with `-EPERM`. Existing `io_uring` instances can still be used.

So you need to set it to 0:

```bash
sysctl kernel.io_uring_disabled=0
```
