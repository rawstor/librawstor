import rawstor

import errno
import unittest
import tempfile
import uuid


class TestTarget(unittest.TestCase):
    def test_create(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000001")

            target.create(size=1 << 20, width=1)

            read_spec = target.spec()
            self.assertEqual(read_spec.size, 1 << 20)

            target.remove()

    def test_spec_not_found(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000002")

            self.assertRaises(FileNotFoundError, target.spec)

    def test_remove_not_found(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000003")

            self.assertRaises(FileNotFoundError, target.remove)

    def test_create_twice(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000004")

            target.create(size=1 << 20, width=1)

            self.assertRaises(
                FileExistsError, target.create, size=1 << 20, width=1)

            target.remove()

    def test_open_write_read(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000007")
            target.create(size=1 << 20, width=1)

            with target.open() as obj:
                self.assertEqual(obj.pwrite(b"ping", 0), 4)
                self.assertEqual(obj.pread(4, 0), b"ping")

            target.remove()

    def test_open_readonly_rejects_write(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000008")
            target.create(size=1 << 20, width=1)

            with target.open(rawstor.READONLY) as obj:
                self.assertEqual(obj.pread(4, 0), b"\0\0\0\0")
                with self.assertRaises(OSError) as cm:
                    obj.pwrite(b"ping", 0)
                self.assertEqual(cm.exception.errno, errno.EROFS)

            target.remove()

    def test_open_snapshot_requires_readonly(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000009/"
                "00000000-0000-0000-0000-00000000000a")

            with self.assertRaises(OSError) as cm:
                target.open()
            self.assertEqual(cm.exception.errno, errno.EINVAL)

    # file:// has no native CoW (OSError/ENOTSUP once the attempt actually
    # reaches the backend), so these only exercise create_snapshot()'s own
    # version id resolution (all three modes -- see its own docstring) --
    # the id is resolved before the doomed backend attempt, so that part is
    # fully testable without a CoW-capable backend at all.
    def test_create_snapshot_generates_fresh_id_for_plain_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000005")

            with self.assertRaises(OSError) as cm:
                target.create_snapshot()
            self.assertEqual(cm.exception.errno, errno.ENOTSUP)

    def test_create_snapshot_uses_id_already_bound_in_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            snapshot_id = "00000000-0000-0000-0000-000000000006"
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000005/"
                f"{snapshot_id}")

            with self.assertRaises(OSError) as cm:
                target.create_snapshot()
            self.assertEqual(cm.exception.errno, errno.ENOTSUP)

    def test_create_snapshot_uses_explicit_id_for_plain_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000005")
            snapshot_id = str(uuid.uuid4())

            with self.assertRaises(OSError) as cm:
                target.create_snapshot(snapshot_id)
            self.assertEqual(cm.exception.errno, errno.ENOTSUP)

    def test_create_snapshot_explicit_id_on_bound_target_is_einval(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            bound_id = "00000000-0000-0000-0000-000000000006"
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000005/"
                f"{bound_id}")

            with self.assertRaises(OSError) as cm:
                target.create_snapshot(str(uuid.uuid4()))
            self.assertEqual(cm.exception.errno, errno.EINVAL)
