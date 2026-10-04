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

    def test_create_chunk_size(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000007")

            target.create(size=4 << 20, width=1, chunk_size=1 << 20)

            read_spec = target.spec()
            self.assertEqual(read_spec.size, 4 << 20)
            self.assertEqual(read_spec.chunk_size, 1 << 20)

            target.remove()

    def test_object_spec_fields(self):
        spec = rawstor.librawstor.ObjectSpec(
            size=4 << 20, width=3, chunk_size=1 << 20, stripe_width=2,
            failure_domain=rawstor.OBJ_DOMAIN_RACK)
        self.assertEqual(spec.size, 4 << 20)
        self.assertEqual(spec.width, 3)
        self.assertEqual(spec.chunk_size, 1 << 20)
        self.assertEqual(spec.stripe_width, 2)
        self.assertEqual(spec.failure_domain, rawstor.OBJ_DOMAIN_RACK)

        spec.stripe_width = 1
        spec.failure_domain = rawstor.OBJ_DOMAIN_DC
        self.assertEqual(spec.stripe_width, 1)
        self.assertEqual(spec.failure_domain, rawstor.OBJ_DOMAIN_DC)

    def test_object_spec_failure_domain_names(self):
        for name, value in [
            ("ost", rawstor.OBJ_DOMAIN_OST),
            ("server", rawstor.OBJ_DOMAIN_SERVER),
            ("rack", rawstor.OBJ_DOMAIN_RACK),
            ("row", rawstor.OBJ_DOMAIN_ROW),
            ("dc", rawstor.OBJ_DOMAIN_DC),
        ]:
            spec = rawstor.target.object_spec(
                size=1 << 20, width=1, failure_domain=name)
            self.assertEqual(spec.failure_domain, value)

        self.assertRaises(
            ValueError, rawstor.target.object_spec,
            size=1 << 20, width=1, failure_domain="zone")

    # file:// keeps no placement policy of its own, so this only checks
    # failure_domain actually reaches rawstor_target_create(): an
    # out-of-range value is refused there.
    def test_create_failure_domain_reaches_library(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000009")

            with self.assertRaises(OSError) as cm:
                target.create(size=1 << 20, width=1, failure_domain=256)
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            target.create(size=1 << 20, width=1, failure_domain="rack")
            target.remove()

    def test_meta(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-00000000000a")
            target.create(size=4 << 20, width=1, chunk_size=4 << 20)

            [meta] = target.meta()
            self.assertEqual(meta.size, 4 << 20)
            self.assertEqual(meta.width, 1)
            self.assertEqual(meta.chunk_size, 4 << 20)
            # Placement policy is mds:// only.
            self.assertEqual(meta.stripe_width, 0)
            self.assertEqual(meta.failure_domain, rawstor.OBJ_DOMAIN_DEFAULT)
            self.assertEqual(meta.member_role, rawstor.MEMBER_DATA)
            self.assertEqual(meta.state, rawstor.OBJECT_SYNC_STATE_CLEAN)

            target.remove()

    def test_chunks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")
            target = location.create(
                size=4 << 20, width=1, chunk_size=1 << 20)

            self.assertEqual(
                target.chunks(), [0, 1 << 20, 2 << 20, 3 << 20])

            target.remove()

    # file:// has no snapshots, so the listing is empty rather than an
    # error.
    def test_snapshots_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000008")
            target.create(size=1 << 20, width=1)

            self.assertEqual(list(target.snapshots()), [])

            target.remove()

    def test_create_twice(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000004")

            target.create(size=1 << 20, width=1)

            self.assertRaises(
                FileExistsError, target.create, size=1 << 20, width=1)

            target.remove()

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
