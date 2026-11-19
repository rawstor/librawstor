import rawstor

import errno
import os
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

    def test_resize_plain_target(self):
        # Only mds:// objects can grow; a file:// backend has no resize.
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-00000000000b")
            target.create(size=1 << 20, width=1)

            with self.assertRaises(OSError) as cm:
                target.resize(2 << 20)
            self.assertEqual(cm.exception.errno, errno.ENOTSUP)
            self.assertEqual(target.spec().size, 1 << 20)

            target.remove()

    def test_resize_size_out_of_range(self):
        target = rawstor.Target(
            "file:///nonexistent/00000000-0000-0000-0000-00000000000c")
        with self.assertRaises(OverflowError):
            target.resize(1 << 64)

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
            self.assertEqual(meta.role, rawstor.OBJECT_MEMBER_IN_SYNC)
            self.assertEqual(meta.writers, 0)

            target.remove()

    def test_sync_accept(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Location(f"file://{temp_dir}").create(
                size=65536, width=1)
            config = rawstor.librawstor.ObjectConfig(epoch=1, sync_id=41)
            self.assertTrue(target.sync_accept(config, 5, 1))
            self.assertEqual(target.meta()[0].sync_id, 41)
            # A copy keeps its own state when it accepts a configuration.
            self.assertEqual(target.meta()[0].state,
                             rawstor.OBJECT_SYNC_STATE_CLEAN)
            config.sync_id = 42
            # A ballot at or below the accepted one is refused.
            self.assertFalse(target.sync_accept(config, 5, 1))
            self.assertEqual(target.meta()[0].sync_id, 41)
            self.assertTrue(target.sync_accept(config, 6, 1))
            self.assertEqual(target.meta()[0].sync_id, 42)
            target.remove()

    def test_chunks(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")
            target = location.create(
                size=4 << 20, width=1, chunk_size=1 << 20)

            self.assertEqual(
                [int(chunk.uri.split(",")[0].rsplit("/", 1)[1], 16)
                 for chunk in target.chunks()],
                [0, 1 << 20, 2 << 20, 3 << 20])

            target.remove()

    def test_slots(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            target = rawstor.Location(f"file://{first},file://{second}").create(
                size=2 << 20, width=2, chunk_size=1 << 20)
            try:
                expected = [uri for chunk in target.chunks()
                            for uri in chunk.uri.split(",")]
                slots = target.slots()
                self.assertEqual([slot.uri for slot in slots], expected)
                self.assertEqual(len(slots), 4)
                self.assertTrue(all(len(slot.meta()) == 1 for slot in slots))
            finally:
                target.remove()

    # An object nobody took a version of lists none.
    def test_versions_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000008")
            target.create(size=1 << 20, width=1)

            self.assertEqual(list(target.versions()), [])

            target.remove()

    def test_create_twice(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000004")

            target.create(size=1 << 20, width=1)

            self.assertRaises(
                FileExistsError, target.create, size=1 << 20, width=1)

            target.remove()

    # file:// versions are fake snapshots (a copy of the chunk): these
    # exercise create_version()'s own version id resolution (all three
    # modes -- see its own docstring) against a backend that takes the
    # version for real.
    def test_create_version_generates_fresh_id_for_plain_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000005")
            target.create(size=1 << 20, width=1)

            version = target.create_version()
            self.assertTrue(version.uri.startswith(target.uri + "/"))
            self.assertEqual(len(version.uri), len(target.uri) + 1 + 36)
            self.assertEqual(
                [v.uri for v in target.versions()], [version.uri])

            version.remove()
            self.assertEqual(list(target.versions()), [])
            target.remove()

    def test_create_version_uses_id_already_bound_in_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            version_id = "00000000-0000-0000-0000-000000000006"
            live = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000005")
            live.create(size=1 << 20, width=1)
            target = rawstor.Target(f"{live.uri}/{version_id}")

            version = target.create_version()
            self.assertEqual(version.uri, target.uri)

            version.remove()
            live.remove()

    def test_create_version_uses_explicit_id_for_plain_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000005")
            target.create(size=1 << 20, width=1)
            version_id = str(uuid.uuid4())

            version = target.create_version(version_id)
            self.assertEqual(version.uri, f"{target.uri}/{version_id}")

            version.remove()
            target.remove()

    def test_create_version_explicit_id_on_bound_target_is_einval(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            bound_id = "00000000-0000-0000-0000-000000000006"
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000005/"
                f"{bound_id}")

            with self.assertRaises(OSError) as cm:
                target.create_version(str(uuid.uuid4()))
            self.assertEqual(cm.exception.errno, errno.EINVAL)


class TestTargetImage(unittest.TestCase):
    # Not a multiple of the 1 MiB block the library moves data in, with a
    # zero block in the middle (a hole in a sparse export) and a tail.
    DATA = (
        os.urandom(1 << 20) + bytes(1 << 20) + os.urandom((1 << 19) + 123))

    def _write(self, path, data=None):
        with open(path, "wb") as f:
            f.write(self.DATA if data is None else data)

    def _read(self, path):
        with open(path, "rb") as f:
            return f.read()

    def test_roundtrip_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            src = os.path.join(temp_dir, "src.img")
            dst = os.path.join(temp_dir, "dst.img")
            self._write(src)
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000011")

            target.create_from_file(src, width=1)
            self.assertEqual(target.spec().size, len(self.DATA))
            target.export(dst)

            self.assertEqual(self._read(dst), self.DATA)
            target.remove()

    def test_export_is_sparse(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            src = os.path.join(temp_dir, "src.img")
            dst = os.path.join(temp_dir, "dst.img")
            self._write(src, bytes(4 << 20))
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000012")
            target.create_from_file(src, width=1)

            target.export(dst)

            st = os.stat(dst)
            self.assertEqual(st.st_size, 4 << 20)
            self.assertEqual(st.st_blocks, 0)
            target.remove()

    def test_export_truncates_existing_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            src = os.path.join(temp_dir, "src.img")
            dst = os.path.join(temp_dir, "dst.img")
            self._write(src, b"x" * 1000)
            self._write(dst, b"y" * 5000)
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000013")
            target.create_from_file(src, width=1)

            target.export(dst)

            self.assertEqual(self._read(dst), b"x" * 1000)
            target.remove()

    def test_create_from_file_larger_size_pads_with_zeros(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            src = os.path.join(temp_dir, "src.img")
            dst = os.path.join(temp_dir, "dst.img")
            self._write(src, b"x" * 1000)
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000014")

            target.create_from_file(src, width=1, size=4096)
            target.export(dst)

            self.assertEqual(self._read(dst), b"x" * 1000 + bytes(3096))
            target.remove()

    def test_create_from_file_smaller_size_is_einval(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            src = os.path.join(temp_dir, "src.img")
            self._write(src, b"x" * 1000)
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000015")

            with self.assertRaises(OSError) as cm:
                target.create_from_file(src, width=1, size=100)
            self.assertEqual(cm.exception.errno, errno.EINVAL)
            with self.assertRaises(OSError) as cm:
                target.spec()
            self.assertEqual(cm.exception.errno, errno.ENOENT)

    def test_create_from_file_missing_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000016")

            with self.assertRaises(FileNotFoundError):
                target.create_from_file(
                    os.path.join(temp_dir, "missing.img"), width=1)
            with self.assertRaises(FileNotFoundError):
                target.spec()

    def test_create_from_file_needs_width(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            src = os.path.join(temp_dir, "src.img")
            self._write(src, b"x")
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000017")

            with self.assertRaises(OSError) as cm:
                target.create_from_file(src, width=0)
            self.assertEqual(cm.exception.errno, errno.EINVAL)

    def test_export_not_found(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000018")

            with self.assertRaises(FileNotFoundError):
                target.export(os.path.join(temp_dir, "dst.img"))

    def test_create_from_object_and_version(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            src = os.path.join(temp_dir, "src.img")
            dst = os.path.join(temp_dir, "dst.img")
            self._write(src)
            origin = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000019")
            origin.create_from_file(src, width=1)
            version = origin.create_version()

            copy = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-00000000001a")
            copy.create_from(origin, width=1)
            copy.export(dst)
            self.assertEqual(self._read(dst), self.DATA)

            from_version = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-00000000001b")
            from_version.create_from(version.uri, width=1)
            from_version.export(dst)
            self.assertEqual(self._read(dst), self.DATA)

            version.export(dst)
            self.assertEqual(self._read(dst), self.DATA)

            for t in (from_version, copy, version, origin):
                t.remove()

    def _assert_progress(self, calls):
        self.assertGreaterEqual(len(calls), 3)
        self.assertEqual(calls[0], 0)
        self.assertEqual(calls[-1], 100)
        self.assertEqual(calls, sorted(set(calls)))
        self.assertTrue(all(0 <= c <= 100 for c in calls))

    def test_progress(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            src = os.path.join(temp_dir, "src.img")
            dst = os.path.join(temp_dir, "dst.img")
            self._write(src, os.urandom(5 << 20))
            first = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000021")
            second = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000022")

            calls = []
            first.create_from_file(src, width=1, progress=calls.append)
            self._assert_progress(calls)

            calls = []
            first.export(dst, progress=calls.append)
            self._assert_progress(calls)

            calls = []
            second.create_from(first, width=1, progress=calls.append)
            self._assert_progress(calls)

            second.remove()
            first.remove()

    def test_progress_of_empty_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            src = os.path.join(temp_dir, "src.img")
            self._write(src, b"")
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000023")

            calls = []
            target.create_from_file(
                src, width=1, size=4096, progress=calls.append)

            self.assertEqual(calls[-1], 100)
            self.assertEqual(calls, sorted(set(calls)))
            target.remove()

    def test_progress_failure_is_not_reported_as_100(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000024")

            calls = []
            with self.assertRaises(FileNotFoundError):
                target.export(
                    os.path.join(temp_dir, "dst.img"), progress=calls.append)
            self.assertNotIn(100, calls)

    def test_progress_exception_is_raised_after_the_operation(self):
        class Boom(Exception):
            pass

        calls = []

        def progress(percent):
            calls.append(percent)
            raise Boom()

        with tempfile.TemporaryDirectory() as temp_dir:
            src = os.path.join(temp_dir, "src.img")
            self._write(src, os.urandom(3 << 20))
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000025")

            with self.assertRaises(Boom):
                target.create_from_file(src, width=1, progress=progress)

            # No further calls once it raised, but the object was made.
            self.assertEqual(calls, [0])
            self.assertEqual(target.spec().size, 3 << 20)
            target.remove()

    def test_progress_must_be_callable(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-000000000026")
            with self.assertRaises(TypeError):
                target.export(os.path.join(temp_dir, "x"), progress=5)

    def test_create_from_missing_object_leaves_nothing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            source = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-00000000001c")
            target = rawstor.Target(
                f"file://{temp_dir}/00000000-0000-0000-0000-00000000001d")

            with self.assertRaises(FileNotFoundError):
                target.create_from(source, width=1)
            with self.assertRaises(FileNotFoundError):
                target.spec()


class TestTargetAccount(unittest.TestCase):
    ACCOUNT = "0197e0a2-7c3b-7d4e-8f10-3a5b6c7d8e9f"
    OBJECT = "0197e0a2-7c3b-7d4e-8f10-000000000001"

    def test_account(self):
        named = rawstor.Target(
            f"ost://{self.ACCOUNT}@10.0.0.1:7777/{self.OBJECT}")
        self.assertEqual(named.account, self.ACCOUNT)

        plain = rawstor.Target(f"ost://10.0.0.1:7777/{self.OBJECT}")
        self.assertEqual(plain.account, rawstor.DEFAULT_ACCOUNT)

    def test_account_of_mirrors(self):
        mirrors = rawstor.Target(
            f"ost://{self.ACCOUNT}@10.0.0.1:7777/{self.OBJECT},"
            f"ost://{self.ACCOUNT}@10.0.0.2:7777/{self.OBJECT}")
        self.assertEqual(mirrors.account, self.ACCOUNT)

        split = rawstor.Target(
            f"ost://{self.ACCOUNT}@10.0.0.1:7777/{self.OBJECT},"
            f"ost://10.0.0.2:7777/{self.OBJECT}")
        with self.assertRaises(OSError) as error:
            split.account
        self.assertEqual(error.exception.errno, errno.EINVAL)

    def test_account_that_is_not_a_uuid(self):
        target = rawstor.Target(f"ost://acme@10.0.0.1:7777/{self.OBJECT}")
        with self.assertRaises(OSError) as error:
            target.account
        self.assertEqual(error.exception.errno, errno.EINVAL)
