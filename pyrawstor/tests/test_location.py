import rawstor

import errno
from pathlib import Path
import unittest
import tempfile


class TestLocation(unittest.TestCase):
    def test_create(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")

            target = location.create(size=1 << 20, width=1)

            read_targets = list(location.objects())
            self.assertEqual(read_targets, [target])

            target.remove()

    def test_create_from_file_and_from_object(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}/store")
            Path(f"{temp_dir}/store").mkdir()
            data = bytes(range(256)) * 5000
            Path(f"{temp_dir}/in.img").write_bytes(data)

            calls = []
            target = location.create_from_file(
                f"{temp_dir}/in.img", width=1, progress=calls.append)
            self.assertEqual(calls[-1], 100)
            self.assertEqual(calls, sorted(set(calls)))
            self.assertEqual(target.spec().size, len(data))
            target.export(f"{temp_dir}/out.img")
            self.assertEqual(Path(f"{temp_dir}/out.img").read_bytes(), data)

            copy = location.create_from(target, width=1)
            self.assertNotEqual(copy, target)
            copy.export(f"{temp_dir}/copy.img")
            self.assertEqual(Path(f"{temp_dir}/copy.img").read_bytes(), data)

            self.assertEqual(
                sorted(t.uri for t in location.objects()),
                sorted([target.uri, copy.uri]))
            copy.remove()
            target.remove()

    def test_create_from_file_with_uuid(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")
            Path(f"{temp_dir}/in.img").write_bytes(b"x" * 4096)
            uuid = "00000000-0000-7000-8000-00000000000a"

            target = location.create_from_file(
                f"{temp_dir}/in.img", width=1, uuid=uuid)

            self.assertIn(uuid, target.uri)
            target.remove()

    def test_create_from_file_missing_source(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")

            with self.assertRaises(FileNotFoundError):
                location.create_from_file(
                    f"{temp_dir}/missing.img", width=1)
            self.assertEqual(list(location.objects()), [])

    def test_empty(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")
            targets = list(location.objects())
            self.assertEqual(targets, [])

    def test_objects(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")

            targets = []
            for _ in range(10):
                target = location.create(size=1 << 20, width=1)
                targets.append(target)
            targets.sort()

            read_targets = list(location.objects())
            self.assertEqual(read_targets, targets)

            for target in targets:
                target.remove()

    def test_not_found(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}_not_found")
            self.assertRaises(FileNotFoundError, lambda: list(location.objects()))

    def test_info(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")

            info = location.info()
            self.assertEqual(info.used, 0)
            self.assertGreater(info.total, 0)

            target = location.create(size=1 << 20, width=1)

            info = location.info()
            stored_size = sum(
                path.stat().st_size
                for path in Path(temp_dir).rglob("*")
                if path.is_file()
            )
            self.assertGreater(stored_size, 1 << 20)
            self.assertEqual(info.used, stored_size)

            target.remove()
            self.assertEqual(location.info().used, 0)

    # file:// keeps no placement policy of its own; see
    # TestTarget.test_create_failure_domain_reaches_library.
    def test_create_failure_domain(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")

            with self.assertRaises(OSError) as cm:
                location.create(size=1 << 20, width=1, failure_domain=256)
            self.assertEqual(cm.exception.errno, errno.EINVAL)

            target = location.create(
                size=1 << 20, width=1, failure_domain="server")
            self.assertEqual(list(location.objects()), [target])

            target.remove()

class TestWitnessLocation(unittest.TestCase):
    def test_plain_uris_and_metadata_discovery(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            paths = [stack.enter_context(tempfile.TemporaryDirectory())
                     for _ in range(3)]
            location = rawstor.Location(
                ','.join(f'file://{path}' for path in paths))
            target = location.create(size=65536, width=2)
            self.assertNotIn('witness+', target.uri)
            self.assertFalse(hasattr(target.spec(), 'witness_member'))
            self.assertEqual(target.spec().width, 2)

            metadata = target.meta()
            self.assertEqual([member.member_role for member in metadata],
                             [rawstor.MEMBER_DATA, rawstor.MEMBER_DATA,
                              rawstor.MEMBER_WITNESS])
            self.assertEqual(metadata[2].size, 65536)
            self.assertEqual(list(location.objects()), [target])
            target.remove()
            self.assertEqual(list(location.objects()), [])

    def test_odd_data_count_is_rejected(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            paths = [stack.enter_context(tempfile.TemporaryDirectory())
                     for _ in range(4)]
            location = rawstor.Location(
                ','.join(f'file://{path}' for path in paths))
            with self.assertRaises(OSError) as error:
                location.create(size=65536, width=3)
            self.assertEqual(error.exception.errno, errno.EINVAL)


class TestAccounts(unittest.TestCase):
    ACCOUNT = "0197e0a2-7c3b-7d4e-8f10-3a5b6c7d8e9f"
    OTHER = "0197e0a2-7c3b-7d4e-8f10-3a5b6c7d8ea0"

    def test_the_registry_is_the_mds(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")
            for call in (
                    lambda: list(location.accounts()),
                    lambda: location.create_account(self.ACCOUNT),
                    lambda: location.remove_account(self.ACCOUNT)):
                with self.assertRaises(OSError) as error:
                    call()
                self.assertEqual(error.exception.errno, errno.ENOTSUP)

    def test_an_object_has_the_account_of_its_location(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{self.ACCOUNT}@{temp_dir}")

            target = location.create(size=1 << 20, width=1)

            self.assertEqual(target.account, self.ACCOUNT)
            self.assertIn(f"{self.ACCOUNT}@", target.uri)
            [meta] = target.meta()
            self.assertEqual(meta.account, self.ACCOUNT)

    def test_the_default_account_is_not_named(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            location = rawstor.Location(f"file://{temp_dir}")

            target = location.create(size=1 << 20, width=1)

            self.assertNotIn("@", target.uri)
            self.assertEqual(target.account, rawstor.DEFAULT_ACCOUNT)
            [meta] = target.meta()
            self.assertEqual(meta.account, rawstor.DEFAULT_ACCOUNT)

    def test_a_location_lists_the_objects_of_its_account(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            acme = rawstor.Location(f"file://{self.ACCOUNT}@{temp_dir}")
            other = rawstor.Location(f"file://{self.OTHER}@{temp_dir}")
            nobody = rawstor.Location(f"file://{temp_dir}")
            owned = acme.create(size=1 << 20, width=1)
            foreign = other.create(size=1 << 20, width=1)
            fallback = nobody.create(size=1 << 20, width=1)

            self.assertEqual(list(acme.objects()), [owned])
            self.assertEqual(list(other.objects()), [foreign])
            # The administrator sees every object, each target naming its
            # own owner.
            listed = sorted(nobody.objects(), key=lambda target: target.account)
            self.assertEqual(
                sorted(target.account for target in listed),
                sorted([self.ACCOUNT, self.OTHER, rawstor.DEFAULT_ACCOUNT]))
            self.assertEqual(
                sorted(listed), sorted([owned, foreign, fallback]))


class TestInitialization(unittest.TestCase):
    def run_python(self, code, tls=None):
        import os
        import subprocess
        import sys

        env = {k: v for k, v in os.environ.items()
               if not k.startswith("RAWSTOR_TLS_")}
        env.update(tls or {})
        result = subprocess.run([sys.executable, "-c", code], env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_invalid_mode(self):
        self.run_python("""
import rawstor
try:
    rawstor.initialize(insecure='false')
except TypeError:
    pass
else:
    raise AssertionError('accepted a non-boolean mode')
rawstor.initialize(insecure=True)
""")

    def test_insecure_without_certificates(self):
        self.run_python("""
import rawstor, tempfile
rawstor.initialize(insecure=True)
rawstor.initialize(insecure=True)
with tempfile.TemporaryDirectory() as directory:
    location = rawstor.Location('file://' + directory)
    target = location.create(size=1 << 20, width=1)
    assert list(location.objects()) == [target]
    target.remove()
try:
    rawstor.initialize()
except RuntimeError:
    pass
else:
    raise AssertionError('TLS mode changed')
""")

    def test_tls_required_and_retry(self):
        self.run_python("""
import rawstor
try:
    rawstor.Location
except RuntimeError:
    pass
else:
    raise AssertionError('accepted missing TLS credentials')
rawstor.initialize(insecure=True)
assert rawstor.Location
""")

    def test_insecure_rejects_tls_settings(self):
        self.run_python("""
import rawstor
try:
    rawstor.initialize(insecure=True)
except RuntimeError:
    pass
else:
    raise AssertionError('accepted TLS settings with insecure')
""", {"RAWSTOR_TLS_CA": "/nonexistent/ca.crt"})

    def test_initialized_tls_cannot_change(self):
        import os
        self.run_python("""
import rawstor
assert rawstor.Target
rawstor.initialize()
try:
    rawstor.initialize(insecure=True)
except RuntimeError:
    pass
else:
    raise AssertionError('TLS mode changed')
""", {k: v for k, v in os.environ.items()
      if k.startswith("RAWSTOR_TLS_")})


    def test_concurrent_explicit_modes(self):
        self.run_python("""
import importlib
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import rawstor

original_import = importlib.import_module
ready = threading.Barrier(2)

def simultaneous_import(name, package=None):
    if name == '.librawstor' and package == 'rawstor':
        ready.wait(timeout=10)
    return original_import(name, package)

def initialize(insecure):
    try:
        rawstor.initialize(insecure=insecure)
    except RuntimeError:
        return False
    return True

with patch.object(importlib, 'import_module', simultaneous_import):
    with ThreadPoolExecutor(max_workers=2) as pool:
        secure = pool.submit(initialize, False)
        insecure = pool.submit(initialize, True)
        assert not secure.result(timeout=10), 'secure call accepted insecure mode'
        assert insecure.result(timeout=10), 'insecure initialization failed'
rawstor.initialize(insecure=True)
""")

    def test_concurrent_implicit_initialization(self):
        for expression in (
            'rawstor.Location',
            'rawstor.Target',
            "importlib.import_module('rawstor.location')",
            "importlib.import_module('rawstor.target')",
            "importlib.import_module('rawstor.librawstor')",
        ):
            with self.subTest(expression=expression):
                self.run_python("""
import importlib
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
import rawstor

original_import = importlib.import_module
ready = threading.Event()
release = threading.Event()

def delayed_import(name, package=None):
    if name == '.librawstor' and package == 'rawstor':
        ready.set()
        assert release.wait(timeout=10)
    return original_import(name, package)

with patch.object(importlib, 'import_module', delayed_import):
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(rawstor.initialize, insecure=True)
        try:
            assert ready.wait(timeout=10)
            try:
                """ + expression + """
            except RuntimeError:
                pass
            else:
                raise AssertionError('implicit import used another thread TLS mode')
        finally:
            release.set()
        pending.result(timeout=10)
rawstor.initialize(insecure=True)
assert rawstor.Location
""")
