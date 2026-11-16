#!/usr/bin/env python3
"""End-to-end authorization with real daemons, TLS certificates and CLI clients.

Run from a configured build tree: python3 /source/tests/security_authorization.py .
Requires built OST/MDS/CLI and OpenSSL; no Python rawstor installation is needed.
"""
from contextlib import ExitStack
import ctypes
import errno
import json
import os
from pathlib import Path
import socket
import signal
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import uuid

MAGIC = 0x72737472
HEAD = struct.Struct('<IHH')
RESPONSE = struct.Struct('<IHHQi')


def receive(connection, size):
    result = b''
    while len(result) < size:
        data = connection.recv(size - len(result))
        if not data:
            raise AssertionError('truncated response')
        result += data
    return result


def request(connection, command, payload=b''):
    connection.sendall(HEAD.pack(MAGIC, command, 1) + payload)
    magic, reply, cid, _, result = RESPONSE.unpack(receive(connection, RESPONSE.size))
    assert (magic, reply, cid) == (MAGIC, command, 1)
    return result, receive(connection, result) if result > 0 else b''


def free_port():
    with socket.socket() as connection:
        connection.bind(('127.0.0.1', 0))
        return connection.getsockname()[1]


def connection_probe(root, target, settings, readonly=False, renew=None):
    # Exercise repeated IO on a single authenticated C API handle.
    os.environ.update(settings)
    library = ctypes.CDLL(str(root / ('src/.libs/librawstor.dylib' if sys.platform == 'darwin' else 'src/.libs/librawstor.so')))
    pointer = ctypes.c_void_p
    completion = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_ssize_t, pointer)
    io_completion = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_size_t, ctypes.c_int, pointer)
    library.rawstor_initialize.argtypes = [pointer]
    library.rawio_queue_create.argtypes = [ctypes.c_uint, ctypes.POINTER(pointer)]
    library.rawio_queue_delete.argtypes = [pointer]
    library.rawio_wait_timeout.argtypes = [pointer, ctypes.c_uint]
    library.rawstor_target_open.argtypes = [pointer, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(pointer), completion, pointer]
    library.rawstor_object_close.argtypes = [pointer, completion, pointer]
    library.rawstor_object_pread.argtypes = [pointer, pointer, ctypes.c_size_t, ctypes.c_uint64, io_completion, pointer]
    library.rawstor_object_pwrite.argtypes = [pointer, pointer, ctypes.c_size_t, ctypes.c_uint64, ctypes.c_bool, io_completion, pointer]
    assert library.rawstor_initialize(None) == 0
    queue, obj = pointer(), pointer()
    assert library.rawio_queue_create(128, ctypes.byref(queue)) == 0
    def drive(submit, io=False):
        result = []
        if io:
            @io_completion
            def callback(size, error, data):
                result.append(-error if error else size)
                return 0
        else:
            @completion
            def callback(value, data):
                result.append(value)
                return 0
        immediate = submit(callback)
        assert immediate == 0, immediate
        deadline = time.monotonic() + 15
        while not result:
            assert time.monotonic() < deadline, 'C API callback timed out'
            waited = library.rawio_wait_timeout(queue, 100)
            assert waited >= 0 or waited == -getattr(errno, 'ETIME', errno.ETIMEDOUT), waited
        return result[0]
    try:
        assert drive(lambda cb: library.rawstor_target_open(queue, target.encode(), int(readonly), ctypes.byref(obj), cb, None)) == 0
        data = ctypes.create_string_buffer(b'x' * 4096)
        if readonly:
            assert drive(lambda cb: library.rawstor_object_pread(obj, data, 4096, 0, cb, None), io=True) == 4096
        else:
            assert drive(lambda cb: library.rawstor_object_pwrite(obj, data, 4096, 0, False, cb, None), io=True) == 4096
            if renew:
                renew()
                library.rawstor_tls_request_reload()
                time.sleep(4.1)
            else:
                time.sleep(.1)
            assert drive(lambda cb: library.rawstor_object_pwrite(obj, data, 4096, 0, False, cb, None), io=True) == 4096
        assert drive(lambda cb: library.rawstor_object_close(obj, cb, None)) == 0
    finally:
        library.rawio_queue_delete(queue)
        library.rawstor_terminate()


def main():
    root = Path(sys.argv[1] if len(sys.argv) > 1 else '.').resolve()
    cli = root / 'cli/rawstor'
    processes = []
    files = []
    with tempfile.TemporaryDirectory(prefix='rawstor-authorization-') as temporary, ExitStack() as resources:
        directory = Path(temporary)
        base = {key: value for key, value in os.environ.items() if not key.startswith('RAWSTOR_')}
        def run(arguments, who=None, success=True, default_location=None):
            settings = environment(who) if who else base.copy()
            if default_location is not None:
                settings["RAWSTOR_LOCATION"] = default_location
            result = subprocess.run([str(cli), *map(str, arguments)], env=settings,
                                    text=True, capture_output=True, timeout=30)
            assert (result.returncode == 0) == success, (arguments, result.returncode, result.stdout, result.stderr)
            return result.stdout.strip()
        def environment(who):
            return dict(base, RAWSTOR_TLS_TRUST_DOMAIN='cluster.example',
                        RAWSTOR_TLS_CERT=str(directory / (who + '.crt')),
                        RAWSTOR_TLS_KEY=str(directory / (who + '.key')),
                        RAWSTOR_TLS_CA=str(directory / 'ca/ca.crt'),
                        RAWSTOR_TLS_MDS_ID=mds_id,
                                                                        RAWSTOR_MDS_OPTS_INFO_INTERVAL='100',
                        RAWSTOR_OPTS_IO_ATTEMPTS='1')
        def connect(port, who):
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=directory / 'ca/ca.crt')
            context.check_hostname = False
            # Match rawtls verification: its small CA does not emit AKI/SKI.
            context.verify_flags &= ~ssl.VERIFY_X509_STRICT
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(directory / (who + '.crt'), directory / (who + '.key'))
            connection = context.wrap_socket(socket.create_connection(('127.0.0.1', port), timeout=5))
            result, data = request(connection, 0x07, struct.pack('<Q', 0))
            assert result == 8, (result, data)
            return connection
        def start(arguments, who, port):
            log = resources.enter_context(open(directory / (who + '.log'), 'w+'))
            files.append(log)
            process = subprocess.Popen(list(map(str, arguments)), env=environment(who), stdout=log, stderr=log)
            processes.append(process)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError(log.read())
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.1):
                        return
                except OSError:
                    time.sleep(.05)
            raise AssertionError('daemon did not start')
        try:
            tenant, other, ost_id, mds_id = map(str, [uuid.uuid4() for _ in range(4)])
            run(['pki', 'init', '--trust-domain', 'cluster.example', directory / 'ca'])
            for who, role, name in [('admin', 'admin', 'operator'), ('ost', 'ost', ost_id),
                                    ('mds', 'mds', mds_id), ('manager', 'client', 'manager'),
                                    ('reader', 'client', 'reader'), ('foreign', 'client', 'foreign')]:
                arguments = ['pki', 'issue', '--ca', directory / 'ca', '--cert', directory / (who + '.crt'),
                             '--key', directory / (who + '.key')]
                if role == 'client':
                    arguments += ['--role', 'reader' if who == 'reader' else 'manager', role, other if who == 'foreign' else tenant, name]
                else:
                    arguments += [role, name]
                run(arguments)
            ost_port, mds_port = free_port(), free_port()
            (directory / 'objects').mkdir()
            topology = directory / 'topology.conf'
            topology.write_text(f'{ost_id} ost://127.0.0.1:{ost_port} 100 data,witness dc/row/rack/host\n')
            start([root / 'ost/src/rawstor-ost', '--workers', '1', '--queue-size', '128',
                   '--bind', f'127.0.0.1:{ost_port}', 'file://' + str(directory / 'objects')], 'ost', ost_port)
            start([root / 'mds/src/rawstor-mds', '--workers', '1', '--queue-size', '128', '--bind', f'127.0.0.1:{mds_port}',
                   '--db', directory / 'mds.db', '--topology', topology], 'mds', mds_port)
            location = f'mds://127.0.0.1:{mds_port}'
            for owner in [tenant, other]:
                run(['tenant', 'create', location, '--uuid', owner], 'admin')
            # Wait for the MDS monitor to make the OST available for placement.
            deadline = time.monotonic() + 15
            while True:
                info = json.loads(run(['location', 'info', location, '--format', 'json'], 'admin'))
                if 'total' in str(info) and any(char in str(info) for char in '123456789'):
                    break
                assert time.monotonic() < deadline, info
                time.sleep(.1)
            target = run(['object', 'create', location, '--size', '64K', '--chunk-size', '64K',
                          '--mirrors', '1', '--format', 'value', '--column', 'target'], 'manager')
            object_id = uuid.UUID(target.rsplit('/', 1)[1]).bytes
            # Display only an explicitly selected URI tenant; retain the actual owner column.
            for who in ['reader', 'admin']:
                rows = json.loads(run(['list', '--format', 'json'], who, default_location=location))
                assert len(rows) == 1 and rows[0]['tenant'] == tenant, rows
                assert rows[0]['location'] == location, rows
                assert rows[0]['target'] == location + '/' + str(uuid.UUID(bytes=object_id)), rows
            selected = location.replace('://', '://' + tenant + '@')
            rows = json.loads(run(['list', selected, '--format', 'json'], 'reader'))
            assert rows[0]['location'] == selected, rows
            assert rows[0]['target'] == selected + '/' + str(uuid.UUID(bytes=object_id)), rows
            run(['testio', target, '--block-size', '4K', '--io-depth', '1', '--count', '4'], 'manager')
            connection_probe(root, target, environment('manager'))
            connection_probe(root, target, environment('reader'), readonly=True)
            run(['object', 'show', target], 'reader')
            run(['testio', target, '--block-size', '4K', '--io-depth', '1', '--count', '1'], 'reader', success=False)
            with connect(mds_port, 'foreign') as connection:
                result, _ = request(connection, 0x41, struct.pack('<16sQ16sQ', object_id, 0, bytes(16), 0))
                assert result == -errno.ENOENT, result
            with connect(mds_port, 'reader') as connection:
                result, _ = request(connection, 0x48, bytes(32))
                assert result == -errno.EACCES, result
                result, data = request(connection, 0x41, struct.pack('<16sQ16sQ', object_id, 0, bytes(16), 0))
                assert result > 0, result
            # OST authorizes the same certificate without a token or MDS lookup.
            with connect(ost_port, 'reader') as connection:
                assert request(connection, 0x00, struct.pack('<16s16sQ16sQ', uuid.uuid4().bytes, object_id, 0, bytes(16), 1))[0] == 0
                assert request(connection, 0x01, struct.pack('<QQQIB', 0, 0, 0, 4096, 0))[0] == 4096
                assert request(connection, 0x02, struct.pack('<QQQIB', 0, 0, 0, 0, 0))[0] == -errno.EACCES
            with connect(ost_port, 'foreign') as connection:
                assert request(connection, 0x0c, struct.pack('<16sQ16sQ', object_id, 0, bytes(16), 0))[0] == -errno.ENOENT
                assert request(connection, 0x05, struct.pack('<16sQ16sQ', object_id, 0, bytes(16), 0))[0] == -errno.ENOENT
                allocate = struct.pack('<16s16sQQQBBBB', uuid.UUID(other).bytes, object_id, 0, 65536, 0, 16, 0, 1, 1)
                assert request(connection, 0x04, allocate)[0] == -errno.ENOENT
            with connect(ost_port, 'admin') as connection:
                assert request(connection, 0x02, struct.pack('<QQQIB', 0, 0, 0, 0, 0))[0] == -errno.EACCES
            version = run(['version', 'create', target, '--format', 'value', '--column', 'target'], 'manager')
            connection_probe(root, version, environment('reader'), readonly=True)
            run(['version', 'show', version], 'reader')
            run(['version', 'remove', version], 'reader', success=False)
            run(['version', 'remove', version], 'manager')
            # An even DATA width adds a witness hosted by the MDS itself.
            ost2_id, ost2_port = str(uuid.uuid4()), free_port()
            run(['pki', 'issue', '--ca', directory / 'ca', '--cert', directory / 'ost2.crt',
                 '--key', directory / 'ost2.key', 'ost', ost2_id])
            (directory / 'objects2').mkdir()
            start([root / 'ost/src/rawstor-ost', '--workers', '1', '--queue-size', '128',
                   '--bind', f'127.0.0.1:{ost2_port}', 'file://' + str(directory / 'objects2')], 'ost2', ost2_port)
            topology.write_text(topology.read_text() +
                f'{ost2_id} ost://127.0.0.1:{ost2_port} 100 data,witness dc/row/rack/host2\n' +
                f'{mds_id} ost://127.0.0.1:{mds_port} 100 witness dc/row/rack/host3\n')
            processes[1].send_signal(signal.SIGHUP)
            deadline = time.monotonic() + 10
            while True:
                try:
                    mirror = run(['object', 'create', location, '--size', '64K', '--chunk-size', '64K',
                                  '--mirrors', '2', '--format', 'value', '--column', 'target'], 'manager')
                    break
                except AssertionError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(.1)
            run(['testio', mirror, '--block-size', '4K', '--io-depth', '1', '--count', '2'], 'manager')
            run(['object', 'show', mirror], 'reader')
            run(['object', 'remove', mirror], 'manager')
            # A newly issued policy restricts the object without modifying MDS.
            restricted = ['pki', 'issue', '--ca', directory / 'ca', '--cert', directory / 'restricted.crt',
                          '--key', directory / 'restricted.key', '--role', 'manager',
                          '--object-permissions', str(uuid.UUID(bytes=object_id)) + ':1', 'client', tenant, 'restricted']
            run(restricted)
            info = json.loads(run(['pki', 'show', '--cert', directory / 'restricted.crt', '--format', 'json']))
            assert 'manager' in str(info) and str(uuid.UUID(bytes=object_id)) in str(info), info
            run(['pki', 'renew', '--ca', directory / 'ca', '--cert', directory / 'restricted.crt',
                 '--key', directory / 'restricted.key'])
            renewed = json.loads(run(['pki', 'show', '--cert', directory / 'restricted.crt', '--format', 'json']))
            assert 'manager' in str(renewed) and str(uuid.UUID(bytes=object_id)) in str(renewed), renewed
            run(['object', 'show', target], 'restricted')
            run(['testio', target, '--block-size', '4K', '--io-depth', '1', '--count', '1'], 'restricted', success=False)
            run(['object', 'remove', target], 'restricted', success=False)
            with connect(ost_port, 'restricted') as connection:
                assert request(connection, 0x05, struct.pack('<16sQ16sQ', object_id, 0, bytes(16), 0))[0] == -errno.EACCES
            # A renewed certificate is picked up by reconnecting an open handle.
            run(['pki', 'issue', '--ca', directory / 'ca', '--cert', directory / 'rotating.crt',
                 '--key', directory / 'rotating.key', '--role', 'manager', '--validity', '4s',
                 'client', tenant, 'rotating'])
            def renew_rotating():
                run(['pki', 'renew', '--ca', directory / 'ca', '--cert', directory / 'rotating.crt',
                     '--key', directory / 'rotating.key'])
            settings = environment('rotating')
            settings['RAWSTOR_OPTS_IO_ATTEMPTS'] = '3'
            connection_probe(root, target, settings, renew=renew_rotating)
            # Existing data connections must notice a tenant transfer.
            with connect(ost_port, 'reader') as connection:
                assert request(connection, 0x00, struct.pack('<16s16sQ16sQ', uuid.uuid4().bytes, object_id, 0, bytes(16), 1))[0] == 0
                assert request(connection, 0x01, struct.pack('<QQQIB', 0, 0, 0, 4096, 0))[0] == 4096
                run(['object', 'transfer', target, other], 'admin')
                assert request(connection, 0x01, struct.pack('<QQQIB', 0, 0, 0, 4096, 0))[0] == -errno.ENOENT
                run(['object', 'transfer', target, tenant], 'admin')
                assert request(connection, 0x01, struct.pack('<QQQIB', 0, 0, 0, 4096, 0))[0] == 4096
            # An established connection may not outlive its client certificate.
            run(['pki', 'issue', '--ca', directory / 'ca', '--cert', directory / 'short.crt',
                 '--key', directory / 'short.key', '--role', 'reader', '--validity', '4s',
                 'client', tenant, 'short'])
            with connect(ost_port, 'short') as connection:
                assert request(connection, 0x00, struct.pack('<16s16sQ16sQ', uuid.uuid4().bytes, object_id, 0, bytes(16), 1))[0] == 0
                time.sleep(4.1)
                assert request(connection, 0x01, struct.pack('<QQQIB', 0, 0, 0, 4096, 0))[0] == -errno.EACCES
            # Direct OST access continues while MDS is stopped.
            processes[1].terminate()
            processes[1].wait(timeout=10)
            direct = f'ost://127.0.0.1:{ost_port}/' + str(uuid.UUID(bytes=object_id))
            run(['object', 'show', direct], 'reader')
            run(['testio', direct, '--block-size', '4K', '--io-depth', '1', '--count', '2'], 'manager')
            run(['object', 'remove', direct], 'manager')
            print('Authorization integration: PASS')
        except BaseException:
            for log in files:
                log.flush(); log.seek(0)
                print(log.name, log.read()[-6000:], file=sys.stderr)
            raise
        finally:
            for process in reversed(processes):
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()


if __name__ == '__main__':
    main()
