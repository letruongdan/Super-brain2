"""One bounded, instrumented original storage case; diagnostic, never acceptance.

The parent verifies the sealed source before/after. The child keeps all assertions and durability/security
calls, timing real underlying calls without recording SQL text, parameters, SIDs or credential values.
"""
from __future__ import annotations

import argparse
import contextlib
import datetime
import functools
import hashlib
import json
import os
import platform
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

PIN = '83183d1954eca293150c607a1bdbb3cb3832ba3a'
SEAL = 'sha256:a82fe46340eba7ff4186400d9eeff14eb9013d22e809e76556cfc33be940ac0d'
CASES = {
    'canary': 'tests/storage/test_kernel_idempotency.py::test_canary_privacy_scan_across_commit_rollback_and_retry',
    'migration': 'tests/storage/test_kernel_migration.py::test_two_target_orchestration_with_injected_sequences_and_noop',
    'upgrade_restore': 'tests/storage/test_kernel_idempotency.py::test_store3_to_store4_migration_min_reader_fence_and_backup_restore',
    'volumes': None,
}


def digest(raw: bytes) -> str:
    return 'sha256:' + hashlib.sha256(raw).hexdigest()


def pin() -> dict:
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == PIN
    assert not subprocess.check_output(['git', 'status', '--porcelain'], text=True).strip()
    run = subprocess.run([sys.executable, '.verification/test_lock.py', 'check', '--root', '.',
                          '--manifest', '.verification/task9-seal.json', '--expected-digest', SEAL],
                         capture_output=True, text=True, check=True)
    return json.loads(run.stdout)


def worker(args: argparse.Namespace) -> int:
    import pytest
    import win32security
    from superbrain.adapters.os import durable, paths

    stats: dict[str, dict[str, int]] = {}
    rows_lock = threading.Lock()
    local = threading.local()
    patches = pytest.MonkeyPatch()
    errors: list[str] = []
    volumes: list[dict] = []

    @contextlib.contextmanager
    def span(label: str):
        stack = getattr(local, 'stack', None)
        if stack is None:
            local.stack = stack = []
        frame = [time.perf_counter_ns(), time.thread_time_ns(), 0]
        stack.append(frame)
        try:
            yield
        finally:
            wall = time.perf_counter_ns() - frame[0]
            cpu = time.thread_time_ns() - frame[1]
            stack.pop()
            if stack:
                stack[-1][2] += wall
            with rows_lock:
                row = stats.setdefault(label, {'count': 0, 'wall_ns': 0, 'thread_cpu_ns': 0,
                                               'exclusive_wall_ns': 0, 'max_wall_ns': 0})
                row['count'] += 1
                row['wall_ns'] += wall
                row['thread_cpu_ns'] += cpu
                row['exclusive_wall_ns'] += max(0, wall - frame[2])
                row['max_wall_ns'] = max(row['max_wall_ns'], wall)

    def wrap(target, name: str, label: str):
        original = getattr(target, name)
        @functools.wraps(original)
        def call(*a, **kw):
            with span(label):
                return original(*a, **kw)
        patches.setattr(target, name, call)

    # Patch below identity-guarded permission helpers. Wrapping _security_descriptor would force their
    # compatibility fallback and introduce a second read that the actual product does not perform.
    wrap(win32security, 'GetNamedSecurityInfo', 'win32.GetNamedSecurityInfo')
    wrap(win32security, 'SetNamedSecurityInfo', 'win32.SetNamedSecurityInfo')
    wrap(os, 'fsync', 'os.fsync')
    wrap(os, 'lstat', 'os.lstat')
    wrap(durable, '_move_file_ex', 'win32.MoveFileEx.write_through')
    wrap(paths.OsPathSafety, 'reject_links', 'path.reject_links')
    wrap(subprocess.Popen, '__init__', 'subprocess.Popen.init')

    original_connect = sqlite3.connect
    class TimedConnection(sqlite3.Connection):
        def execute(self, sql, parameters=(), /):
            # First keyword only: never retain full SQL, literals or bound values.
            verb = sql.lstrip().split(None, 1)[0].upper() if isinstance(sql, str) and sql.strip() else 'UNKNOWN'
            category = verb if verb in {'BEGIN', 'COMMIT', 'ROLLBACK', 'PRAGMA', 'SELECT', 'INSERT',
                                        'UPDATE', 'DELETE', 'CREATE', 'ALTER', 'DROP', 'SAVEPOINT', 'RELEASE'} else 'OTHER'
            with span('sqlite.execute.' + category):
                return super().execute(sql, parameters)
        def commit(self):
            with span('sqlite.commit'):
                return super().commit()
        def rollback(self):
            with span('sqlite.rollback'):
                return super().rollback()
        def close(self):
            with span('sqlite.close'):
                return super().close()

    def connect(*a, **kw):
        if 'factory' in kw:
            errors.append('caller_supplied_factory_not_replaced')
        else:
            kw['factory'] = TimedConnection
        with span('sqlite.connect'):
            return original_connect(*a, **kw)
    patches.setattr(sqlite3, 'connect', connect)
    started = time.perf_counter_ns()
    cpu = time.process_time_ns()
    code = 99
    try:
        if args.case == 'volumes':
            from superbrain.adapters.os import os_adapters
            from superbrain.storage.sqlite import connect as open_database
            adapters = os_adapters()
            payload = b'superbrain-synthetic-storage-profile\n' * 100
            for role, value in [('LOCALAPPDATA', os.environ.get('LOCALAPPDATA')),
                                ('RUNNER_TEMP', os.environ.get('RUNNER_TEMP'))]:
                row = {'role': role, 'iterations': 5}
                volumes.append(row)
                if not value:
                    row['status'] = 'environment_variable_missing'
                    continue
                base = Path(value)
                row['drive'] = base.drive
                adapters.paths.reject_links(base)
                if not base.is_dir():
                    row['status'] = 'base_missing'
                    continue
                if adapters.permissions.check_ancestors(base):
                    row['status'] = 'ancestor_policy_refused'
                    continue
                root = base / ('superbrain-profile-' + uuid.uuid4().hex)
                root.mkdir()
                adapters.permissions.secure_directory(root)
                assert not adapters.permissions.object_problems(root)
                assert not adapters.permissions.check_ancestors(root)
                info = durable.detect_fs(root)
                row.update(fs_type=info.fs_type, remote=info.remote, profile_root=str(root),
                           status='owner_secured_new_synthetic_directory')
                start = time.perf_counter_ns()
                for index in range(5):
                    staging, final = root / f'write-{index}.tmp', root / f'write-{index}.bin'
                    adapters.paths.reject_links(root)
                    adapters.publisher.write_new(staging, payload)
                    adapters.permissions.secure_file(staging)
                    assert not adapters.permissions.object_problems(staging)
                    adapters.publisher.publish(staging, final)
                    adapters.publisher.sync_directory(root)
                    assert final.read_bytes() == payload
                row['atomic_write_5_wall_ns'] = time.perf_counter_ns() - start
                db = open_database(root / 'sample.db', traits=adapters.traits)
                try:
                    db.execute('CREATE TABLE synthetic_sample(n INTEGER PRIMARY KEY, payload BLOB NOT NULL)')
                    start = time.perf_counter_ns()
                    for index in range(5):
                        db.execute('BEGIN IMMEDIATE')
                        db.execute('INSERT INTO synthetic_sample VALUES (?, ?)', (index, payload))
                        db.execute('COMMIT')
                    row['sqlite_full_wal_commit_5_wall_ns'] = time.perf_counter_ns() - start
                    assert db.execute('SELECT count(*) FROM synthetic_sample').fetchone()[0] == 5
                    assert all(value[0] == payload for value in db.execute('SELECT payload FROM synthetic_sample'))
                finally:
                    db.close()
                row['status'] = 'measured'
            code = 0
        else:
            code = int(pytest.main(['-q', CASES[args.case], '--basetemp='+str(args.basetemp),
                                    '-o', 'cache_dir='+str(args.cache_dir),
                                    '--junitxml='+str(args.output/'junit.xml')]))
    finally:
        patches.undo()
        (args.output/'worker-receipt.json').write_text(json.dumps({
            'diagnostic_only': True, 'source': PIN, 'case': args.case, 'node': CASES[args.case],
            'pid': os.getpid(), 'pytest_exit': code, 'wall_ns': time.perf_counter_ns()-started,
            'process_cpu_ns': time.process_time_ns()-cpu, 'spans': stats, 'volumes': volumes,
            'coverage_gaps': sorted(set(errors)),
            'limitations': ['Timings include wrapper overhead; this is not an acceptance receipt.',
                            'SQLite C-level fsync bypasses Python os.fsync; SQLite statement times include its I/O.',
                            'thread_cpu_ns is inclusive; do not sum nested rows as exclusive costs.',
                            'Subprocess constructor timing excludes child CPU/lifetime.'],
        }, indent=2), encoding='utf-8')
    return code


def main() -> int:
    global PIN, SEAL
    parser = argparse.ArgumentParser()
    parser.add_argument('case', choices=CASES)
    parser.add_argument('--source-commit', default=PIN)
    parser.add_argument('--seal-digest', default=SEAL)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--basetemp', type=Path, required=True)
    parser.add_argument('--cache-dir', type=Path, required=True)
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    PIN, SEAL = args.source_commit, args.seal_digest
    if sys.platform != 'win32':
        raise SystemExit('This diagnostic is Windows-only')
    if args.worker:
        return worker(args)
    for dest in (args.output, args.basetemp, args.cache_dir):
        if dest.exists():
            raise SystemExit('Refusing to replace existing diagnostic evidence')
    trusted = Path(os.environ['TEMP']).resolve()
    assert args.basetemp.resolve().is_relative_to(trusted)
    assert args.cache_dir.resolve().is_relative_to(trusted)
    before = pin()
    args.output.mkdir(parents=True)
    state = {'diagnostic_only': True, 'source': PIN, 'seal_digest': SEAL, 'case': args.case,
             'pid': os.getpid(), 'started_at': datetime.datetime.now(datetime.UTC).isoformat(),
             'python': sys.version, 'executable': sys.executable, 'platform': platform.platform(),
             'cpu_count': os.cpu_count(), 'before': before,
             'probe_digest': digest(Path(__file__).read_bytes()), 'child_timeout_s': 60}
    (args.output/'start.json').write_text(json.dumps(state, indent=2), encoding='utf-8')
    command = [sys.executable, str(Path(__file__).resolve()), args.case, '--worker', '--output', str(args.output),
               '--basetemp', str(args.basetemp), '--cache-dir', str(args.cache_dir),
               '--source-commit', PIN, '--seal-digest', SEAL]
    code = 99
    try:
        with (args.output/'worker.log').open('w', encoding='utf-8') as log:
            child = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            state['child_pid'] = child.pid
            (args.output/'start.json').write_text(json.dumps(state, indent=2), encoding='utf-8')
            try:
                code = child.wait(timeout=60)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
                code = 124
                state['status'] = 'diagnostic_child_timeout'
    finally:
        state['child_exit'] = code
        state['ended_at'] = datetime.datetime.now(datetime.UTC).isoformat()
        state['after'] = pin()
        (args.output/'receipt.json').write_text(json.dumps(state, indent=2), encoding='utf-8')
    print(json.dumps({'diagnostic_only': True, 'case': args.case, 'exit': code,
                      'receipt': str(args.output/'receipt.json')}))
    return int(code)


if __name__ == '__main__':
    raise SystemExit(main())
