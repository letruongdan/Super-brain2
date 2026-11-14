"""One original commit-deadline case with metadata observations and unchanged assertions."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import pytest

NODE = ('tests/integration/test_kernel_receipts.py::'
        'test_writable_shim_observes_commit_unknown_before_release')
CASE_NAME = NODE.rsplit('::', 1)[1]
UNKNOWN = 'commit_outcome_unknown'


def error_code(value: object) -> str | None:
    if not isinstance(value, dict):
        return None
    error = value.get('error')
    if isinstance(error, dict) and isinstance(error.get('code'), str):
        return error['code']
    result = value.get('result')
    if not isinstance(result, dict):
        return None
    structured = result.get('structuredContent')
    if not isinstance(structured, dict):
        return None
    error = structured.get('error')
    return error.get('code') if isinstance(error, dict) and isinstance(error.get('code'), str) else None


class Trace:
    def __init__(self) -> None:
        self.patch = pytest.MonkeyPatch()
        self.frames: list[Any] = []
        self.receive: list[dict[str, int]] = []
        self.callback_delivery: list[dict[str, object]] = []
        self.parent_return: list[int] = []
        self.original_assertion: dict[str, int | float] = {}
        self.capture_errors: list[str] = []
        self.call_outcome: str | None = None

    def pytest_runtest_call(self, item: Any) -> None:
        assert item.nodeid == NODE
        module = item.module
        original_hooks = module.DaemonTestHooks
        original_recorders = module.record_sends_by_connection
        original_exchange = module.InstalledMcpPipeSession.send_frames_and_expect_response

        def hooks(*args: Any, **kwargs: Any) -> Any:
            after_reserve = kwargs.get('after_reserve_before_enqueue')

            def reserved(reservation: Any) -> None:
                deadlines = reservation.deadlines
                self.receive.append(dict(receive_ns=deadlines.receive_ns,
                                         handler_deadline_ns=deadlines.handler_deadline_ns,
                                         commit_waiter_cutoff_ns=deadlines.commit_waiter_cutoff_ns))
                callback = reservation._on_response
                if callback is not None:
                    def response(envelope: Any) -> None:
                        observed = time.perf_counter_ns()
                        if error_code(envelope) == UNKNOWN:
                            self.callback_delivery.append(dict(observed_ns=observed,
                                                               thread=threading.current_thread().name))
                        callback(envelope)
                    self.patch.setattr(reservation, '_on_response', response)
                else:
                    self.capture_errors.append('reservation_has_no_response_callback')
                if after_reserve is not None:
                    after_reserve(reservation)

            kwargs['after_reserve_before_enqueue'] = reserved
            return original_hooks(*args, **kwargs)

        def recorders() -> Any:
            record, frames_done = original_recorders()
            self.frames.append(frames_done)
            return record, frames_done

        def exchange(session: Any, *args: Any, **kwargs: Any) -> Any:
            reply = original_exchange(session, *args, **kwargs)
            observed = time.perf_counter_ns()
            if error_code(reply) == UNKNOWN:
                self.parent_return.append(observed)
            return reply

        self.patch.setattr(module, 'DaemonTestHooks', hooks)
        self.patch.setattr(module, 'record_sends_by_connection', recorders)
        self.patch.setattr(module.InstalledMcpPipeSession, 'send_frames_and_expect_response', exchange)

    @pytest.hookimpl(hookwrapper=True)
    def pytest_runtest_makereport(self, item: Any, call: Any) -> Any:
        outcome = yield
        report = outcome.get_result()
        if item.nodeid != NODE or call.when != 'call':
            return
        self.call_outcome = report.outcome
        if call.excinfo is not None:
            traceback = call.excinfo.value.__traceback__
            while traceback is not None:
                frame = traceback.tb_frame
                if frame.f_code.co_name == CASE_NAME:
                    for name in ('t0', 'arrived_ns', 'arrival_ms', 'flush_ms'):
                        value = frame.f_locals.get(name)
                        if type(value) in (int, float):
                            self.original_assertion[name] = value
                traceback = traceback.tb_next

    def summary(self) -> dict[str, object]:
        flushed: list[int] = []
        for read_frames in self.frames:
            try:
                flushed.extend(read_frames(UNKNOWN.encode()))
            except (AssertionError, TypeError, ValueError, StopIteration) as error:
                self.capture_errors.append('frame_reader_'+type(error).__name__)
        first = self.receive[0]['receive_ns'] if self.receive else None

        def relative(value: int) -> float | None:
            return None if first is None else (value-first)/1_000_000

        return dict(case_outcome=self.call_outcome, reservations=self.receive,
                    response_callback=self.callback_delivery,
                    complete_http_unknown_flush_ns=flushed,
                    parent_original_method_return_ns=self.parent_return,
                    original_failing_assertion=self.original_assertion,
                    relative_ms=dict(callback=[relative(int(row['observed_ns'])) for row in self.callback_delivery],
                                     complete_http_flush=[relative(value) for value in flushed],
                                     parent_method_return=[relative(value) for value in self.parent_return]),
                    capture_errors=self.capture_errors)


def pin(source: str, expected: str) -> dict[str, object]:
    assert subprocess.check_output(['git','rev-parse','HEAD'], text=True, timeout=10).strip() == source
    assert not subprocess.check_output(['git','status','--porcelain'], text=True, timeout=10).strip()
    raw = subprocess.check_output([sys.executable,'.verification/test_lock.py','check','--root','.',
                                   '--manifest','.verification/task9-seal.json','--expected-digest',expected],timeout=10)
    return json.loads(raw)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--basetemp', type=Path, required=True)
    parser.add_argument('--cache-dir', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--seal-digest', required=True)
    args = parser.parse_args()
    for target in (args.output,args.basetemp,args.cache_dir):
        if target.exists():
            raise RuntimeError('Prior diagnostic directories must be inspected first')
    trusted_temp = Path(tempfile.gettempdir()).resolve()
    assert args.basetemp.resolve().is_relative_to(trusted_temp)
    assert args.cache_dir.resolve().is_relative_to(trusted_temp)
    args.output.mkdir(parents=True)
    before = pin(args.source_commit,args.seal_digest)
    state: dict[str, object] = dict(diagnostic_only=True, source=args.source_commit,
                                   expected_seal=args.seal_digest, before=before, pid=os.getpid(),
                                   started_unix=time.time(), node=NODE,
                                   probe_digest='sha256:'+hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    (args.output/'start.json').write_text(json.dumps(state,indent=2),encoding='utf-8')
    trace = Trace()
    code = 99
    try:
        code = int(pytest.main(['-q',NODE,'--basetemp='+str(args.basetemp),
                               '-o','cache_dir='+str(args.cache_dir),
                               '--junitxml='+str(args.output/'junit.xml')],plugins=[trace]))
    finally:
        diagnostic_exit = code
        trace.patch.undo()
        state.update(trace.summary())
        state.update(pytest_exit=code,ended_unix=time.time())
        try:
            state['after'] = pin(args.source_commit,args.seal_digest)
        except (AssertionError, subprocess.SubprocessError, OSError, json.JSONDecodeError) as error:
            state['after_error_type'] = type(error).__name__
            diagnostic_exit = code or 2
        state['diagnostic_exit'] = diagnostic_exit
        (args.output/'receipt.json').write_text(json.dumps(state,indent=2),encoding='utf-8')
    print(json.dumps(dict(diagnostic_only=True,pytest_exit=code,diagnostic_exit=diagnostic_exit,
                         receipt=str(args.output/'receipt.json'))))
    return diagnostic_exit


if __name__ == '__main__':
    raise SystemExit(main())
