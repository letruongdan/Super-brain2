"""Oracle tests for ``tests/support/init_clone.py::init_store_cloned``."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.composition._init_recovery import compute_init_request_digest
from tests.support import rereview_1d666f5 as rr
from tests.support.clock import FakeClock
from tests.support.init_clone import init_store_cloned


def test_init_store_cloned_isolates_distinct_signers_and_rewrites_db_metadata(trusted_tmp: Path) -> None:
    clock = FakeClock(datetime(2026, 11, 20, 12, 0, tzinfo=UTC))
    os_ = os_adapters(clock=clock)
    signer_a = rr.ssh_enrollment("signer-a", "dan")
    signer_b = rr.ssh_enrollment("signer-b", "dan")
    assert signer_a.key_digest != signer_b.key_digest

    clones = [
        ("a", signer_a, trusted_tmp / "a" / "data", trusted_tmp / "a" / "cfg"),
        ("b", signer_b, trusted_tmp / "b" / "data", trusted_tmp / "b" / "cfg"),
        ("a2", signer_a, trusted_tmp / "a2" / "data", trusted_tmp / "a2" / "cfg"),
    ]

    reports = []
    for _tag, exp_signer, data_x, cfg_x in clones:
        cfg_x.mkdir(parents=True, exist_ok=True)
        os_.permissions.secure_directory(cfg_x)
        rep = init_store_cloned(
            os_,
            data_root=data_x,
            cfg_dir=cfg_x,
            owner_id="dan",
            machine_id="same-box",
            signer=exp_signer,
        )
        reports.append(rep)

        assert rep.signer.key_digest == exp_signer.key_digest

        db_path = data_x / "policy" / "policy.db"
        assert db_path.is_file()
        with closing(sqlite3.connect(f"file:{db_path.resolve().as_posix()}?mode=ro", uri=True)) as conn:
            row = conn.execute(
                "SELECT channel, owner_id, key_digest, credential_id FROM signer WHERE revoked_at IS NULL"
            ).fetchone()
            assert row is not None
            assert row[0] == exp_signer.channel.value
            assert row[1] == exp_signer.owner_id
            assert row[2] == exp_signer.key_digest
            assert (row[3] or "") == (exp_signer.credential_id or "")

            meta_row = conn.execute("SELECT value FROM meta WHERE key = 'init_bootstrap_state'").fetchone()
            assert meta_row is not None
            meta_state = json.loads(meta_row[0])
            assert meta_state["status"] == "completed"
            assert meta_state["config_dir"] == os.path.abspath(cfg_x)
            expected_digest = compute_init_request_digest(
                owner_id="dan", machine_id="same-box", signer=exp_signer, config_dir=cfg_x
            )
            assert meta_state["request_digest"] == expected_digest

        d_cfg = read_daemon_config(cfg_x / "daemon.json", os_)
        assert Path(d_cfg.data_root) == data_x.resolve()
        assert d_cfg.expected_store_id == rep.store_id
        assert Path(d_cfg.cert_path) == (cfg_x / "tls" / "server.pem").resolve()
        assert (cfg_x / "tls" / "ca.pem").is_file()

    rep_a, rep_b, rep_a2 = reports
    assert rep_a.signer.key_digest != rep_b.signer.key_digest
    assert rep_a.signer.key_digest == rep_a2.signer.key_digest
