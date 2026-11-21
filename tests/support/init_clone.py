"""Session-cached ``init_store`` base: one real ``brain init`` run, cloned per test with paths rebased."""

from __future__ import annotations

import dataclasses
import json
import os
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path

from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.composition._init_recovery import compute_init_request_digest
from superbrain.composition.init_entry import InitReport, InitRequest, init_store
from superbrain.core._kernel_approval import SignerEnrollment
from superbrain.ports.os import OsAdapters
from tests.support.inc2_fixture import ensure_template_base
from tests.support.inc2_transport import clone_owner_only_tree, write_daemon_config_file

_CacheKey = tuple[str, str, str, str, str]
_CACHE: dict[_CacheKey, tuple[Path, InitReport]] = {}


def init_store_cloned(
    os_: OsAdapters, *, data_root: Path, cfg_dir: Path, owner_id: str, machine_id: str, signer: SignerEnrollment
) -> InitReport:
    """Like ``init_store`` for fresh ``data_root`` / ``cfg_dir``: clones a cached base and rewrites ``daemon.json``."""
    key: _CacheKey = (owner_id, machine_id, signer.channel.value, signer.key_digest, signer.credential_id or "")
    if key not in _CACHE or not _CACHE[key][0].is_dir():
        root = ensure_template_base() / f"init-clone-{uuid.uuid4().hex}"
        (root / "cfg").mkdir(parents=True)
        os_.permissions.secure_directory(root / "cfg")
        req = InitRequest(
            data_root=root / "data", config_dir=root / "cfg", owner_id=owner_id, machine_id=machine_id, signer=signer
        )
        _CACHE[key] = (root, init_store(req, os_))
    root, tpl = _CACHE[key]
    clone_owner_only_tree(root / "data", data_root)
    clone_owner_only_tree(root / "cfg", cfg_dir)
    raw = json.loads(tpl.daemon_config_path.read_text(encoding="utf-8"))
    rel_cfg = tpl.daemon_config_path.relative_to(root / "cfg")
    (cfg_dir / rel_cfg).unlink()
    write_daemon_config_file(
        cfg_dir / rel_cfg,
        data_root=data_root,
        expected_store_id=tpl.store_id,
        cert_path=cfg_dir / Path(raw["cert_path"]).relative_to(root / "cfg"),
        key_path=cfg_dir / Path(raw["key_path"]).relative_to(root / "cfg"),
        os_=os_,
    )
    req_digest = compute_init_request_digest(
        owner_id=owner_id, machine_id=machine_id, signer=signer, config_dir=cfg_dir
    )
    policy_db = data_root / "policy" / "policy.db"
    conn = sqlite3.connect(policy_db)
    try:
        cur = conn.cursor()
        cur.execute("SELECT value FROM meta WHERE key = 'init_bootstrap_state'")
        row = cur.fetchone()
        assert row is not None
        meta = json.loads(row[0])
        meta["config_dir"] = os.path.abspath(cfg_dir)
        meta["request_digest"] = req_digest
        cur.execute(
            "UPDATE meta SET value = ? WHERE key = 'init_bootstrap_state'",
            (json.dumps(meta, sort_keys=True),),
        )
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()
    os_.permissions.secure_file(policy_db)

    read_daemon_config(cfg_dir / rel_cfg, os_)
    with closing(sqlite3.connect(f"file:{policy_db.resolve().as_posix()}?mode=ro", uri=True)) as vconn:
        s_row = vconn.execute(
            "SELECT channel, owner_id, key_digest, credential_id FROM signer WHERE revoked_at IS NULL"
        ).fetchone()
        assert s_row is not None
        assert (s_row[0], s_row[1], s_row[2], s_row[3] or "") == (
            signer.channel.value, signer.owner_id, signer.key_digest, signer.credential_id or ""
        )
        m_row = vconn.execute("SELECT value FROM meta WHERE key = 'init_bootstrap_state'").fetchone()
        assert m_row is not None
        m_data = json.loads(m_row[0])
        assert m_data.get("config_dir") == os.path.abspath(cfg_dir)
        assert m_data.get("request_digest") == req_digest

    return dataclasses.replace(
        tpl,
        daemon_config_path=cfg_dir / rel_cfg,
        cli_credential_path=_rebase(tpl.cli_credential_path, root, data_root, cfg_dir),
    )


def _rebase(path: Path, root: Path, data_root: Path, cfg_dir: Path) -> Path:
    for src, dst in ((root / "cfg", cfg_dir), (root / "data", data_root)):
        if path.is_relative_to(src):
            return dst / path.relative_to(src)
    return path
