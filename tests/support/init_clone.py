"""Session-cached ``init_store`` base: one real ``brain init`` run, cloned per test with paths rebased."""

from __future__ import annotations

import dataclasses
import json
import uuid
from pathlib import Path

from superbrain.adapters.os.daemon_config import read_daemon_config
from superbrain.composition.init_entry import InitReport, InitRequest, init_store
from superbrain.core._kernel_approval import SignerEnrollment
from superbrain.ports.os import OsAdapters
from tests.support.inc2_fixture import ensure_template_base
from tests.support.inc2_transport import clone_owner_only_tree, write_daemon_config_file

_CACHE: dict[tuple[str, str], tuple[Path, InitReport]] = {}


def init_store_cloned(
    os_: OsAdapters, *, data_root: Path, cfg_dir: Path, owner_id: str, machine_id: str, signer: SignerEnrollment
) -> InitReport:
    """Like ``init_store`` for fresh ``data_root`` / ``cfg_dir``: clones a cached base and rewrites ``daemon.json``."""
    key = (owner_id, machine_id)
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
    read_daemon_config(cfg_dir / rel_cfg, os_)
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
