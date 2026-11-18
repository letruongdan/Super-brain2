"""Independent bug-proof oracle V2 for I2-CLOSE-01: canonical JSON, subclasses, and backup/restore U+007F compat.

Derives all expected bytes, digests, and backup manifests strictly from the JSON/pre-R41 canonical UTF-8 format
(``sort_keys=True``, ``separators=(",", ":")``, ``ensure_ascii=False``, ``allow_nan=False``) without calling
production ``canonical_json`` or ``canonical_digest`` to compute expected values.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Sequence
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path

import pytest

from superbrain.adapters.os import os_adapters
from superbrain.core import canonical, errors
from superbrain.core.jsonvalue import JsonValue
from superbrain.ports import os as ports_os
from superbrain.ports.policy import IntentKind
from superbrain.storage import backup as bkp
from superbrain.storage import cas, kinds, layout, policy_store, restore, schema, store, writer
from tests.storage.conftest import CLOCK_START, DEMO_KINDS
from tests.support.clock import FakeClock
from tests.support.fs import corrupt_bytes

E2 = "0192f3a4-5b6c-7d8e-9f01-000000000e02"
E3 = "0192f3a4-5b6c-7d8e-9f01-000000000e03"


def _pre_r41_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha256_tag(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class _StrSub(str):
    """Plain ``str`` subclass for ORACLE-02 subtype parity."""


class _Choice(StrEnum):
    DEL_KEY = "k\x7f"
    DEL_VAL = "v\x7f"
    CTRL_DEL = "\x1f\x7f"


class _DictSub(dict[str, JsonValue]):
    """Plain ``dict`` subclass for ORACLE-02 subtype parity."""


class _ListSub(list[JsonValue]):
    """Plain ``list`` subclass for ORACLE-02 subtype parity."""


class _FloatSub(float):
    """Plain ``float`` subclass for ORACLE-02 subtype parity."""


# --- 1. Canonical Byte Parity, canonical_digest, & Subclass Matrix --------------------------------------------------


def test_canonical_json_byte_parity_across_control_del_and_unicode_positions() -> None:
    assert canonical.canonical_json("\x7e") == b'"~"'
    assert canonical.canonical_json("\x7f") == b'"\x7f"' and canonical.canonical_json("\x7f") != b'"\\u007f"'
    assert canonical.canonical_json("\x80") == b'"\xc2\x80"' and canonical.canonical_json("\x1f") == b'"\\u001f"'
    assert canonical.canonical_json({"\x7f": "v"}) == b'{"\x7f":"v"}'
    assert canonical.canonical_json({"v": "\x7f"}) == b'{"v":"\x7f"}'
    assert canonical.canonical_json({"\x7f": "v", "u": "é"}) == b'{"u":"\xc3\xa9","\x7f":"v"}'
    assert canonical.canonical_json({"v": "\x7f", "u": "🚀"}) == b'{"u":"\xf0\x9f\x9a\x80","v":"\x7f"}'

    ascii_nested: dict[str, JsonValue] = {
        "arr": ["\x1f", "\x7e", "\x7f"],
        "\x7f": {"\x7e": "\x7f", "k\x7f": "\x1f\x7f"},
    }
    expected_ascii = b'{"arr":["\\u001f","~","\x7f"],"\x7f":{"k\x7f":"\\u001f\x7f","~":"\x7f"}}'
    mixed_nested: dict[str, JsonValue] = {
        "arr": ["\x1f", "\x7e", "\x7f", "\x80"],
        "u": "é🚀",
        "\x7f": {"\x7e": "\x7f", "k\x7f": "\x1f\x7f"},
    }
    expected_mixed = (
        b'{"arr":["\\u001f","~","\x7f","\xc2\x80"],"u":"\xc3\xa9\xf0\x9f\x9a\x80",'
        b'"\x7f":{"k\x7f":"\\u001f\x7f","~":"\x7f"}}'
    )
    raw_ascii, raw_mixed = canonical.canonical_json(ascii_nested), canonical.canonical_json(mixed_nested)
    assert raw_ascii == expected_ascii == _pre_r41_json(ascii_nested)
    assert raw_mixed == expected_mixed == _pre_r41_json(mixed_nested)
    assert b"\\u007f" not in raw_ascii and b"\\u007f" not in raw_mixed
    subtree = b'"\x7f":{"k\x7f":"\\u001f\x7f","~":"\x7f"}'
    assert subtree in raw_ascii and subtree in raw_mixed
    assert canonical.digest_bytes(raw_ascii) == _sha256_tag(expected_ascii)
    assert json.loads(raw_ascii.decode("utf-8")) == ascii_nested


def test_canonical_json_and_validate_json_positive_and_negative_twins() -> None:
    valid_ascii: dict[str, JsonValue] = {"k\x7f": ["\x1f", "\x7e", "\x7f"]}
    valid_mixed: dict[str, JsonValue] = {"k\x7f": ["\x1f", "\x7e", "\x7f", "\x80"], "u": "é🚀"}
    canonical.validate_json(valid_ascii)
    canonical.validate_json(valid_mixed)
    for manifest in (valid_ascii, valid_mixed):
        dig_k = canonical.canonical_digest("knowledge", manifest)
        dig_n = canonical.canonical_digest("note", manifest)
        assert dig_k == _sha256_tag(_pre_r41_json({"kind": "knowledge", "manifest": manifest}))
        assert dig_n == _sha256_tag(_pre_r41_json({"kind": "note", "manifest": manifest}))
        assert dig_k != dig_n

    for bad in ("\ud800", "a\x7f\ud800", {"\ud800": "v"}, {"é\ud800": "v"}, math.nan, math.inf, -math.inf, {1: "v"}):
        with pytest.raises(errors.BrainError) as exc_v:
            canonical.validate_json(bad)
        assert exc_v.value.code is errors.ErrorCode.INVALID_INPUT
        payload = bad if isinstance(bad, dict) else {"v": bad}
        with pytest.raises(errors.BrainError) as exc_d:
            canonical.canonical_digest("knowledge", payload)  # type: ignore[arg-type]
        assert exc_d.value.code is errors.ErrorCode.INVALID_INPUT


def test_canonical_subclass_parity_positive_twins() -> None:
    single_probes: tuple[tuple[object, object, bytes], ...] = (
        ({_StrSub("\x7f"): "v"}, {"\x7f": "v"}, b'{"\x7f":"v"}'),
        ({_StrSub("k"): "\x7f"}, {"k": "\x7f"}, b'{"k":"\x7f"}'),
        ({"k": _StrSub("\x7f")}, {"k": "\x7f"}, b'{"k":"\x7f"}'),
        ({_Choice.DEL_KEY: _Choice.DEL_VAL}, {"k\x7f": "v\x7f"}, b'{"k\x7f":"v\x7f"}'),
        (_ListSub([_StrSub("\x7f"), _Choice.CTRL_DEL]), ["\x7f", "\x1f\x7f"], b'["\x7f","\\u001f\x7f"]'),
    )
    for sub_val, base_val, expected_bytes in single_probes:
        canonical.validate_json(sub_val)
        encoded = canonical.canonical_json(sub_val)
        assert encoded == expected_bytes == _pre_r41_json(base_val)
        assert canonical.canonical_json(base_val) == expected_bytes
        if isinstance(sub_val, dict) and isinstance(base_val, dict):
            assert canonical.canonical_digest("knowledge", sub_val) == _sha256_tag(
                _pre_r41_json({"kind": "knowledge", "manifest": base_val})
            )

    base_ascii: dict[str, JsonValue] = {
        "arr": ["\x1f", "\x7e", "\x7f"],
        "f": 1.5,
        "k\x7f": {"sub\x7f": "\x1f\x7f", "v\x7f": "v\x7f"},
    }
    sub_ascii = _DictSub(
        {
            _StrSub("arr"): _ListSub(["\x1f", "\x7e", _StrSub("\x7f")]),
            _StrSub("f"): _FloatSub(1.5),
            _Choice.DEL_KEY: _DictSub({_StrSub("sub\x7f"): _Choice.CTRL_DEL, _StrSub("v\x7f"): _Choice.DEL_VAL}),
        }
    )
    base_mixed: dict[str, JsonValue] = {**base_ascii, "u": "é🚀\x80"}
    sub_mixed = _DictSub({**sub_ascii, _StrSub("u"): _StrSub("é🚀\x80")})

    for sub_obj, base_obj in ((sub_ascii, base_ascii), (sub_mixed, base_mixed)):
        canonical.validate_json(sub_obj)
        expected_raw = _pre_r41_json(base_obj)
        assert canonical.canonical_json(sub_obj) == expected_raw == canonical.canonical_json(base_obj)
        assert b"\\u007f" not in expected_raw
        # canonical_digest contracts prohibit all floats (reject_floats=True), including float subclasses.
        float_cases: tuple[dict[str, JsonValue], ...] = (sub_obj, base_obj)
        for float_obj in float_cases:
            with pytest.raises(errors.BrainError) as exc_float:
                canonical.canonical_digest("knowledge", float_obj)
            assert exc_float.value.code is errors.ErrorCode.INVALID_INPUT
        sub_digest_obj = _DictSub({k: v for k, v in sub_obj.items() if k != "f"})
        base_digest_obj = {k: v for k, v in base_obj.items() if k != "f"}
        assert canonical.canonical_digest("knowledge", sub_digest_obj) == _sha256_tag(
            _pre_r41_json({"kind": "knowledge", "manifest": base_digest_obj})
        )


def test_canonical_subclass_negative_twins() -> None:
    bad_items: tuple[object, ...] = (
        _StrSub("\ud800"),
        _StrSub("a\x7f\ud800"),
        {_StrSub("\ud800"): "v"},
        {_StrSub("k\x7f"): _StrSub("v\ud800")},
        _DictSub({_StrSub("k\x7f"): _ListSub([_StrSub("\ud800")])}),
        _DictSub({_StrSub("u\ud800"): _ListSub([_StrSub("\x7f"), _StrSub("é")])}),
        _FloatSub(math.nan),
        _FloatSub(math.inf),
        _FloatSub(-math.inf),
        {_FloatSub(1.5): "v"},
        _ListSub([_DictSub({_StrSub("ok\x7f"): _FloatSub(math.nan)})]),
    )
    for bad in bad_items:
        with pytest.raises(errors.BrainError) as exc_v:
            canonical.validate_json(bad)
        assert exc_v.value.code is errors.ErrorCode.INVALID_INPUT
        payload = bad if isinstance(bad, dict) else {"v": bad}
        with pytest.raises(errors.BrainError) as exc_d:
            canonical.canonical_digest("knowledge", payload)  # type: ignore[arg-type]
        assert exc_d.value.code is errors.ErrorCode.INVALID_INPUT


# --- 2. Untouched Backup Writers + Pre-R41 Witness Backups & Real Restore -------------------------------------------


def _assert_manifest_raw_u007f(
    backup_dir: Path, snapshot_name: str, expected_store_id: str, expected_kind: bkp.BackupKind
) -> bytes:
    raw = (backup_dir / "manifest.json").read_bytes()
    assert b"\\u007f" not in raw
    fields = json.loads(raw)
    assert isinstance(fields, dict)
    assert fields["kind"] == expected_kind and fields["store_id"] == expected_store_id
    assert fields["db_digest"] == _sha256_tag((backup_dir / snapshot_name).read_bytes())
    expected_raw = _pre_r41_json(fields)
    assert raw == expected_raw and expected_store_id.encode("utf-8") in raw
    return raw


def _rewrite_manifest_pre_r41(
    backup_dir: Path, snapshot_name: str, expected_store_id: str, os_: ports_os.OsAdapters
) -> bytes:
    manifest_path = backup_dir / "manifest.json"
    fields = json.loads(manifest_path.read_bytes())
    assert isinstance(fields, dict) and fields["store_id"] == expected_store_id
    assert fields["db_digest"] == _sha256_tag((backup_dir / snapshot_name).read_bytes())
    raw = _pre_r41_json(fields)
    assert expected_store_id.encode("utf-8") in raw and b"\\u007f" not in raw
    manifest_path.write_bytes(raw)
    os_.permissions.secure_file(manifest_path)
    return raw


def _seed_backup_triplet(
    root: layout.DataRoot,
    lease: writer.WriterLease,
    os_: ports_os.OsAdapters,
    clock: FakeClock,
    store_id: str,
    quarantined: str,
) -> tuple[tuple[Path, Path, Path], str, str]:
    handles: list[store.Store | policy_store.PolicyStore] = []
    try:
        pol = policy_store.PolicyStore.create(root, lease, os_, store_id=store_id)
        st = store.Store.create(root, lease, os_, pol, (), kinds.KindRegistry(DEMO_KINDS))
        handles.extend((pol, st))
        witness_d = st.store_content(b"witness-pre-r41", "event", E2, cas.RetentionClass.EVIDENCE, None)
        pol.record_intent(IntentKind.QUARANTINE, {"digest": quarantined})
        store_bak = bkp.create_store_backup(st, os_, clock.now())
        policy_bak = bkp.create_policy_backup(pol, os_, clock.now())
        post_d = st.store_content(b"post-backup", "event", E3, cas.RetentionClass.EVIDENCE, None)
        st.close()
        pol.close()
        full_bak = bkp.create_maintenance_backup(root, lease, os_, target="store", now=clock.now())
        return (store_bak, full_bak, policy_bak), witness_d, post_d
    finally:
        for h in reversed(handles):
            if not h.closed:
                h.close()


def _verify_and_restore_triplet(
    root: layout.DataRoot,
    lease: writer.WriterLease,
    os_: ports_os.OsAdapters,
    clock: FakeClock,
    store_id: str,
    quarantined: str,
    backups: tuple[Path, Path, Path],
    witness_d: str,
    post_d: str,
) -> None:
    store_bak, full_bak, policy_bak = backups
    checks: tuple[tuple[Path, bkp.BackupKind, Sequence[schema.Migration]], ...] = (
        (store_bak, "store", schema.STORE_MIGRATIONS),
        (full_bak, "store_full", schema.STORE_MIGRATIONS),
        (policy_bak, "policy", schema.POLICY_MIGRATIONS),
    )
    for bak, kind, migs in checks:
        m = bkp.verify_backup(bak, expected_kind=kind, expected_store_id=store_id, migrations=migs, os_=os_)
        assert m.store_id == store_id and m.logical_verified

    handles: list[store.Store | policy_store.PolicyStore] = []
    try:
        pol2 = policy_store.PolicyStore.open(root, lease, os_, migrations=schema.POLICY_MIGRATIONS)
        handles.append(pol2)
        for idx, (bak, expect_post) in enumerate(((store_bak, False), (full_bak, True)), start=1):
            restore.restore_store(root, lease, os_, bak, pol2, clock.now() + timedelta(seconds=idx))
            restored = store.Store.open(root, lease, os_, pol2, (), kinds.KindRegistry(DEMO_KINDS))
            handles.append(restored)
            assert restored.store_id == store_id and restored.cas.holders(witness_d) != []
            assert (restored.cas.holders(post_d) != []) is expect_post
            restored.close()
        pol2.close()

        rep = restore.restore_policy(
            root, lease, os_, policy_bak, store_id=store_id, now=clock.now() + timedelta(seconds=3)
        )
        final_pol = policy_store.PolicyStore.open(root, lease, os_, migrations=schema.POLICY_MIGRATIONS)
        handles.append(final_pol)
        assert final_pol.store_id == store_id and final_pol.trust_generation() == rep.trust_generation
        assert final_pol.is_quarantined(quarantined)
        # Reopen main Store against restored policy to confirm Store.reconcile_policy() tolerates U+007F store_id.
        reconciled_st = store.Store.open(root, lease, os_, final_pol, (), kinds.KindRegistry(DEMO_KINDS))
        handles.append(reconciled_st)
        assert reconciled_st.store_id == store_id
    finally:
        for h in reversed(handles):
            if not h.closed:
                h.close()


@pytest.mark.parametrize("store_id", ["store-\x7f-0001", "store-\x7f-é-0001"], ids=["ascii_del", "unicode_del"])
def test_untouched_backup_writers_emit_raw_u007f_and_restore_all_three_kinds(trusted_tmp: Path, store_id: str) -> None:
    clock = FakeClock(CLOCK_START)
    os_ = os_adapters(clock=clock)
    root, quarantined = layout.prepare_data_root(trusted_tmp / "root", os_), "sha256:" + "11" * 32

    with writer.acquire_writer(root, os_) as lease:
        layout.secure_subdirectories(root, lease, os_)
        backups, witness_d, post_d = _seed_backup_triplet(root, lease, os_, clock, store_id, quarantined)
        store_bak, full_bak, policy_bak = backups
        checks: tuple[tuple[Path, str, bkp.BackupKind], ...] = (
            (store_bak, "brain.db", "store"),
            (full_bak, "brain.db", "store_full"),
            (policy_bak, "policy.db", "policy"),
        )
        for bak, snap, kind in checks:
            _assert_manifest_raw_u007f(bak, snap, store_id, kind)
        _verify_and_restore_triplet(root, lease, os_, clock, store_id, quarantined, backups, witness_d, post_d)


@pytest.mark.parametrize("store_id", ["store-\x7f-0001", "store-\x7f-é-0001"], ids=["ascii_del", "unicode_del"])
def test_pre_r41_witness_backup_verify_and_restore_all_three_kinds(trusted_tmp: Path, store_id: str) -> None:
    clock = FakeClock(CLOCK_START)
    os_ = os_adapters(clock=clock)
    root, quarantined = layout.prepare_data_root(trusted_tmp / "root", os_), "sha256:" + "11" * 32

    with writer.acquire_writer(root, os_) as lease:
        layout.secure_subdirectories(root, lease, os_)
        backups, witness_d, post_d = _seed_backup_triplet(root, lease, os_, clock, store_id, quarantined)
        store_bak, full_bak, policy_bak = backups
        _rewrite_manifest_pre_r41(store_bak, "brain.db", store_id, os_)
        _rewrite_manifest_pre_r41(full_bak, "brain.db", store_id, os_)
        _rewrite_manifest_pre_r41(policy_bak, "policy.db", store_id, os_)
        _verify_and_restore_triplet(root, lease, os_, clock, store_id, quarantined, backups, witness_d, post_d)


def _assert_backup_rejected(
    root: layout.DataRoot,
    lease: writer.WriterLease,
    os_: ports_os.OsAdapters,
    pol: policy_store.PolicyStore | None,
    bak: Path,
    kind: bkp.BackupKind,
    store_id: str,
    migs: Sequence[schema.Migration],
    now: datetime,
) -> None:
    with pytest.raises(errors.BrainError) as exc_ver:
        bkp.verify_backup(bak, expected_kind=kind, expected_store_id=store_id, migrations=migs, os_=os_)
    assert exc_ver.value.code is errors.ErrorCode.INTEGRITY_FAILURE
    with pytest.raises(errors.BrainError) as exc_rest:
        if kind == "policy":
            restore.restore_policy(root, lease, os_, bak, store_id=store_id, now=now)
        else:
            assert pol is not None
            restore.restore_store(root, lease, os_, bak, pol, now)
    assert exc_rest.value.code is errors.ErrorCode.INTEGRITY_FAILURE


@pytest.mark.parametrize("store_id", ["store-\x7f-0001", "store-\x7f-é-0001"], ids=["ascii_del", "unicode_del"])
@pytest.mark.parametrize("kind", ["store", "store_full", "policy"])
def test_backup_verify_and_restore_reject_escaped_u007f_and_tampered_snapshot(
    trusted_tmp: Path, store_id: str, kind: bkp.BackupKind
) -> None:
    clock = FakeClock(CLOCK_START)
    os_ = os_adapters(clock=clock)
    root = layout.prepare_data_root(trusted_tmp / "root", os_)

    with writer.acquire_writer(root, os_) as lease:
        layout.secure_subdirectories(root, lease, os_)
        pol = policy_store.PolicyStore.create(root, lease, os_, store_id=store_id)
        st = store.Store.create(root, lease, os_, pol, (), kinds.KindRegistry(DEMO_KINDS))
        try:
            st.store_content(b"witness", "event", E2, cas.RetentionClass.EVIDENCE, None)
            if kind == "store":
                bak = bkp.create_store_backup(st, os_, clock.now())
                snap_name, migs = "brain.db", schema.STORE_MIGRATIONS
            elif kind == "policy":
                bak = bkp.create_policy_backup(pol, os_, clock.now())
                snap_name, migs = "policy.db", schema.POLICY_MIGRATIONS
            else:
                st.close()
                bak = bkp.create_maintenance_backup(root, lease, os_, target="store", now=clock.now())
                snap_name, migs = "brain.db", schema.STORE_MIGRATIONS
            if not st.closed:
                st.close()
            if kind == "policy":
                pol.close()

            raw_valid = _rewrite_manifest_pre_r41(bak, snap_name, store_id, os_)
            escaped = raw_valid.replace(b"\x7f", b"\\u007f")
            assert b"\\u007f" in escaped
            bad_digest = _pre_r41_json({**json.loads(raw_valid), "db_digest": "sha256:" + "0" * 64})
            for idx, bad_manifest in enumerate((escaped, bad_digest), start=1):
                (bak / "manifest.json").write_bytes(bad_manifest)
                os_.permissions.secure_file(bak / "manifest.json")
                _assert_backup_rejected(
                    root, lease, os_, pol, bak, kind, store_id, migs, clock.now() + timedelta(seconds=idx)
                )
            (bak / "manifest.json").write_bytes(raw_valid)
            os_.permissions.secure_file(bak / "manifest.json")
            corrupt_bytes(bak / snap_name, offsets=[200])
            _assert_backup_rejected(
                root, lease, os_, pol, bak, kind, store_id, migs, clock.now() + timedelta(seconds=3)
            )
        finally:
            for h in (st, pol):
                if not h.closed:
                    h.close()
