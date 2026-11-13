"""Requirement-derived tests for owner-only client profile/trust loaders and launch checkout verification (`T7b.1`)."""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from superbrain.core.client_profile import ClientProfile, SelectedWorkspace, WorkspaceProfile

_VALID_UUID_V7 = "01950000-0000-7000-8000-000000000001"
_VALID_SECRET_B64 = base64.urlsafe_b64encode(b"\x11" * 32).rstrip(b"=").decode("ascii")
_VALID_BEARER_TOKEN = f"{_VALID_UUID_V7}.{_VALID_SECRET_B64}"
_VALID_LEAF_SHA256 = "a" * 64
_SAMPLE_CA_PEM = (
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBszCCAVmgAwIBAgIUTestSampleCertificateBodyOnly000123456789\n"
    "-----END CERTIFICATE-----\n"
)


def _write_secure_file(path: Path, data: bytes) -> Path:
    from superbrain.adapters.os import os_adapters

    os_ = os_adapters()
    parent_existed = path.parent.exists()
    path.parent.mkdir(parents=True, exist_ok=True)
    if not parent_existed:
        os_.permissions.secure_directory(path.parent)
    path.write_bytes(data)
    os_.permissions.secure_file(path)
    return path


def _make_secure_dir(path: Path) -> Path:
    from superbrain.adapters.os import os_adapters

    path.mkdir(parents=True, exist_ok=True)
    os_adapters().permissions.secure_directory(path)
    return path


def _broaden_file_permissions(path: Path) -> None:
    if sys.platform == "win32":
        import ntsecuritycon

        from tests.support.winacl import grant

        grant(path, "S-1-1-0", ntsecuritycon.FILE_GENERIC_READ)
    else:
        os.chmod(path, 0o644)


def _broaden_dir_permissions(path: Path) -> None:
    if sys.platform == "win32":
        import ntsecuritycon

        from tests.support.winacl import grant

        grant(path, "S-1-5-32-545", ntsecuritycon.FILE_DELETE_CHILD)
    else:
        os.chmod(path, 0o777)


def test_profile_requires_exact_owner_only_paths_and_types(monkeypatch: Any) -> None:
    import pytest

    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.daemon_config import (
        read_client_ca,
        read_client_credential,
        read_client_endpoint,
        read_client_profile,
    )
    from superbrain.core.canonical import canonical_json
    from superbrain.core.errors import BrainError, ErrorCode
    from superbrain.core.kernel import Endpoint, Scope, parse_bearer_token
    from tests.support.fs import fake_link
    from tests.support.inc2_transport import make_trusted_test_dir

    os_ = os_adapters()
    base_dir = make_trusted_test_dir("t7b1-profile-types")
    try:
        spaced_dir = _make_secure_dir(base_dir / "owner dir with spaces")
        chk_dir = _make_secure_dir(spaced_dir / "checkout main")
        endpoint_file = _write_secure_file(
            spaced_dir / "endpoint.json",
            canonical_json(
                {
                    "version": 1,
                    "host": "127.0.0.1",
                    "port": 54321,
                    "store_id": "store-01",
                    "writer_epoch": 3,
                    "instance_id": "inst-01",
                    "contract": "mcp-tools-v2",
                }
            ),
        )
        ca_file = _write_secure_file(spaced_dir / "ca.pem", _SAMPLE_CA_PEM.encode("utf-8"))
        cred_file = _write_secure_file(spaced_dir / "credential.txt", _VALID_BEARER_TOKEN.encode("utf-8"))

        # 1. Positive checks: profile without workspace, profile with workspace, endpoint, CA, credential
        profile_no_ws_path = _write_secure_file(
            spaced_dir / "profile-no-ws.json",
            canonical_json(
                {
                    "version": 1,
                    "endpoint_path": str(endpoint_file),
                    "expected_store_id": "store-01",
                    "ca_file": str(ca_file),
                    "leaf_cert_sha256": _VALID_LEAF_SHA256,
                    "credential_file": str(cred_file),
                }
            ),
        )
        prof_no_ws = read_client_profile(profile_no_ws_path, os_)
        assert prof_no_ws == ClientProfile(
            version=1,
            endpoint_path=endpoint_file,
            expected_store_id="store-01",
            ca_file=ca_file,
            leaf_cert_sha256=_VALID_LEAF_SHA256,
            credential_file=cred_file,
            workspace=None,
        )

        profile_ws_dict: dict[str, Any] = {
            "version": 1,
            "endpoint_path": str(endpoint_file),
            "expected_store_id": "store-01",
            "ca_file": str(ca_file),
            "leaf_cert_sha256": _VALID_LEAF_SHA256,
            "credential_file": str(cred_file),
            "workspace": {
                "alias": "ws-main",
                "checkout_path": str(chk_dir),
                "expected_workspace_id": "ws-repo-01",
                "expected_checkout_id": "chk-01",
            },
        }
        profile_ws_path = _write_secure_file(
            spaced_dir / "profile-ws.json",
            canonical_json(profile_ws_dict),
        )
        prof_ws = read_client_profile(profile_ws_path, os_)
        assert prof_ws == ClientProfile(
            version=1,
            endpoint_path=endpoint_file,
            expected_store_id="store-01",
            ca_file=ca_file,
            leaf_cert_sha256=_VALID_LEAF_SHA256,
            credential_file=cred_file,
            workspace=WorkspaceProfile(
                alias="ws-main",
                checkout_path=chk_dir,
                expected_workspace_id="ws-repo-01",
                expected_checkout_id="chk-01",
            ),
        )
        sel = SelectedWorkspace(
            alias="ws-main",
            scope=Scope(repo_id="ws-repo-01", checkout_id="chk-01"),
        )
        assert sel.alias == "ws-main" and sel.scope.repo_id == "ws-repo-01"

        ep = read_client_endpoint(endpoint_file, os_)
        assert ep == Endpoint(
            version=1,
            host="127.0.0.1",
            port=54321,
            store_id="store-01",
            writer_epoch=3,
            instance_id="inst-01",
            contract="mcp-tools-v2",
        )
        assert read_client_ca(ca_file, os_) == _SAMPLE_CA_PEM

        for suffix in (b"", b"\n", b"\r\n"):
            _write_secure_file(cred_file, _VALID_BEARER_TOKEN.encode("utf-8") + suffix)
            loaded_tok = read_client_credential(cred_file, os_)
            assert loaded_tok == _VALID_BEARER_TOKEN
            assert parse_bearer_token(loaded_tok)[0] == _VALID_UUID_V7

        # 2. Missing files: endpoint -> DAEMON_UNAVAILABLE; profile/ca/credential -> NOT_FOUND
        with pytest.raises(BrainError) as ep_missing_exc:
            read_client_endpoint(spaced_dir / "missing-endpoint.json", os_)
        assert ep_missing_exc.value.code == ErrorCode.DAEMON_UNAVAILABLE

        for reader, missing_name in (
            (read_client_profile, "missing-profile.json"),
            (read_client_ca, "missing-ca.pem"),
            (read_client_credential, "missing-cred.txt"),
        ):
            with pytest.raises(BrainError) as miss_exc:
                reader(spaced_dir / missing_name, os_)
            assert miss_exc.value.code == ErrorCode.NOT_FOUND

        # 3. Profile schema & type violations -> INVALID_INPUT / UNSAFE_PATH
        bad_profile_path = spaced_dir / "bad-profile.json"

        def _assert_bad_profile_bytes(raw_bytes: bytes, *expected_codes: ErrorCode) -> None:
            _write_secure_file(bad_profile_path, raw_bytes)
            with pytest.raises(BrainError) as exc_info:
                read_client_profile(bad_profile_path, os_)
            assert exc_info.value.code in expected_codes

        # Duplicate JSON key
        _assert_bad_profile_bytes(
            b'{"version":1,"version":1,"endpoint_path":"'
            + str(endpoint_file).replace("\\", "\\\\").encode("utf-8")
            + b'","expected_store_id":"store-01","ca_file":"'
            + str(ca_file).replace("\\", "\\\\").encode("utf-8")
            + b'","leaf_cert_sha256":"'
            + _VALID_LEAF_SHA256.encode("ascii")
            + b'","credential_file":"'
            + str(cred_file).replace("\\", "\\\\").encode("utf-8")
            + b'"}',
            ErrorCode.INVALID_INPUT,
        )

        # Missing required top-level keys
        for req_key in (
            "version",
            "endpoint_path",
            "expected_store_id",
            "ca_file",
            "leaf_cert_sha256",
            "credential_file",
        ):
            mut = dict(profile_ws_dict)
            del mut[req_key]
            _assert_bad_profile_bytes(canonical_json(mut), ErrorCode.INVALID_INPUT)

        # Extra top-level key and extra workspace key
        _assert_bad_profile_bytes(
            canonical_json({**profile_ws_dict, "extra_field": "bad"}),
            ErrorCode.INVALID_INPUT,
        )
        _assert_bad_profile_bytes(
            canonical_json(
                {
                    **profile_ws_dict,
                    "workspace": {**profile_ws_dict["workspace"], "extra_ws": 1},
                }
            ),
            ErrorCode.INVALID_INPUT,
        )

        # Missing required workspace keys
        for ws_req in ("alias", "checkout_path", "expected_workspace_id", "expected_checkout_id"):
            ws_mut = dict(profile_ws_dict["workspace"])
            del ws_mut[ws_req]
            _assert_bad_profile_bytes(
                canonical_json({**profile_ws_dict, "workspace": ws_mut}),
                ErrorCode.INVALID_INPUT,
            )

        # Wrong version values (including bool True/False) and invalid workspace types (null, array, str)
        for bad_ver in (0, 2, -1, True, False, "1", None, 1.0):
            _assert_bad_profile_bytes(
                canonical_json({**profile_ws_dict, "version": bad_ver}),
                ErrorCode.INVALID_INPUT,
            )
        for bad_ws in (None, [], [profile_ws_dict["workspace"]], "ws-main", 1):
            _assert_bad_profile_bytes(
                canonical_json({**profile_ws_dict, "workspace": bad_ws}),
                ErrorCode.INVALID_INPUT,
            )

        # Invalid leaf_cert_sha256
        for bad_pin in ("A" * 64, "g" * 64, "a" * 63, "a" * 65, "", 123, None):
            _assert_bad_profile_bytes(
                canonical_json({**profile_ws_dict, "leaf_cert_sha256": bad_pin}),
                ErrorCode.INVALID_INPUT,
            )

        # Invalid expected_store_id, alias, expected_workspace_id, expected_checkout_id
        for bad_id in ("", "bad id", "bad\tid", "-leading-dash", "a..b", "a" * 129, 123, None):
            _assert_bad_profile_bytes(
                canonical_json({**profile_ws_dict, "expected_store_id": bad_id}),
                ErrorCode.INVALID_INPUT,
            )
            for ws_id_key in ("alias", "expected_workspace_id", "expected_checkout_id"):
                _assert_bad_profile_bytes(
                    canonical_json(
                        {
                            **profile_ws_dict,
                            "workspace": {**profile_ws_dict["workspace"], ws_id_key: bad_id},
                        }
                    ),
                    ErrorCode.INVALID_INPUT,
                )

        # Relative, empty, parent-traversal (`..`), or NUL paths inside profile fields and on reader entrypoints
        bad_path_spellings: list[str] = [
            "",
            "relative/file.json",
            str(spaced_dir / ".." / "escape.json"),
            f"{spaced_dir}\x00evil",
        ]
        if sys.platform == "win32":
            bad_path_spellings.extend(
                [
                    r"\\?\C:\temp\file.json",
                    r"\\.\pipe\file.json",
                    r"\\localhost\c$\temp\file.json",
                    f"{spaced_dir / 'file.json'}:stream",
                ]
            )

        for bad_spelling in bad_path_spellings:
            for top_path_key in ("endpoint_path", "ca_file", "credential_file"):
                _assert_bad_profile_bytes(
                    canonical_json({**profile_ws_dict, top_path_key: bad_spelling}),
                    ErrorCode.INVALID_INPUT,
                    ErrorCode.UNSAFE_PATH,
                )
            _assert_bad_profile_bytes(
                canonical_json(
                    {
                        **profile_ws_dict,
                        "workspace": {**profile_ws_dict["workspace"], "checkout_path": bad_spelling},
                    }
                ),
                ErrorCode.INVALID_INPUT,
                ErrorCode.UNSAFE_PATH,
            )
            if bad_spelling and "\x00" not in bad_spelling:
                for reader in (
                    read_client_profile,
                    read_client_endpoint,
                    read_client_ca,
                    read_client_credential,
                ):
                    with pytest.raises(BrainError) as path_exc:
                        reader(Path(bad_spelling), os_)
                    assert path_exc.value.code in (ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH)

        # 4. Invalid endpoint, CA, and credential contents
        bad_ep_path = spaced_dir / "bad-endpoint.json"
        for bad_ep_obj in (
            {
                "version": 2,
                "host": "127.0.0.1",
                "port": 54321,
                "store_id": "store-01",
                "writer_epoch": 1,
                "instance_id": "inst-01",
                "contract": "mcp-tools-v2",
            },
            {
                "version": 1,
                "host": "0.0.0.0",
                "port": 54321,
                "store_id": "store-01",
                "writer_epoch": 1,
                "instance_id": "inst-01",
                "contract": "mcp-tools-v2",
            },
            {
                "version": 1,
                "host": "127.0.0.1",
                "port": True,
                "store_id": "store-01",
                "writer_epoch": 1,
                "instance_id": "inst-01",
                "contract": "mcp-tools-v2",
            },
            {
                "version": 1,
                "host": "127.0.0.1",
                "port": 0,
                "store_id": "store-01",
                "writer_epoch": 1,
                "instance_id": "inst-01",
                "contract": "mcp-tools-v2",
            },
            {
                "version": 1,
                "host": "127.0.0.1",
                "port": 65536,
                "store_id": "store-01",
                "writer_epoch": 1,
                "instance_id": "inst-01",
                "contract": "mcp-tools-v2",
            },
            {
                "version": 1,
                "host": "127.0.0.1",
                "port": 54321,
                "store_id": "store-01",
                "writer_epoch": 0,
                "instance_id": "inst-01",
                "contract": "mcp-tools-v2",
            },
            {
                "version": 1,
                "host": "127.0.0.1",
                "port": 54321,
                "store_id": "store-01",
                "writer_epoch": 1,
                "instance_id": "inst-01",
                "contract": "mcp-tools-v1",
            },
            {
                "version": 1,
                "host": "127.0.0.1",
                "port": 54321,
                "store_id": "store-01",
                "writer_epoch": 1,
                "instance_id": "inst-01",
                "contract": "mcp-tools-v2",
                "extra": 1,
            },
        ):
            _write_secure_file(bad_ep_path, canonical_json(bad_ep_obj))
            with pytest.raises(BrainError) as ep_exc:
                read_client_endpoint(bad_ep_path, os_)
            assert ep_exc.value.code == ErrorCode.INVALID_INPUT

        bad_ca_path = spaced_dir / "bad-ca.pem"
        for bad_ca_bytes in (b"", b"   \n", b"NOT A PEM CERTIFICATE\n", b"\xff\xfe"):
            _write_secure_file(bad_ca_path, bad_ca_bytes)
            with pytest.raises(BrainError) as ca_exc:
                read_client_ca(bad_ca_path, os_)
            assert ca_exc.value.code == ErrorCode.INVALID_INPUT

        bad_cred_path = spaced_dir / "bad-cred.txt"
        for bad_cred_bytes in (
            b"",
            b"   \n",
            b"not-a-bearer-token\n",
            f"01950000-0000-4000-8000-000000000001.{_VALID_SECRET_B64}\n".encode(),
            f"{_VALID_BEARER_TOKEN}\nextra-line\n".encode(),
            f"{_VALID_BEARER_TOKEN} trailing\n".encode(),
            b"\xff\xfe",
        ):
            _write_secure_file(bad_cred_path, bad_cred_bytes)
            with pytest.raises(BrainError) as cred_exc:
                read_client_credential(bad_cred_path, os_)
            assert cred_exc.value.code in (ErrorCode.UNAUTHENTICATED, ErrorCode.INVALID_INPUT)

        # 5. Size caps: 65,536 B allowed vs 65,537 B rejected for profile/endpoint/CA; 257 B rejected for credential
        base_prof_bytes = canonical_json(
            profile_no_ws_path
            and read_client_profile(profile_no_ws_path, os_)
            and {
                "version": 1,
                "endpoint_path": str(endpoint_file),
                "expected_store_id": "store-01",
                "ca_file": str(ca_file),
                "leaf_cert_sha256": _VALID_LEAF_SHA256,
                "credential_file": str(cred_file),
            }
        )
        exact_64k_prof = base_prof_bytes + (b" " * (65_536 - len(base_prof_bytes)))
        assert len(exact_64k_prof) == 65_536
        _write_secure_file(bad_profile_path, exact_64k_prof)
        assert read_client_profile(bad_profile_path, os_) == prof_no_ws

        _write_secure_file(bad_profile_path, exact_64k_prof + b" ")
        with pytest.raises(BrainError) as prof_cap_exc:
            read_client_profile(bad_profile_path, os_)
        assert prof_cap_exc.value.code == ErrorCode.INVALID_INPUT

        base_ep_bytes = ep.encode_canonical()
        exact_64k_ep = base_ep_bytes + (b" " * (65_536 - len(base_ep_bytes)))
        _write_secure_file(bad_ep_path, exact_64k_ep)
        assert read_client_endpoint(bad_ep_path, os_) == ep

        _write_secure_file(bad_ep_path, exact_64k_ep + b" ")
        with pytest.raises(BrainError) as ep_cap_exc:
            read_client_endpoint(bad_ep_path, os_)
        assert ep_cap_exc.value.code == ErrorCode.INVALID_INPUT

        ca_bytes = _SAMPLE_CA_PEM.encode("utf-8")
        exact_64k_ca = ca_bytes + (b"#" * (65_536 - len(ca_bytes)))
        _write_secure_file(bad_ca_path, exact_64k_ca)
        assert len(read_client_ca(bad_ca_path, os_)) == 65_536

        _write_secure_file(bad_ca_path, exact_64k_ca + b"#")
        with pytest.raises(BrainError) as ca_cap_exc:
            read_client_ca(bad_ca_path, os_)
        assert ca_cap_exc.value.code == ErrorCode.INVALID_INPUT

        _write_secure_file(bad_cred_path, b"x" * 257)
        with pytest.raises(BrainError) as cred_cap_exc:
            read_client_credential(bad_cred_path, os_)
        assert cred_cap_exc.value.code in (ErrorCode.INVALID_INPUT, ErrorCode.UNAUTHENTICATED)

        # 6. Directory instead of regular file, symlinked leaf/ancestor, and broadened permissions
        for reader in (
            read_client_profile,
            read_client_endpoint,
            read_client_ca,
            read_client_credential,
        ):
            with pytest.raises(BrainError) as dir_exc:
                reader(chk_dir, os_)
            assert dir_exc.value.code in (ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH)

        for reader, target_file in (
            (read_client_profile, profile_ws_path),
            (read_client_endpoint, endpoint_file),
            (read_client_ca, ca_file),
            (read_client_credential, cred_file),
        ):
            with monkeypatch.context() as mp:
                fake_link(mp, target_file)
                with pytest.raises(BrainError) as link_leaf_exc:
                    reader(target_file, os_)
                assert link_leaf_exc.value.code == ErrorCode.UNSAFE_PATH

            with monkeypatch.context() as mp:
                fake_link(mp, spaced_dir)
                with pytest.raises(BrainError) as link_anc_exc:
                    reader(target_file, os_)
                assert link_anc_exc.value.code == ErrorCode.UNSAFE_PATH

        if sys.platform == "win32":
            junc_dir = base_dir / "junction-dir"
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junc_dir), str(spaced_dir)],
                check=True,
                capture_output=True,
            )
            with pytest.raises(BrainError) as junc_exc:
                read_client_profile(junc_dir / "profile-ws.json", os_)
            assert junc_exc.value.code == ErrorCode.UNSAFE_PATH

        # Broadened file permissions on each of the 4 files -> INSECURE_PERMISSIONS
        perm_dir = _make_secure_dir(base_dir / "perm-checks")
        p_copy = _write_secure_file(perm_dir / "profile.json", profile_ws_path.read_bytes())
        e_copy = _write_secure_file(perm_dir / "endpoint.json", endpoint_file.read_bytes())
        c_copy = _write_secure_file(perm_dir / "ca.pem", ca_file.read_bytes())
        k_copy = _write_secure_file(perm_dir / "credential.txt", _VALID_BEARER_TOKEN.encode("utf-8"))

        for reader, copy_file in (
            (read_client_profile, p_copy),
            (read_client_endpoint, e_copy),
            (read_client_ca, c_copy),
            (read_client_credential, k_copy),
        ):
            _broaden_file_permissions(copy_file)
            with pytest.raises(BrainError) as perm_exc:
                reader(copy_file, os_)
            assert perm_exc.value.code == ErrorCode.INSECURE_PERMISSIONS
            os_.permissions.secure_file(copy_file)

        # Broadened ancestor directory permissions -> INSECURE_PERMISSIONS
        _broaden_dir_permissions(perm_dir)
        for reader, copy_file in (
            (read_client_profile, p_copy),
            (read_client_endpoint, e_copy),
            (read_client_ca, c_copy),
            (read_client_credential, k_copy),
        ):
            with pytest.raises(BrainError) as anc_perm_exc:
                reader(copy_file, os_)
            assert anc_perm_exc.value.code == ErrorCode.INSECURE_PERMISSIONS
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)


def test_profile_refuses_replaced_file_and_unverified_cwd(monkeypatch: Any) -> None:
    import pytest

    from superbrain.adapters.os import os_adapters
    from superbrain.adapters.os.daemon_config import (
        read_client_ca,
        read_client_credential,
        read_client_endpoint,
        read_client_profile,
    )
    from superbrain.adapters.os.workspaces import verify_launch_checkout
    from superbrain.core.canonical import canonical_json
    from superbrain.core.errors import BrainError, ErrorCode
    from tests.support.fs import fake_link
    from tests.support.inc2_transport import make_trusted_test_dir

    os_ = os_adapters()
    base_dir = make_trusted_test_dir("t7b1-replace-and-cwd")
    try:
        chk_dir = _make_secure_dir(base_dir / "checkout")
        sub_cwd = _make_secure_dir(chk_dir / "nested")
        endpoint_file = _write_secure_file(
            base_dir / "endpoint.json",
            canonical_json(
                {
                    "version": 1,
                    "host": "127.0.0.1",
                    "port": 54321,
                    "store_id": "store-01",
                    "writer_epoch": 1,
                    "instance_id": "inst-01",
                    "contract": "mcp-tools-v2",
                }
            ),
        )
        ca_file = _write_secure_file(base_dir / "ca.pem", _SAMPLE_CA_PEM.encode("utf-8"))
        cred_file = _write_secure_file(base_dir / "credential.txt", _VALID_BEARER_TOKEN.encode("utf-8"))
        profile_file = _write_secure_file(
            base_dir / "profile.json",
            canonical_json(
                {
                    "version": 1,
                    "endpoint_path": str(endpoint_file),
                    "expected_store_id": "store-01",
                    "ca_file": str(ca_file),
                    "leaf_cert_sha256": _VALID_LEAF_SHA256,
                    "credential_file": str(cred_file),
                }
            ),
        )

        # 1. File replacement between preflight lstat and open fstat (real swap on os.open)
        real_os_open = os.open
        for reader, target_file in (
            (read_client_profile, profile_file),
            (read_client_endpoint, endpoint_file),
            (read_client_ca, ca_file),
            (read_client_credential, cred_file),
        ):
            replacement = _write_secure_file(target_file.with_suffix(".replacement"), target_file.read_bytes())
            assert not target_file.samefile(replacement)

            def _swapping_open(
                path: str | os.PathLike[str],
                flags: int,
                mode: int = 0o777,
                *,
                _target: Path = target_file,
                _replacement: Path = replacement,
            ) -> int:
                if Path(path).resolve() == _target.resolve():
                    # Both files exist before the swap, so they have distinct identities.
                    os.replace(_replacement, _target)
                return real_os_open(path, flags, mode)

            with monkeypatch.context() as mp:
                mp.setattr(os, "open", _swapping_open)
                with pytest.raises(BrainError) as swap_exc:
                    reader(target_file, os_)
                assert swap_exc.value.code == ErrorCode.UNSAFE_PATH

            # Also verify via os.path.samestat returning False (covers filesystems that reuse nothing or post-read swap)
            with monkeypatch.context() as mp:
                mp.setattr(os.path, "samestat", lambda _s1, _s2: False)
                with pytest.raises(BrainError) as samestat_exc:
                    reader(target_file, os_)
                assert samestat_exc.value.code == ErrorCode.UNSAFE_PATH

        # 2. verify_launch_checkout checks raw path safety, symlinks/junctions, and directory ACLs
        verify_launch_checkout(chk_dir, chk_dir, os_)
        verify_launch_checkout(chk_dir, sub_cwd, os_)

        with pytest.raises(BrainError) as rel_exc:
            verify_launch_checkout(Path("relative/checkout"), sub_cwd, os_)
        assert rel_exc.value.code in (ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH)

        with pytest.raises(BrainError) as rel_cwd_exc:
            verify_launch_checkout(chk_dir, Path("relative/cwd"), os_)
        assert rel_cwd_exc.value.code in (ErrorCode.INVALID_INPUT, ErrorCode.UNSAFE_PATH)

        with monkeypatch.context() as mp:
            fake_link(mp, chk_dir)
            with pytest.raises(BrainError) as link_chk_exc:
                verify_launch_checkout(chk_dir, sub_cwd, os_)
            assert link_chk_exc.value.code == ErrorCode.UNSAFE_PATH

        with monkeypatch.context() as mp:
            fake_link(mp, sub_cwd)
            with pytest.raises(BrainError) as link_cwd_exc:
                verify_launch_checkout(chk_dir, sub_cwd, os_)
            assert link_cwd_exc.value.code == ErrorCode.UNSAFE_PATH

        _broaden_dir_permissions(sub_cwd)
        with pytest.raises(BrainError) as cwd_acl_exc:
            verify_launch_checkout(chk_dir, sub_cwd, os_)
        assert cwd_acl_exc.value.code == ErrorCode.INSECURE_PERMISSIONS
        os_.permissions.secure_directory(sub_cwd)

        _broaden_dir_permissions(chk_dir)
        with pytest.raises(BrainError) as chk_acl_exc:
            verify_launch_checkout(chk_dir, sub_cwd, os_)
        assert chk_acl_exc.value.code == ErrorCode.INSECURE_PERMISSIONS
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)
