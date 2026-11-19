"""SSH approval verifier (spec 11.3): real ``ssh-keygen -Y verify`` in namespace ``ensemble-brain-approval``.

The brain builds the one-line ``allowed_signers`` from the enrolled key, runs OpenSSH without a shell and with a
timeout, and always removes its private scratch files. OpenSSH 9.5 ``allowed_signers`` cannot express
``verify-required``, so for the ``sk-*`` channels the SSHSIG blob is parsed here *after* ``ssh-keygen`` accepted it to
read the FIDO flags byte (``UP`` for ``ssh_sk``, ``UP|UV`` for ``ssh_sk_verified``). Failures never leak OpenSSH output.
"""

from __future__ import annotations

import base64
import binascii
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from superbrain.adapters.os import os_adapters
from superbrain.core._kernel_approval import (
    APPROVAL_NAMESPACE,
    ApprovalChannel,
    ApprovalMessage,
    AssuranceLevel,
    assurance_for,
    parse_ssh_public_key,
)
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.ports.os import OsAdapters

_SK_PREFIX = "sk-"
_PRINCIPAL = "signer"
_TIMEOUT_SECONDS = 20
_MAX_SIGNATURE_BYTES = 16 * 1024
_MAX_MESSAGE_BYTES = 8 * 1024 * 1024
_KEY_TYPE_RE = re.compile(r"[a-z0-9][a-z0-9@.\-]{0,127}")
_ARMOR_BEGIN = b"-----BEGIN SSH SIGNATURE-----"
_ARMOR_END = b"-----END SSH SIGNATURE-----"
_SSHSIG_MAGIC = b"SSHSIG"
_FLAG_UP = 0x01
_FLAG_UV = 0x04
_VERIFIED_CHANNELS = frozenset({ApprovalChannel.SSH_KEY, ApprovalChannel.SSH_SK, ApprovalChannel.SSH_SK_VERIFIED})


def _unauthenticated() -> BrainError:
    return BrainError(ErrorCode.UNAUTHENTICATED, "unauthenticated")


def _invalid() -> BrainError:
    return BrainError(ErrorCode.INVALID_INPUT, "invalid input")


class _Reader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def take(self, count: int) -> bytes:
        end = self._pos + count
        if count < 0 or end > len(self._data):
            raise _unauthenticated()
        chunk = self._data[self._pos : end]
        self._pos = end
        return chunk

    def uint32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def string(self) -> bytes:
        return self.take(self.uint32())

    @property
    def exhausted(self) -> bool:
        return self._pos == len(self._data)


def _sk_flags(signature: bytes) -> int:
    """FIDO flags byte of an armored SSHSIG made by an ``sk-*`` key (call only after ``ssh-keygen`` verified it)."""
    lines = [line.strip() for line in signature.strip().splitlines()]
    if len(lines) < 3 or lines[0] != _ARMOR_BEGIN or lines[-1] != _ARMOR_END:
        raise _unauthenticated()
    try:
        raw = base64.b64decode(b"".join(lines[1:-1]), validate=True)
    except (binascii.Error, ValueError) as err:
        raise _unauthenticated() from err
    reader = _Reader(raw)
    if reader.take(len(_SSHSIG_MAGIC)) != _SSHSIG_MAGIC:
        raise _unauthenticated()
    if reader.uint32() != 1:
        raise _unauthenticated()
    reader.string()  # public key
    reader.string()  # namespace
    reader.string()  # reserved
    reader.string()  # hash algorithm
    inner_bytes = reader.string()
    if not reader.exhausted:
        raise _unauthenticated()
    inner = _Reader(inner_bytes)
    if not inner.string().startswith(_SK_PREFIX.encode()):
        raise _unauthenticated()
    inner.string()  # signature blob
    flags = inner.take(1)[0]
    inner.uint32()  # counter
    if not inner.exhausted:
        raise _unauthenticated()
    return flags


class SshSigVerifier:
    """Verifies SSHSIG approval signatures with the real ``ssh-keygen`` binary."""

    def __init__(self, *, ssh_keygen: Path, scratch_dir: Path, os_: OsAdapters | None = None) -> None:
        if not isinstance(ssh_keygen, Path) or not isinstance(scratch_dir, Path):
            raise _invalid()
        self._ssh_keygen = ssh_keygen
        self._scratch_dir = scratch_dir
        self._os = os_

    def verify(
        self,
        message: ApprovalMessage,
        *,
        channel: ApprovalChannel,
        public_key: str,
        signature: bytes,
        timeout_s: float | None = None,
    ) -> AssuranceLevel:
        if not isinstance(message, ApprovalMessage) or not isinstance(channel, ApprovalChannel):
            raise _invalid()
        if channel not in _VERIFIED_CHANNELS:
            raise _invalid()
        if not isinstance(signature, bytes) or not signature or len(signature) > _MAX_SIGNATURE_BYTES:
            raise _invalid()
        key_type, blob = parse_ssh_public_key(public_key)
        if _KEY_TYPE_RE.fullmatch(key_type) is None:
            raise _invalid()
        is_sk = key_type.startswith(_SK_PREFIX)
        if is_sk != (channel is not ApprovalChannel.SSH_KEY):
            raise _invalid()
        data = message.canonical_bytes()
        if len(data) > _MAX_MESSAGE_BYTES:
            raise _invalid()
        allowed_line = f'{_PRINCIPAL} namespaces="{APPROVAL_NAMESPACE}" {key_type} {blob}\n'
        effective_timeout = (
            _TIMEOUT_SECONDS
            if timeout_s is None
            else min(float(_TIMEOUT_SECONDS), max(0.05, timeout_s))
        )
        self._run_keygen(allowed_line, signature, data, timeout_s=effective_timeout)
        if is_sk:
            flags = _sk_flags(signature)
            if not flags & _FLAG_UP:
                raise _unauthenticated()
            if channel is ApprovalChannel.SSH_SK_VERIFIED and not flags & _FLAG_UV:
                raise _unauthenticated()
        return assurance_for(channel)

    def _run_keygen(self, allowed_line: str, signature: bytes, data: bytes, *, timeout_s: float) -> None:
        adapters = self._os if self._os is not None else os_adapters()
        adapters.paths.reject_unsafe_path(str(self._scratch_dir))
        adapters.paths.reject_links(self._scratch_dir)
        if adapters.permissions.check_ancestors(self._scratch_dir):
            raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
        try:
            workdir = Path(tempfile.mkdtemp(prefix="ssh-verify-", dir=self._scratch_dir))
        except OSError as err:
            raise _unauthenticated() from err
        try:
            adapters.paths.reject_links(workdir)
            if adapters.permissions.check_ancestors(workdir):
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
            adapters.permissions.secure_directory(workdir)
            if adapters.permissions.object_problems(workdir):
                raise BrainError(ErrorCode.INSECURE_PERMISSIONS, "insecure permissions")
            allowed = workdir / "allowed_signers"
            sig_file = workdir / "signature"
            allowed.write_bytes(allowed_line.encode("ascii"))
            sig_file.write_bytes(signature)
            adapters.permissions.secure_file(allowed)
            adapters.permissions.secure_file(sig_file)
            command = [
                str(self._ssh_keygen),
                "-Y",
                "verify",
                "-f",
                str(allowed),
                "-I",
                _PRINCIPAL,
                "-n",
                APPROVAL_NAMESPACE,
                "-s",
                str(sig_file),
            ]
            try:
                completed = subprocess.run(  # noqa: S603 - fixed argv, shell=False, brain-built files
                    command,
                    input=data,
                    capture_output=True,
                    check=False,
                    shell=False,
                    timeout=timeout_s,
                )
            except subprocess.TimeoutExpired as err:
                if timeout_s < _TIMEOUT_SECONDS:
                    raise BrainError(ErrorCode.DEADLINE_EXCEEDED, "deadline exceeded") from err
                raise _unauthenticated() from err
            except (OSError, subprocess.SubprocessError) as err:
                raise _unauthenticated() from err
            if completed.returncode != 0:
                raise _unauthenticated()
        except (OSError, UnicodeEncodeError) as err:
            raise _unauthenticated() from err
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


__all__ = ["SshSigVerifier"]
