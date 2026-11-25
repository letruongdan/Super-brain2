"""Shared ``ConfigMergerPort`` adapter dispatching Markdown, JSON and TOML slice operations."""

from __future__ import annotations

from collections.abc import Mapping

import tomlkit
from tomlkit.exceptions import TOMLKitError

from superbrain.adapters.harness_config._common import digest_json_value, invalid_config, revision_conflict
from superbrain.adapters.harness_config.json_keys import _parse_json_root, merge_json_keys, remove_json_keys
from superbrain.adapters.harness_config.markdown_blocks import merge_markdown_block, remove_markdown_block
from superbrain.adapters.harness_config.toml_tables import merge_toml_table, remove_toml_table
from superbrain.core._json_parse import parse_json
from superbrain.core.proposals import ManagedFormat
from superbrain.ports.proposals import ConfigMergerPort, MergeOutput

__all__ = ["SharedConfigMergerAdapter"]


def _dotted_path(slice_id: str) -> tuple[str, ...]:
    parts = tuple(seg for seg in slice_id.split(".") if seg)
    if not parts or ".".join(parts) != slice_id:
        raise invalid_config()
    return parts


class SharedConfigMergerAdapter(ConfigMergerPort):
    """Implements ``ConfigMergerPort`` for Markdown, JSON and TOML shared harness configs."""

    def apply_slice(
        self,
        existing_text: str | None,
        *,
        managed_format: ManagedFormat,
        slice_id: str,
        replacement_bytes: bytes,
        expected_slice_digest: str | None,
    ) -> MergeOutput:
        try:
            body_text = replacement_bytes.decode("utf-8")
        except UnicodeDecodeError as err:
            raise invalid_config("slice payload is not valid UTF-8") from err

        if managed_format is ManagedFormat.MARKDOWN:
            return merge_markdown_block(
                existing_text,
                slice_id=slice_id,
                block_body=body_text,
                expected_slice_digest=expected_slice_digest,
            )
        if managed_format is ManagedFormat.JSON:
            parsed = parse_json(replacement_bytes)
            return merge_json_keys(
                existing_text,
                key_path=_dotted_path(slice_id),
                value=parsed,
                expected_slice_digest=expected_slice_digest,
            )
        if managed_format is ManagedFormat.TOML:
            try:
                parsed_toml = tomlkit.parse(body_text).unwrap()
            except TOMLKitError as err:
                raise invalid_config(f"malformed TOML slice: {err}") from err
            if not isinstance(parsed_toml, Mapping):
                raise invalid_config()
            return merge_toml_table(
                existing_text,
                table_path=_dotted_path(slice_id),
                values=parsed_toml,
                expected_slice_digest=expected_slice_digest,
            )
        raise invalid_config()

    def remove_slice(
        self,
        existing_text: str,
        *,
        managed_format: ManagedFormat,
        slice_id: str,
        expected_slice_digest: str | None,
    ) -> MergeOutput:
        if managed_format is ManagedFormat.MARKDOWN:
            return remove_markdown_block(
                existing_text,
                slice_id=slice_id,
                expected_slice_digest=expected_slice_digest,
            )
        if managed_format is ManagedFormat.JSON:
            if "," in slice_id:
                slice_parts = [part for part in slice_id.split(",")]
                paths = [_dotted_path(part) for part in slice_parts]
                doc = _parse_json_root(existing_text)
                extracted: dict[str, object] = {}
                for part, kp in zip(slice_parts, paths, strict=True):
                    cursor: object = doc
                    for seg in kp:
                        if not isinstance(cursor, Mapping) or seg not in cursor:
                            raise revision_conflict("expected JSON slice is missing")
                        cursor = cursor[seg]
                    extracted[part] = cursor
                if expected_slice_digest is not None and digest_json_value(extracted) != expected_slice_digest:  # type: ignore[arg-type]
                    raise revision_conflict("JSON managed key modified out-of-band")
                cur_text = existing_text
                changed = False
                for kp in paths:
                    out = remove_json_keys(cur_text, key_path=kp, expected_slice_digest=None)
                    cur_text = out.updated_text
                    changed = changed or out.changed
                return MergeOutput(
                    updated_text=cur_text,
                    slice_digest=digest_json_value(extracted),  # type: ignore[arg-type]
                    changed=changed,
                )
            return remove_json_keys(
                existing_text,
                key_path=_dotted_path(slice_id),
                expected_slice_digest=expected_slice_digest,
            )
        if managed_format is ManagedFormat.TOML:
            return remove_toml_table(
                existing_text,
                table_path=_dotted_path(slice_id),
                expected_slice_digest=expected_slice_digest,
            )
        raise invalid_config()
