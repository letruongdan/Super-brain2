"""Canonical MCP v2 schema catalog loader and self-contained ``$defs`` closure builder."""

from __future__ import annotations

import copy
import hashlib
import importlib.resources
import tomllib
from collections.abc import Callable
from pathlib import Path
from types import MappingProxyType

from superbrain.core.canonical import digest_bytes
from superbrain.core.errors import BrainError, ErrorCode
from superbrain.core.jsonvalue import JsonValue
from superbrain.core.kernel import ToolCatalog, ToolSpec

DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
CANONICAL_SCHEMA_ID = "https://ensemble-agents.local/superbrain/mcp-tools-v2.json"
CONTRACT_NAME = "mcp-tools-v2"
TOKENIZER_NAME = "utf8-byte-v1"
RESOLUTION_NAME = "single-checkout-owner-profile-v1"

EXPECTED_TOOL_ORDER: tuple[str, ...] = (
    "prepare_task",
    "search_knowledge",
    "get_artifact",
    "submit_episode",
    "record_outcome",
    "request_improvement",
    "get_job",
    "get_health",
)

_CACHED_CATALOG: ToolCatalog | None = None


def _read_schema_bytes() -> bytes:
    """Read packaged wheel schema first; fallback only to verified super-brain2 source root."""
    packaged = importlib.resources.files("superbrain.core").joinpath("data", "mcp-tools-v2.json")
    if packaged.is_file():
        return packaged.read_bytes()

    module_path = Path(__file__).resolve()
    if len(module_path.parents) < 4:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
    repo_root = module_path.parents[3]
    expected_core = repo_root / "src" / "superbrain" / "core"
    pyproject_path = repo_root / "pyproject.toml"
    schema_path = repo_root / "schemas" / "mcp-tools-v2.json"

    if (
        not expected_core.is_dir()
        or expected_core.resolve() != module_path.parent
        or pyproject_path.is_symlink()
        or not pyproject_path.is_file()
        or schema_path.is_symlink()
        or not schema_path.is_file()
    ):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

    try:
        pyproject_data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as err:
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure") from err

    project_section = pyproject_data.get("project")
    if not isinstance(project_section, dict) or project_section.get("name") != "super-brain2":
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

    try:
        return schema_path.read_bytes()
    except OSError as err:
        raise BrainError(ErrorCode.IO_ERROR, "I/O error") from err


def _collect_local_def_refs(node: JsonValue) -> set[str]:
    found: set[str] = set()
    stack: list[JsonValue] = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            ref = current.get("$ref")
            if isinstance(ref, str):
                if not ref.startswith("#/$defs/"):
                    raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
                found.add(ref.removeprefix("#/$defs/"))
            for key, child in current.items():
                if key != "$defs":
                    stack.append(child)
        elif isinstance(current, list):
            stack.extend(current)
    return found


def _build_defs_closure(
    body: dict[str, JsonValue],
    root_defs: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    needed: set[str] = set()
    frontier = list(_collect_local_def_refs(body))
    while frontier:
        def_name = frontier.pop()
        target = root_defs.get(def_name)
        if not isinstance(target, dict):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        if def_name not in needed:
            needed.add(def_name)
            frontier.extend(_collect_local_def_refs(target))
    return {name: copy.deepcopy(root_defs[name]) for name in sorted(needed)}


def _clone_catalog(template: ToolCatalog) -> ToolCatalog:
    cloned_tools: dict[str, ToolSpec] = {}
    for name, spec in template.tools.items():
        cloned_tools[name] = ToolSpec(
            name=spec.name,
            description=spec.description,
            contract=spec.contract,
            tokenizer=spec.tokenizer,
            side_effects=spec.side_effects,
            is_async=spec.is_async,
            implemented_in=spec.implemented_in,
            client_input_ref=spec.client_input_ref,
            daemon_input_ref=spec.daemon_input_ref,
            result_ref=spec.result_ref,
            input_schema=copy.deepcopy(spec.input_schema),
            output_schema=copy.deepcopy(spec.output_schema),
        )
    return ToolCatalog(
        contract=template.contract,
        schema_id=template.schema_id,
        tokenizer=template.tokenizer,
        resolution=template.resolution,
        schema_sha256=template.schema_sha256,
        schema_digest=template.schema_digest,
        raw_bytes=template.raw_bytes,
        schema=copy.deepcopy(template.schema),
        tools=MappingProxyType(cloned_tools),
    )


def build_catalog(parser: Callable[[bytes], JsonValue]) -> ToolCatalog:
    """Load, verify, and cache the canonical MCP v2 catalog using ``parser``."""
    global _CACHED_CATALOG
    if _CACHED_CATALOG is not None:
        return _clone_catalog(_CACHED_CATALOG)

    raw_bytes = _read_schema_bytes()
    parsed = parser(raw_bytes)
    if not isinstance(parsed, dict):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

    schema_uri = parsed.get("$schema")
    schema_id = parsed.get("$id")
    contract = parsed.get("x-contract")
    tokenizer = parsed.get("x-tokenizer")
    resolution = parsed.get("x-resolution")
    raw_defs = parsed.get("$defs")
    raw_tools = parsed.get("x-tools")

    if (
        schema_uri != DRAFT_2020_12
        or schema_id != CANONICAL_SCHEMA_ID
        or contract != CONTRACT_NAME
        or tokenizer != TOKENIZER_NAME
        or resolution != RESOLUTION_NAME
        or not isinstance(raw_defs, dict)
        or not isinstance(raw_tools, dict)
        or tuple(raw_tools.keys()) != EXPECTED_TOOL_ORDER
    ):
        raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

    specs: dict[str, ToolSpec] = {}
    for name in EXPECTED_TOOL_ORDER:
        meta = raw_tools.get(name)
        if not isinstance(meta, dict):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")
        description = meta.get("description")
        t_contract = meta.get("x-contract")
        t_tokenizer = meta.get("x-tokenizer")
        side_effects = meta.get("x-side-effects")
        is_async = meta.get("x-async")
        implemented_in = meta.get("x-implemented-in")
        client_ref = meta.get("client_input_ref")
        daemon_ref = meta.get("daemon_input_ref")
        result_ref = meta.get("result_ref")

        if (
            not isinstance(description, str)
            or t_contract != CONTRACT_NAME
            or t_tokenizer != TOKENIZER_NAME
            or not isinstance(side_effects, str)
            or not isinstance(is_async, bool)
            or not isinstance(implemented_in, str)
            or not isinstance(client_ref, str)
            or not client_ref.startswith("#/$defs/")
            or not isinstance(daemon_ref, str)
            or not daemon_ref.startswith("#/$defs/")
            or not isinstance(result_ref, str)
            or not result_ref.startswith("#/$defs/")
        ):
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

        client_def = raw_defs.get(client_ref.removeprefix("#/$defs/"))
        if not isinstance(client_def, dict) or client_def.get("type") != "object":
            raise BrainError(ErrorCode.INTEGRITY_FAILURE, "integrity failure")

        input_body = copy.deepcopy(client_def)
        input_closure = _build_defs_closure(input_body, raw_defs)
        input_schema: dict[str, JsonValue] = {
            "$schema": DRAFT_2020_12,
            **input_body,
            "$defs": input_closure,
        }

        output_body: dict[str, JsonValue] = {
            "$schema": DRAFT_2020_12,
            "type": "object",
            "oneOf": [
                {
                    "type": "object",
                    "additionalProperties": False,
                    "required": ["ok", "data"],
                    "properties": {
                        "ok": {"type": "boolean", "const": True},
                        "data": {"$ref": result_ref},
                    },
                },
                {"$ref": "#/$defs/ErrorEnvelope"},
            ],
        }
        output_closure = _build_defs_closure(output_body, raw_defs)
        output_schema: dict[str, JsonValue] = {
            **output_body,
            "$defs": output_closure,
        }

        specs[name] = ToolSpec(
            name=name,
            description=description,
            contract=t_contract,
            tokenizer=t_tokenizer,
            side_effects=side_effects,
            is_async=is_async,
            implemented_in=implemented_in,
            client_input_ref=client_ref,
            daemon_input_ref=daemon_ref,
            result_ref=result_ref,
            input_schema=input_schema,
            output_schema=output_schema,
        )

    _CACHED_CATALOG = ToolCatalog(
        contract=CONTRACT_NAME,
        schema_id=CANONICAL_SCHEMA_ID,
        tokenizer=TOKENIZER_NAME,
        resolution=RESOLUTION_NAME,
        schema_sha256=hashlib.sha256(raw_bytes).hexdigest(),
        schema_digest=digest_bytes(raw_bytes),
        raw_bytes=raw_bytes,
        schema=copy.deepcopy(parsed),
        tools=MappingProxyType(specs),
    )
    return _clone_catalog(_CACHED_CATALOG)
