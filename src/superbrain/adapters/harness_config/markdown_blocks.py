"""Markdown managed-block merger preserving surrounding user prose (spec 11.2, I3-2)."""

from __future__ import annotations

from superbrain.adapters.harness_config._common import check_clean_text, invalid_config, revision_conflict
from superbrain.core.canonical import digest_bytes
from superbrain.ports.proposals import MergeOutput

__all__ = ["merge_markdown_block", "remove_markdown_block"]


def _markers(slice_id: str) -> tuple[str, str]:
    if not isinstance(slice_id, str) or not slice_id or "\n" in slice_id or "\r" in slice_id or "\x00" in slice_id:
        raise invalid_config()
    return f"<!-- ensemble-brain:begin:{slice_id} -->", f"<!-- ensemble-brain:end:{slice_id} -->"


def _render_block(begin: str, body: str, end: str) -> str:
    clean_body = check_clean_text(body).replace("\r\n", "\n").strip("\n")
    if "<!-- ensemble-brain:" in clean_body:
        raise invalid_config("managed block body must not contain delimiter markers")
    if clean_body:
        return f"{begin}\n{clean_body}\n{end}"
    return f"{begin}\n{end}"


def _locate_block(text: str, begin: str, end: str) -> tuple[int, int] | None:
    b_idx = text.find(begin)
    e_idx = text.find(end)
    if b_idx == -1 and e_idx == -1:
        return None
    if b_idx == -1 or e_idx == -1 or e_idx < b_idx:
        raise revision_conflict("malformed managed block markers")
    if text.find(begin, b_idx + len(begin)) != -1 or text.find(end, e_idx + len(end)) != -1:
        raise revision_conflict("duplicate managed block markers")
    # Require markers on their own lines cleanly.
    if b_idx > 0 and text[b_idx - 1] != "\n":
        raise revision_conflict("malformed begin marker alignment")
    after_begin = b_idx + len(begin)
    if after_begin < len(text) and text[after_begin] not in ("\n", "\r"):
        raise revision_conflict("malformed begin marker line")
    line_before_end = e_idx - 1
    if line_before_end >= 0 and text[line_before_end] != "\n":
        raise revision_conflict("malformed end marker alignment")
    end_stop = e_idx + len(end)
    if end_stop < len(text) and text[end_stop] not in ("\n", "\r"):
        raise revision_conflict("malformed end marker line")
    return b_idx, end_stop


def _slice_digest(block_text: str) -> str:
    return digest_bytes(block_text.replace("\r\n", "\n").encode("utf-8"))


def merge_markdown_block(
    existing_text: str | None,
    *,
    slice_id: str,
    block_body: str,
    expected_slice_digest: str | None,
) -> MergeOutput:
    """Insert or update a delimited Markdown block without touching out-of-band user content."""
    text = check_clean_text(existing_text)
    begin, end = _markers(slice_id)
    rendered = _render_block(begin, block_body, end)
    new_digest = _slice_digest(rendered)
    span = _locate_block(text, begin, end)

    if span is None:
        if expected_slice_digest is not None:
            raise revision_conflict("expected managed block is missing")
        if not text:
            return MergeOutput(updated_text=rendered + "\n", slice_digest=new_digest, changed=True)
        sep = "" if text.endswith("\n") else "\n"
        prefix = text + sep
        if not prefix.endswith("\n\n"):
            prefix += "\n"
        return MergeOutput(updated_text=prefix + rendered + "\n", slice_digest=new_digest, changed=True)

    if expected_slice_digest is None:
        raise revision_conflict("unmanaged collision on existing managed block")
    start, stop = span
    current_block = text[start:stop]
    if _slice_digest(current_block) != expected_slice_digest:
        raise revision_conflict("managed block modified out-of-band")
    if current_block == rendered:
        return MergeOutput(updated_text=text, slice_digest=new_digest, changed=False)
    updated = text[:start] + rendered + text[stop:]
    return MergeOutput(updated_text=updated, slice_digest=new_digest, changed=True)


def remove_markdown_block(
    existing_text: str,
    *,
    slice_id: str,
    expected_slice_digest: str | None,
) -> MergeOutput:
    """Remove Brain's managed Markdown block while preserving surrounding user sections."""
    text = check_clean_text(existing_text)
    begin, end = _markers(slice_id)
    span = _locate_block(text, begin, end)
    if span is None:
        if expected_slice_digest is not None:
            raise revision_conflict("expected managed block is missing")
        return MergeOutput(updated_text=text, slice_digest=digest_bytes(b""), changed=False)

    start, stop = span
    current_block = text[start:stop]
    if expected_slice_digest is not None and _slice_digest(current_block) != expected_slice_digest:
        raise revision_conflict("managed block modified out-of-band")

    before = text[:start]
    after = text[stop:]
    eol = "\r\n" if "\r\n" in text else "\n"
    if after.startswith("\r\n"):
        after = after[2:]
    elif after.startswith("\n"):
        after = after[1:]
    before_clean = before.rstrip("\r\n")
    after_clean = after.lstrip("\r\n")
    if before_clean and after_clean:
        updated = before_clean + (eol * 2) + after_clean
    elif before_clean:
        updated = before_clean + eol
    else:
        updated = after_clean
    return MergeOutput(updated_text=updated, slice_digest=_slice_digest(current_block), changed=True)
