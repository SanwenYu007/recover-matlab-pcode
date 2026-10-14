"""Recover supported legacy MATLAB P-code into a fresh, portable evidence directory.

This decoder reads bytes only: it never executes input files. The observed
v01.00/v00.00 format and tables derive from Cognet-74/ptom_py; see the packaged
provenance. Decoding alone does not establish MATLAB equivalence.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import sys
import zlib

from pcode_tables import SCRAMBLE_TABLE, TOKEN_TABLE

SUPPORTED_HEADER = b"v01.00v00.00"
MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024
SPELLINGS = {
    1: "function ", 2: "function ", 3: "if ", 4: "switch ", 5: "try ",
    6: "while ", 7: "for ", 8: "end ", 9: "else ", 10: "elseif ",
    11: "break ", 12: "return ", 13: "parfor ", 15: "global ",
    16: "persistent ", 20: "catch ", 21: "continue ", 22: "case ",
    23: "otherwise ", 25: "classdef ", 28: "properties ", 30: "methods ",
    31: "events ", 32: "enumeration ", 33: "spmd ", 41: "end ", 47: "?",
    50: "; ", 51: ",", 52: "(", 53: ")", 54: "[", 55: "]", 56: "{",
    57: "}", 60: "'", 61: ".'", 62: "~", 63: "@", 70: "+", 71: "-",
    72: "*", 73: "/", 74: "\\", 75: "^", 76: ":", 80: ".", 81: ".*",
    82: "./", 83: ".\\", 84: ".^", 85: "&", 86: "|", 87: "&&", 88: "||",
    89: "<", 90: ">", 91: "<=", 92: ">=", 93: "==", 94: "~=", 95: "=",
    100: "\n", 101: "\n", 102: "\n", 103: "...\n",
}
BLOCK_OPENERS = {1, 2, 3, 4, 5, 6, 7, 13, 25, 28, 30, 31, 32, 33}
BRANCHES = {9, 10, 20, 22, 23}

class RecoveryError(ValueError):
    pass

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def read_legacy(data: bytes, record: dict) -> tuple[bytes, list[str], list[dict]]:
    if len(data) < 32:
        raise RecoveryError("Truncated 32-byte header")
    record["header_hex"] = data[:32].hex()
    if data[:12] != SUPPORTED_HEADER:
        raise RecoveryError(f"Unsupported version header: {data[:12]!r}")
    scramble, crc, reserved, compressed_size, decompressed_size = struct.unpack(">5I", data[12:32])
    record["header"] = {
        "major_version": data[:6].decode("ascii"),
        "minor_version": data[6:12].decode("ascii"),
        "scramble": scramble, "crc": crc, "reserved": reserved,
        "compressed_size": compressed_size, "decompressed_size": decompressed_size,
    }
    if compressed_size == 0 or decompressed_size < 28:
        raise RecoveryError("Invalid payload sizes")
    if decompressed_size > MAX_DECOMPRESSED_BYTES:
        raise RecoveryError("Declared decompressed payload exceeds 64 MiB limit")
    if len(data) != 32 + compressed_size:
        raise RecoveryError("Compressed size does not match exact file length")
    payload = bytearray(data[32:])
    seed = (scramble >> 12) & 255
    for word in range(len(payload) // 4):
        offset = word * 4
        value = int.from_bytes(payload[offset:offset + 4], "little")
        value ^= SCRAMBLE_TABLE[(word + seed) & 255]
        payload[offset:offset + 4] = value.to_bytes(4, "little")
    inflater = zlib.decompressobj()
    plain = inflater.decompress(payload, decompressed_size + 1)
    if len(plain) != decompressed_size or not inflater.eof or inflater.unconsumed_tail or inflater.unused_data:
        raise RecoveryError("Zlib payload is truncated, oversized, or has trailing data")
    record["decompression_success"] = True
    record["decompressed_sha256"] = sha256(plain)
    counts = struct.unpack(">7I", plain[:28])
    record["symbol_group_counts"] = list(counts)
    name_count = sum(counts)
    if name_count > len(plain) - 28:
        raise RecoveryError("Symbol count exceeds minimum available bytes")
    names = []
    offset = 28
    for index in range(name_count):
        end = plain.find(b"\0", offset)
        if end < 0:
            raise RecoveryError(f"Missing terminator for symbol {index}")
        try:
            names.append(plain[offset:end].decode("utf-8", errors="strict"))
        except UnicodeDecodeError as error:
            raise RecoveryError(f"Non-UTF-8 symbol {index}: {error}") from error
        offset = end + 1
    record["symbol_count"] = len(names)
    record["code_offset_in_decompressed"] = offset
    code = plain[offset:]
    tokens = []
    unknown = []
    position = 0
    while position < len(code):
        byte = code[position]
        if byte & 0x80:
            if position + 1 >= len(code):
                raise RecoveryError(f"Truncated symbol reference at token byte {position}")
            index = 128 + 256 * ((byte & 0x7F) - 1) + code[position + 1]
            if not 0 <= index < len(names):
                raise RecoveryError(f"Out-of-range symbol {index} at token byte {position}")
            tokens.append({"offset": position, "kind": "symbol", "id": index, "text": names[index]})
            position += 2
        else:
            token = {"offset": position, "kind": "token", "id": byte, "text": SPELLINGS.get(byte)}
            tokens.append(token)
            if token["text"] is None:
                unknown.append({"offset": position, "id": byte,
                                "upstream_text": TOKEN_TABLE[byte] if byte < len(TOKEN_TABLE) else None})
            position += 1
    record["unknown_tokens"] = unknown
    record["token_count"] = len(tokens)
    record["token_bytes"] = len(code)
    record["token_sha256"] = sha256(code)
    record["token_histogram"] = dict(sorted(Counter(t["id"] for t in tokens if t["kind"] == "token").items()))
    if unknown:
        record["recovery_status"] = "unresolved_tokens"
    return code, names, tokens

def render(tokens: list[dict]) -> str:
    """Add layout at token boundaries; never transform any symbol's text."""
    lines, parts = [], []
    depth, line_depth = 0, 0
    first_token, continuation = True, False
    for position, token in enumerate(tokens):
        token_id = token["id"] if token["kind"] == "token" else None
        if first_token:
            if token_id == 8:
                depth = max(depth - 1, 0)
            line_depth = max(depth - (token_id in BRANCHES), 0) + int(continuation)
            if token_id in BLOCK_OPENERS:
                depth += 1
            first_token = False
        if token_id in {100, 101, 102, 103}:
            if token_id == 103:
                parts.append("...")
            line = "".join(parts).rstrip(" ")
            lines.append(("    " * line_depth + line) if line else "")
            parts, first_token = [], True
            continuation = token_id == 103
        elif token["kind"] == "symbol":
            previous = tokens[position - 1] if position > 0 else None
            if previous and (previous["kind"] == "symbol" or
                             (previous["kind"] == "token" and previous["id"] in {53, 55, 57, 60, 61})):
                parts.append(" ")
            parts.append(token["text"])
        elif token["text"] is None:
            parts.append(f"[UNRESOLVED_TOKEN_{token['id']}_AT_{token['offset']}]")
        else:
            parts.append(token["text"])
    if parts:
        lines.append("    " * line_depth + "".join(parts).rstrip(" "))
    # MATLAB's pcode payload records an EOF newline as a distinct token.
    # Preserve its presence instead of introducing an extra terminal token.
    has_terminal_newline = bool(tokens) and tokens[-1]["kind"] == "token" and tokens[-1]["id"] in {100, 101, 102, 103}
    return "\n".join(lines) + ("\n" if has_terminal_newline else "")


def _is_link(path: Path) -> bool:
    """Include Windows junctions and other reparse points, even on older Python."""
    info = path.lstat()
    return stat.S_ISLNK(info.st_mode) or bool(
        getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def _within(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def _validate_input_path(path: Path, root: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RecoveryError(f"Cannot resolve input path {path}: {error}") from error
    if not _within(resolved, root):
        raise RecoveryError(f"Input symlink or junction escapes the input tree: {path}")
    return resolved


def _collect_inputs(input_path: Path) -> tuple[Path, list[Path]]:
    if input_path.is_file():
        if input_path.suffix.lower() != ".p":
            raise RecoveryError("A single input file must have a .p extension")
        layout_root = input_path.parent
        while layout_root.name.startswith(("+", "@")):
            layout_root = layout_root.parent
        return layout_root, [input_path]
    if not input_path.is_dir():
        raise RecoveryError(f"Input is not a regular file or directory: {input_path}")
    found = []

    def visit(directory: Path, active: set[Path]) -> None:
        resolved = _validate_input_path(directory, input_path)
        if resolved in active:
            raise RecoveryError(f"Input directory link forms a cycle: {directory}")
        active = active | {resolved}
        for child in sorted(directory.iterdir(), key=lambda item: (item.name.casefold(), item.name)):
            target = _validate_input_path(child, input_path)
            if target.is_dir():
                visit(child, active)
            elif target.is_file() and child.suffix.lower() == ".p":
                found.append(child)

    visit(input_path, set())
    return input_path, found


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(path.expanduser()))


def _check_output_path(output_path: Path, input_path: Path) -> None:
    for candidate in (output_path, *output_path.parents):
        try:
            if _is_link(candidate):
                raise RecoveryError(f"Output symlink or junction is not allowed: {candidate}")
        except FileNotFoundError:
            continue
    if input_path.is_dir() and (
        _within(output_path, input_path) or _within(input_path, output_path)
    ):
        raise RecoveryError("Output directory must not overlap the input directory")
    if input_path.is_file() and _within(input_path, output_path):
        raise RecoveryError("Output directory must not contain the input file")


def _prepare_output(input_path: Path, output_path: Path | None) -> Path:
    if output_path is None:
        name = input_path.stem if input_path.is_file() else input_path.name
        base = input_path.parent / f"{name}_recovered"
        suffix = 0
        while True:
            candidate = base if suffix == 0 else base.with_name(f"{base.name}_{suffix}")
            if os.path.lexists(candidate):
                suffix += 1
                continue
            _check_output_path(candidate, input_path)
            try:
                candidate.mkdir()
            except FileExistsError:
                suffix += 1
                continue
            return candidate
    candidate = _lexical_absolute(output_path)
    _check_output_path(candidate, input_path)
    if candidate.exists():
        if not candidate.is_dir():
            raise RecoveryError(f"Output is not a directory: {candidate}")
        if next(candidate.iterdir(), None) is not None:
            raise RecoveryError(f"Output directory must be empty: {candidate}")
    else:
        candidate.mkdir(parents=True)
    return candidate


def _write_new(path: Path, content: bytes, output_root: Path) -> None:
    """Create a new artifact exclusively; never replace an existing path."""
    if not _within(path, output_root):
        raise RecoveryError(f"Artifact path escapes output directory: {path}")
    for candidate in (path, *path.parents):
        if candidate == output_root.parent:
            break
        try:
            if _is_link(candidate):
                raise RecoveryError(f"Output symlink or junction is not allowed: {candidate}")
        except FileNotFoundError:
            continue
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(content)


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def recover(input_path: Path, output_path: Path | None = None) -> dict:
    """Decode one .p file or a directory tree and return its written manifest."""
    try:
        input_path = input_path.expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RecoveryError(f"Cannot resolve input: {error}") from error
    layout_root, paths = _collect_inputs(input_path)
    if not paths:
        raise RecoveryError("Input directory contains no .p files")
    # A .p/.P pair with the same stem must never compete for an artifact path.
    artifact_names = set()
    for path in paths:
        key = path.relative_to(layout_root).with_suffix(".m").as_posix().casefold()
        if key in artifact_names:
            raise RecoveryError(f"Inputs have colliding source output paths: {path}")
        artifact_names.add(key)
    output_root = _prepare_output(input_path, output_path)
    records = []
    for path in paths:
        relative = path.relative_to(layout_root)
        record = {
            "relative_path": relative.as_posix(),
            "input_path": str(path),
            "input_sha256": None,
            "input_size": None,
            "source_path": None,
            "source_sha256": None,
            "status": "decode_failed",
            "error": None,
            "unknown_tokens": [],
            "evidence": {},
            "decompression_success": False,
        }
        try:
            _validate_input_path(path, input_path if input_path.is_dir() else layout_root)
            data = path.read_bytes()
            record["input_size"] = len(data)
            record["input_sha256"] = sha256(data)
            if data[:12] != SUPPORTED_HEADER and not SUPPORTED_HEADER.startswith(data):
                record["status"] = "unsupported_format"
                raise RecoveryError(f"Unsupported version header: {data[:12]!r}")
            code, names, tokens = read_legacy(data, record)
            evidence_base = output_root / "evidence" / relative
            token_path = evidence_base.with_suffix(".tokens.bin")
            symbol_path = evidence_base.with_suffix(".symbols.json")
            sequence_path = evidence_base.with_suffix(".tokens.json")
            _write_new(token_path, code, output_root)
            _write_new(symbol_path, _json_bytes(names), output_root)
            _write_new(sequence_path, _json_bytes(tokens), output_root)
            record["evidence"] = {
                "token_bytes": str(token_path),
                "symbols": str(symbol_path),
                "tokens": str(sequence_path),
            }
            if record["unknown_tokens"]:
                record["status"] = "unresolved_tokens"
                record["error"] = f"Unresolved token IDs: {sorted({t['id'] for t in record['unknown_tokens']})}"
            else:
                target = output_root / "sources" / relative.with_suffix(".m")
                source = render(tokens).encode("utf-8")
                _write_new(target, source, output_root)
                record["source_path"] = str(target)
                record["source_sha256"] = sha256(source)
                record["status"] = "decoded_unverified"
        except (RecoveryError, ValueError, zlib.error, OSError) as error:
            record["error"] = str(error)
        records.append(record)
    manifest = {
        "schema_version": 1,
        "tool": "recover-matlab-pcode",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "format_scope": SUPPORTED_HEADER.decode("ascii"),
        "input_path": str(input_path),
        "layout_root": str(layout_root),
        "output_dir": str(output_root),
        "count": len(records),
        "summary": dict(Counter(record["status"] for record in records)),
        "files": records,
    }
    _write_new(output_root / "recovery_manifest.json", _json_bytes(manifest), output_root)
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="A .p file or a directory containing .p files")
    parser.add_argument("--output", type=Path, help="A nonexistent or empty directory (default: a fresh adjacent *_recovered directory)")
    args = parser.parse_args(argv)
    try:
        manifest = recover(args.input, args.output)
    except (RecoveryError, OSError) as error:
        print(f"recover-matlab-pcode: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"count": manifest["count"], "summary": manifest["summary"],
                      "manifest": str(Path(manifest["output_dir"]) / "recovery_manifest.json")}, ensure_ascii=False))
    return int(any(record["status"] != "decoded_unverified" for record in manifest["files"]))


if __name__ == "__main__":
    raise SystemExit(main())