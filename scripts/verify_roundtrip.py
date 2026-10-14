"""Close MATLAB P-code recovery evidence without executing any target."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tempfile
import zlib

from recover_pcode import read_legacy, sha256, RecoveryError

TOOL = "recover-matlab-pcode"
DECODED_STATUSES = {
    "decoded_unverified", "verified_payload_identical", "validation_failed",
    "source_changed", "input_changed", "payload_mismatch",
}
UNDECODED_STATUSES = {"unsupported_format", "decode_failed", "unresolved_tokens"}


class VerificationError(ValueError):
    """Invalid, stale, incomplete, or out-of-scope verification evidence."""


class RegeneratedChangedError(VerificationError):
    """The generated file no longer matches native validation evidence."""

def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def _load_json(path: Path) -> tuple[dict, bytes]:
    try:
        data = path.read_bytes()
        value = json.loads(data.decode("utf-8-sig"))
    except (OSError, UnicodeError, ValueError) as error:
        raise VerificationError(f"Cannot read JSON evidence {path}: {error}") from error
    if not isinstance(value, dict):
        raise VerificationError(f"JSON evidence must contain an object: {path}")
    return value, data


def _absolute(value: object, label: str) -> Path:
    if not isinstance(value, (str, os.PathLike)) or not str(value):
        raise VerificationError(f"{label} must be an absolute path")
    path = Path(value)
    if not path.is_absolute():
        raise VerificationError(f"{label} must be an absolute path")
    try:
        return path.resolve()
    except (OSError, RuntimeError) as error:
        raise VerificationError(f"Cannot resolve {label}: {error}") from error


def _relative(value: object) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or ":" in value:
        raise VerificationError("Invalid POSIX relative_path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise VerificationError("Invalid POSIX relative_path")
    path = PurePosixPath(value)
    if path.is_absolute() or path.suffix.lower() != ".p":
        raise VerificationError("relative_path must be a relative P-code path")
    return path


def _within(path: Path, root: Path) -> bool:
    return path == root or path.is_relative_to(root)


def _records(value: object, label: str) -> list[dict]:
    # MATLAB jsonencode emits a JSON object for a scalar struct.
    if isinstance(value, dict):
        return [value]
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise VerificationError(f"{label} must contain record objects")
    return value


def _issues(value: object) -> list[dict]:
    if value is None or value == []:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list) and all(isinstance(issue, dict) for issue in value):
        return value
    raise VerificationError("AnalyzerMessages must be an object or an array of objects")


def _validate_hash(value: object, label: str, optional: bool = False) -> None:
    if optional and value is None:
        return
    if not isinstance(value, str) or len(value) != 64 or any(c not in "0123456789abcdefABCDEF" for c in value):
        raise VerificationError(f"{label} must be a SHA-256 hex digest")


def _safe_output(path: Path, protected: set[Path], input_scope: Path,
                 input_is_directory: bool, manifest_path: Path) -> None:
    if path in protected or (input_is_directory and _within(path, input_scope)):
        raise VerificationError("Report output would overwrite a protected file or input scope")
    if path.suffix.lower() != ".json":
        raise VerificationError("Report output must have a .json extension")
    if path.exists():
        prior, _ = _load_json(path)
        if (prior.get("Tool") != TOOL or prior.get("Kind") != "roundtrip_validation"
                or _absolute(prior.get("ManifestPath"), "ManifestPath") != manifest_path):
            raise VerificationError("Refusing to overwrite an unrelated existing file")


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".pcode-validation-",
                                         suffix=".tmp", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def verify(manifest_path: Path, matlab_report_path: Path,
           output_path: Path | None = None) -> dict:
    """Verify native reencoding evidence, write a report, and update the manifest."""
    manifest_path = Path(manifest_path).expanduser().resolve()
    matlab_report_path = Path(matlab_report_path).expanduser().resolve()
    if manifest_path == matlab_report_path:
        raise VerificationError("The MATLAB report and manifest must be distinct files")
    manifest, manifest_bytes = _load_json(manifest_path)
    native, native_bytes = _load_json(matlab_report_path)
    if manifest.get("schema_version") != 1 or manifest.get("tool") != TOOL:
        raise VerificationError("Unsupported recovery manifest")
    if native.get("SchemaVersion") != 1 or native.get("Tool") != TOOL or native.get("Kind") != "matlab_validation":
        raise VerificationError("Unsupported MATLAB validation report")
    if _absolute(native.get("ManifestPath"), "ManifestPath") != manifest_path:
        raise VerificationError("MATLAB report refers to a different manifest")
    if native.get("ManifestSHA256") != sha256(manifest_bytes):
        raise VerificationError("MATLAB report is stale: manifest SHA-256 does not match")
    input_scope = _absolute(manifest.get("input_path"), "input_path")
    layout_root = _absolute(manifest.get("layout_root"), "layout_root")
    output_root = _absolute(manifest.get("output_dir"), "output_dir")
    verification_root = _absolute(native.get("VerificationRoot"), "VerificationRoot")
    if not _within(manifest_path, output_root):
        raise VerificationError("Manifest is outside output scope")
    input_is_directory = input_scope == layout_root or input_scope.is_dir()
    if (input_is_directory and (_within(output_root, input_scope) or _within(input_scope, output_root))
            or not input_is_directory and _within(input_scope, output_root)):
        raise VerificationError("Input and output scopes overlap")
    if (_within(verification_root, output_root) or _within(output_root, verification_root)
            or _within(input_scope, verification_root)
            or input_is_directory and _within(verification_root, input_scope)):
        raise VerificationError("Verification scope overlaps input or output scope")
    if not verification_root.is_dir():
        raise VerificationError("Verification scope directory is missing")
    files = _records(manifest.get("files"), "manifest files")
    native_records = _records(native.get("Records"), "MATLAB Records")
    index = {}
    for record in native_records:
        relative = _relative(record.get("RelativePath")).as_posix()
        key = relative.casefold() if os.name == "nt" else relative
        if key in index:
            raise VerificationError(f"Duplicate MATLAB record: {relative}")
        index[key] = record
    expected_keys = set()
    protected = {manifest_path, matlab_report_path}
    plans = []
    for item in files:
        relative = _relative(item.get("relative_path"))
        relative_text = relative.as_posix()
        key = relative_text.casefold() if os.name == "nt" else relative_text
        if key in expected_keys:
            raise VerificationError(f"Duplicate manifest record: {relative_text}")
        expected_keys.add(key)
        if key not in index:
            raise VerificationError(f"MATLAB report is missing record: {relative_text}")
        record = index[key]
        source_status = item.get("status")
        if source_status not in DECODED_STATUSES | UNDECODED_STATUSES:
            raise VerificationError(f"Unknown manifest status for {relative_text}: {source_status}")
        decode_status = item.get("decode_status", source_status)
        if decode_status not in DECODED_STATUSES | UNDECODED_STATUSES:
            raise VerificationError(f"Unknown preserved decode status for {relative_text}: {decode_status}")
        input_path = _absolute(item.get("input_path"), "input_path")
        expected_input = layout_root.joinpath(*relative.parts).resolve()
        if (input_path != expected_input or not _within(input_path, layout_root)
                or (input_is_directory and not _within(input_path, input_scope))
                or (not input_is_directory and input_path != input_scope)):
            raise VerificationError(f"Input is outside manifest scope: {relative_text}")
        if _absolute(record.get("InputPath"), "InputPath") != input_path:
            raise VerificationError(f"MATLAB InputPath is outside manifest scope: {relative_text}")
        protected.add(input_path)
        _validate_hash(item.get("input_sha256"), "input_sha256", decode_status in UNDECODED_STATUSES)
        source_path = None
        if item.get("source_path") is not None:
            source_path = _absolute(item["source_path"], "source_path")
            expected_source = output_root.joinpath("sources", *relative.with_suffix(".m").parts).resolve()
            if source_path != expected_source or not _within(source_path, output_root):
                raise VerificationError(f"Source is outside manifest scope: {relative_text}")
            if _absolute(record.get("SourcePath"), "SourcePath") != source_path:
                raise VerificationError(f"MATLAB SourcePath is outside manifest scope: {relative_text}")
            protected.add(source_path)
            _validate_hash(item.get("source_sha256"), "source_sha256")
        elif record.get("SourcePath") not in {"", None}:
            raise VerificationError(f"Unexpected MATLAB SourcePath: {relative_text}")
        issues = _issues(record.get("AnalyzerMessages"))
        regenerated = None
        if decode_status in DECODED_STATUSES:
            if source_path is None:
                raise VerificationError(f"Decoded source is missing from manifest: {relative_text}")
            if record.get("Status") not in {"reencoded", "failed"}:
                raise VerificationError(f"Decoded input has no native validation result: {relative_text}")
            regenerated = _absolute(record.get("RegeneratedPath"), "RegeneratedPath")
            expected_regenerated = verification_root.joinpath(*relative.with_suffix(".p").parts).resolve()
            if regenerated != expected_regenerated or not _within(regenerated, verification_root):
                raise VerificationError(f"Regenerated P-code is outside verification scope: {relative_text}")
            if record.get("Status") == "reencoded":
                _validate_hash(record.get("SourceSHA256"), "SourceSHA256")
                _validate_hash(record.get("RegeneratedSHA256"), "RegeneratedSHA256")
            protected.add(regenerated)
        elif record.get("Status") != "skipped_not_decoded":
            raise VerificationError(f"Undecoded input has contradictory MATLAB evidence: {relative_text}")
        evidence = item.get("evidence", {})
        if not isinstance(evidence, dict):
            raise VerificationError("Manifest evidence must be an object")
        for value in evidence.values():
            if isinstance(value, str):
                protected.add(_absolute(value, "evidence path"))
        plans.append((item, record, input_path, source_path, regenerated, issues, decode_status))
    unexpected = set(index) - expected_keys
    if unexpected:
        raise VerificationError(f"MATLAB report has out-of-scope records: {sorted(unexpected)}")
    report_path = (output_root / "roundtrip_validation.json" if output_path is None
                   else Path(output_path).expanduser().resolve())
    _safe_output(report_path, protected, input_scope, input_is_directory, manifest_path)
    results = []
    for item, record, input_path, source_path, regenerated, issues, decode_status in plans:
        decode_error = item.get("decode_error", item.get("error"))
        result = {
            "RelativePath": item["relative_path"], "InputPath": str(input_path),
            "SourcePath": str(source_path) if source_path else None,
            "RegeneratedPath": str(regenerated) if regenerated else None,
            "Status": decode_status, "DecodeStatus": decode_status, "InputSHA256": None,
            "SourceSHA256": None, "RegeneratedSHA256": None,
            "OriginalPayloadSHA256": None, "RegeneratedPayloadSHA256": None,
            "PayloadIdentical": None, "ByteIdentical": None,
            "AnalyzerMessages": issues, "AnalyzerCount": len(issues),
            "ErrorIdentifier": "", "ErrorMessage": "",
        }
        try:
            input_bytes = input_path.read_bytes()
            result["InputSHA256"] = sha256(input_bytes)
        except OSError as error:
            input_bytes = None
            input_read_error = str(error)
        else:
            input_read_error = ""
        if item.get("input_sha256") is not None and result["InputSHA256"] != item["input_sha256"]:
            result.update(Status="input_changed", ErrorIdentifier="Recovery:InputChanged",
                          ErrorMessage=input_read_error or "Original P-code SHA-256 changed since recovery")
        elif decode_status in UNDECODED_STATUSES:
            result["ErrorMessage"] = decode_error or ""
        else:
            try:
                source_hash = sha256(source_path.read_bytes())
                result["SourceSHA256"] = source_hash
            except OSError as error:
                source_hash = None
                source_read_error = str(error)
            else:
                source_read_error = ""
            if source_hash != item["source_sha256"] or (record.get("SourceSHA256") and source_hash != record["SourceSHA256"]):
                result.update(Status="source_changed", ErrorIdentifier="Recovery:SourceChanged",
                              ErrorMessage=source_read_error or "Source SHA-256 disagrees with recovery or MATLAB evidence")
            elif record["Status"] == "failed":
                result.update(Status="validation_failed",
                              ErrorIdentifier=record.get("ErrorIdentifier") or "Recovery:NativeValidationFailed",
                              ErrorMessage=record.get("ErrorMessage") or "MATLAB validation failed")
            else:
                try:
                    regenerated_bytes = regenerated.read_bytes()
                    result["RegeneratedSHA256"] = sha256(regenerated_bytes)
                    if result["RegeneratedSHA256"] != record["RegeneratedSHA256"]:
                        raise RegeneratedChangedError("Regenerated P-code SHA-256 changed after MATLAB validation")
                    result["ByteIdentical"] = input_bytes == regenerated_bytes
                    original_payload, regenerated_payload = {}, {}
                    read_legacy(input_bytes, original_payload)
                    read_legacy(regenerated_bytes, regenerated_payload)
                    result["OriginalPayloadSHA256"] = original_payload["decompressed_sha256"]
                    result["RegeneratedPayloadSHA256"] = regenerated_payload["decompressed_sha256"]
                    result["PayloadIdentical"] = (original_payload["decompressed_sha256"]
                                                  == regenerated_payload["decompressed_sha256"])
                    if result["PayloadIdentical"]:
                        result["Status"] = "verified_payload_identical"
                    else:
                        result.update(Status="payload_mismatch", ErrorIdentifier="Recovery:PayloadMismatch",
                                      ErrorMessage="Complete decompressed P-code payloads differ")
                    if sha256(source_path.read_bytes()) != source_hash:
                        result.update(Status="source_changed", ErrorIdentifier="Recovery:SourceChanged",
                                      ErrorMessage="Source changed while verifying")
                    elif sha256(input_path.read_bytes()) != result["InputSHA256"]:
                        result.update(Status="input_changed", ErrorIdentifier="Recovery:InputChanged",
                                      ErrorMessage="Original P-code changed while verifying")
                    elif sha256(regenerated.read_bytes()) != result["RegeneratedSHA256"]:
                        raise RegeneratedChangedError("Regenerated P-code changed while verifying")
                except (OSError, RecoveryError, ValueError, zlib.error) as error:
                    result.update(Status="validation_failed",
                                  ErrorIdentifier=("Recovery:RegeneratedChanged" if isinstance(error, RegeneratedChangedError)
                                                   else "Recovery:RoundTripFailed"),
                                  ErrorMessage=str(error))
        item["decode_status"] = decode_status
        item["decode_error"] = decode_error
        item["status"] = result["Status"]
        if item["status"] not in UNDECODED_STATUSES:
            item["error"] = result["ErrorMessage"] or None
        item["validation"] = {
            "matlab_report": str(matlab_report_path), "roundtrip_report": str(report_path),
            "payload_identical": result["PayloadIdentical"], "byte_identical": result["ByteIdentical"],
            "analyzer_count": result["AnalyzerCount"],
        }
        results.append(result)
    summary = dict(Counter(record["Status"] for record in results))
    all_verified = bool(results) and all(record["Status"] == "verified_payload_identical" for record in results)
    report = {
        "SchemaVersion": 1, "Tool": TOOL, "Kind": "roundtrip_validation",
        "ManifestPath": str(manifest_path), "ManifestSHA256Before": sha256(manifest_bytes),
        "MATLABReportPath": str(matlab_report_path), "MATLABReportSHA256": sha256(native_bytes),
        "VerificationRoot": str(verification_root), "CreatedUTC": datetime.now(timezone.utc).isoformat(),
        "AllVerified": all_verified, "Summary": summary, "Records": results,
    }
    manifest["count"] = len(files)
    manifest["summary"] = summary
    manifest["validation"] = {
        "matlab_report": str(matlab_report_path), "matlab_report_sha256": sha256(native_bytes),
        "roundtrip_report": str(report_path), "all_verified": all_verified,
    }
    updated_bytes = _json_bytes(manifest)
    report["ManifestSHA256After"] = sha256(updated_bytes)
    if manifest_path.read_bytes() != manifest_bytes or matlab_report_path.read_bytes() != native_bytes:
        raise VerificationError("Evidence became stale while verifying; no manifest update was made")
    _atomic_write(report_path, _json_bytes(report))
    _atomic_write(manifest_path, updated_bytes)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--matlab-report", required=True, type=Path)
    parser.add_argument("--output", type=Path, help="JSON report path (default: OUT/roundtrip_validation.json)")
    args = parser.parse_args(argv)
    try:
        result = verify(args.manifest, args.matlab_report, args.output)
    except (VerificationError, OSError) as error:
        print(f"{TOOL}: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"all_verified": result["AllVerified"], "summary": result["Summary"]}, ensure_ascii=False))
    return 0 if result["AllVerified"] else 1


if __name__ == "__main__":
    raise SystemExit(main())