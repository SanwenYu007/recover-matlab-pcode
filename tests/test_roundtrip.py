"""Round-trip evidence tests; targets are never executed."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))


def load_verifier():
    spec = importlib.util.spec_from_file_location("verify_roundtrip", SCRIPTS / "verify_roundtrip.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RoundTripTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((SCRIPTS / "verify_roundtrip.py").is_file(),
                        "Portable round-trip verifier has not been implemented")
        self.verify_module = load_verifier()
        from recover_pcode import sha256, SCRAMBLE_TABLE
        self.hash = sha256
        self.table = SCRAMBLE_TABLE
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / "input"
        self.output = self.root / "output"
        self.verification = self.root / "native-temp"
        for folder in (self.inputs, self.output, self.verification):
            folder.mkdir()
        self.input = self.inputs / "unit.p"
        self.source = self.output / "sources" / "unit.m"
        self.source.parent.mkdir()
        self.regenerated = self.verification / "unit.p"
        self.input.write_bytes(self.fixture())
        self.source.write_text("function x = unit\nx = 1;\nend\n", encoding="utf-8")
        self.regenerated.write_bytes(self.fixture(wrapper=(4096, 42, 9)))
        self.manifest_path = self.output / "recovery_manifest.json"
        self.matlab_path = self.output / "matlab_validation.json"
        self.manifest = {
            "schema_version": 1, "tool": "recover-matlab-pcode",
            "input_path": str(self.inputs), "layout_root": str(self.inputs),
            "output_dir": str(self.output), "files": [self.manifest_record()],
        }
        self.report = {
            "SchemaVersion": 1, "Tool": "recover-matlab-pcode",
            "Kind": "matlab_validation", "ManifestPath": str(self.manifest_path),
            "VerificationRoot": str(self.verification), "Records": [self.native_record()],
        }
        self.save()

    def fixture(self, token=100, wrapper=(0, 0, 0)):
        plain = struct.pack(">7I", 1, 0, 0, 0, 0, 0, 0) + b"unit\0\x80\x80" + bytes([token])
        encoded = bytearray(zlib.compress(plain))
        seed = (wrapper[0] >> 12) & 255
        for word in range(len(encoded) // 4):
            offset = 4 * word
            value = int.from_bytes(encoded[offset:offset + 4], "little")
            encoded[offset:offset + 4] = (value ^ self.table[(word + seed) & 255]).to_bytes(4, "little")
        return b"v01.00v00.00" + struct.pack(">5I", *wrapper, len(encoded), len(plain)) + encoded

    def manifest_record(self):
        return {"relative_path": "unit.p", "input_path": str(self.input),
                "input_sha256": self.hash(self.input.read_bytes()),
                "source_path": str(self.source),
                "source_sha256": self.hash(self.source.read_bytes()),
                "status": "decoded_unverified", "error": None,
                "unknown_tokens": [], "evidence": {}}

    def native_record(self):
        return {"RelativePath": "unit.p", "InputPath": str(self.input),
                "SourcePath": str(self.source), "RegeneratedPath": str(self.regenerated),
                "Status": "reencoded", "AnalyzerMessages": [],
                "SourceSHA256": self.hash(self.source.read_bytes()),
                "RegeneratedSHA256": self.hash(self.regenerated.read_bytes()),
                "ErrorIdentifier": "", "ErrorMessage": ""}

    def save(self):
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        self.report["ManifestSHA256"] = self.hash(self.manifest_path.read_bytes())
        self.matlab_path.write_text(json.dumps(self.report), encoding="utf-8")

    def run_verify(self, output=None):
        return self.verify_module.verify(self.manifest_path, self.matlab_path, output)

    def test_same_payload_different_wrapper_is_verified(self):
        source_bytes = self.source.read_bytes()
        result = self.run_verify()
        record = result["Records"][0]
        self.assertTrue(record["PayloadIdentical"])
        self.assertFalse(record["ByteIdentical"])
        self.assertEqual(record["Status"], "verified_payload_identical")
        self.assertEqual(self.source.read_bytes(), source_bytes)
        updated = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(updated["files"][0]["status"], "verified_payload_identical")

    def test_uppercase_input_extension_uses_lowercase_regenerated_extension(self):
        uppercase_input = self.inputs / "unit.P"
        self.input.rename(uppercase_input)
        self.input = uppercase_input
        self.manifest["files"][0]["relative_path"] = "unit.P"
        self.manifest["files"][0]["input_path"] = str(uppercase_input)
        self.report["Records"][0]["RelativePath"] = "unit.P"
        self.report["Records"][0]["InputPath"] = str(uppercase_input)
        self.save()
        self.assertEqual(self.run_verify()["Records"][0]["Status"], "verified_payload_identical")

    def test_scalar_native_record_is_supported(self):
        self.report["Records"] = self.report["Records"][0]
        self.save()
        self.assertTrue(self.run_verify()["AllVerified"])
    def test_regenerated_file_change_after_native_report_is_detected(self):
        self.regenerated.write_bytes(self.input.read_bytes())
        result = self.run_verify()
        self.assertEqual(result["Records"][0]["Status"], "validation_failed")
        self.assertEqual(result["Records"][0]["ErrorIdentifier"], "Recovery:RegeneratedChanged")
        self.assertIsNone(result["Records"][0]["PayloadIdentical"])
    def test_payload_mismatch_is_not_verified(self):
        self.regenerated.write_bytes(self.fixture(token=101))
        self.report["Records"][0]["RegeneratedSHA256"] = self.hash(self.regenerated.read_bytes())
        self.save()
        result = self.run_verify()
        self.assertEqual(result["Records"][0]["Status"], "payload_mismatch")
        self.assertFalse(result["Records"][0]["PayloadIdentical"])

    def test_source_change_after_native_report_is_detected(self):
        self.source.write_text("changed source", encoding="utf-8")
        result = self.run_verify()
        self.assertEqual(result["Records"][0]["Status"], "source_changed")

    def test_source_report_hash_disagreement_is_detected(self):
        self.report["Records"][0]["SourceSHA256"] = "0" * 64
        self.save()
        self.assertEqual(self.run_verify()["Records"][0]["Status"], "source_changed")

    def test_input_change_is_detected(self):
        self.input.write_bytes(self.fixture(token=101))
        self.assertEqual(self.run_verify()["Records"][0]["Status"], "input_changed")

    def test_missing_native_record_is_rejected(self):
        self.report["Records"] = []
        self.save()
        before = self.manifest_path.read_bytes()
        with self.assertRaisesRegex(self.verify_module.VerificationError, "missing"):
            self.run_verify()
        self.assertEqual(self.manifest_path.read_bytes(), before)

    def test_stale_manifest_report_is_rejected(self):
        self.manifest["new_metadata"] = "new run"
        self.manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        with self.assertRaisesRegex(self.verify_module.VerificationError, "stale"):
            self.run_verify()

    def test_regenerated_outside_verification_root_is_rejected(self):
        self.report["Records"][0]["RegeneratedPath"] = str(self.input)
        self.save()
        with self.assertRaisesRegex(self.verify_module.VerificationError, "scope"):
            self.run_verify()

    def test_input_outside_manifest_scope_is_rejected(self):
        alien = self.root / "alien.p"
        alien.write_bytes(self.fixture())
        self.manifest["files"][0]["input_path"] = str(alien)
        self.report["Records"][0]["InputPath"] = str(alien)
        self.save()
        with self.assertRaisesRegex(self.verify_module.VerificationError, "scope"):
            self.run_verify()

    def test_mixed_unsupported_batch_remains_partial(self):
        unsupported = self.inputs / "modern.p"
        unsupported.write_bytes(b"unsupported container")
        self.manifest["files"].append({
            "relative_path": "modern.p", "input_path": str(unsupported),
            "input_sha256": self.hash(unsupported.read_bytes()), "source_path": None,
            "source_sha256": None, "status": "unsupported_format",
            "error": "Unsupported version", "unknown_tokens": [], "evidence": {},
        })
        self.report["Records"].append({
            "RelativePath": "modern.p", "InputPath": str(unsupported),
            "SourcePath": "", "RegeneratedPath": "", "Status": "skipped_not_decoded",
            "AnalyzerMessages": [], "SourceSHA256": "", "ErrorIdentifier": "",
            "ErrorMessage": ""})
        self.save()
        result = self.run_verify()
        self.assertFalse(result["AllVerified"])
        self.assertEqual(result["Summary"]["verified_payload_identical"], 1)
        self.assertEqual(result["Summary"]["unsupported_format"], 1)
        self.assertEqual(result["Records"][1]["Status"], "unsupported_format")

    def test_changed_unsupported_input_can_be_revalidated(self):
        unsupported = self.inputs / "modern.p"
        unsupported.write_bytes(b"unsupported container")
        self.manifest["files"].append({
            "relative_path": "modern.p", "input_path": str(unsupported),
            "input_sha256": self.hash(unsupported.read_bytes()), "source_path": None,
            "source_sha256": None, "status": "unsupported_format",
            "error": "Unsupported version", "unknown_tokens": [], "evidence": {},
        })
        self.report["Records"].append({
            "RelativePath": "modern.p", "InputPath": str(unsupported),
            "SourcePath": "", "RegeneratedPath": "", "Status": "skipped_not_decoded",
            "AnalyzerMessages": [], "SourceSHA256": "", "ErrorIdentifier": "",
            "ErrorMessage": ""})
        self.save()
        unsupported.write_bytes(b"changed unsupported container")
        first = self.run_verify()
        self.assertEqual(first["Records"][1]["Status"], "input_changed")
        self.manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.save()
        second = self.run_verify()
        self.assertEqual(second["Records"][1]["Status"], "input_changed")
        self.assertEqual(second["Records"][1]["DecodeStatus"], "unsupported_format")
        self.assertFalse(second["AllVerified"])
    def test_scalar_analyzer_message_counts_as_one(self):
        self.report["Records"][0]["AnalyzerMessages"] = {"message": "Unused variable", "line": 2}
        self.save()
        self.assertEqual(self.run_verify()["Records"][0]["AnalyzerCount"], 1)

    def test_output_cannot_overwrite_source(self):
        before = self.source.read_bytes()
        with self.assertRaises(self.verify_module.VerificationError):
            self.run_verify(self.source)
        self.assertEqual(self.source.read_bytes(), before)

    def test_output_cannot_overwrite_arbitrary_existing_file(self):
        arbitrary = self.output / "user.json"
        arbitrary.write_text('{"user":"data"}', encoding="utf-8")
        with self.assertRaises(self.verify_module.VerificationError):
            self.run_verify(arbitrary)
        self.assertEqual(arbitrary.read_text(encoding="utf-8"), '{"user":"data"}')

    def test_native_failure_preserves_error(self):
        self.report["Records"][0].update(Status="failed", ErrorIdentifier="MATLAB:parse", ErrorMessage="Cannot parse")
        self.save()
        result = self.run_verify()
        self.assertEqual(result["Records"][0]["Status"], "validation_failed")
        self.assertIn("Cannot parse", result["Records"][0]["ErrorMessage"])


if __name__ == "__main__":
    unittest.main()