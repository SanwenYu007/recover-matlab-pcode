"""Behavior tests for portable recovery, using generated non-proprietary fixtures."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib

SCRIPT = Path(os.environ.get("RECOVERY_SCRIPT", Path(__file__).resolve().parents[1] / "scripts" / "recover_pcode.py"))
# Format constants sufficient for these small fixtures, independent of the decoder.
SCRAMBLE_WORDS = (
    0x050F0687, 0xC3F63AB0, 0x2E022A9C, 0x036DAA8C, 0x32ED8AE2, 0xF5571876, 0xC66FE7F3, 0x6CF0D7C0,
    0xBE08BA59, 0x0CBB32BE, 0x2E1E76F9, 0x5B095029, 0xD7B83753, 0xB949C2EA, 0x002B7101, 0x10BF6F59,
    0x5A565564, 0xCF31F672, 0x49B64869, 0x30B5AE91, 0x33D84C72, 0xE4B5B87D, 0x97EF0BD8, 0x58A53999,
    0xA2D54211, 0x040D16F3, 0x8ED0F2AB, 0xA1123692, 0x7CAD41FD, 0x47FD2EE5, 0xD5B56675, 0x01BC4884,
    0x8BF36995, 0x83B79111, 0x8529F311, 0x3EE0F477, 0x790EA987, 0x4B99DB04, 0x2BD1CC37, 0x371763E1,
    0x58550DC3, 0xD9F04330, 0x1220B40A, 0xB00D4516, 0x133A061B, 0x924C250C, 0x40CCB470, 0x6D905B7F,
    0x617E1B7E, 0x0A82FCD9, 0x1E460A11, 0x155667F0, 0x6F38B557, 0x363515E9, 0x6DFBA189, 0x920DF768,
    0x3A422CDD, 0x7CCC9435, 0xB3202DFB, 0x36EF6EDA, 0x44C9C31A, 0x08D59470, 0xB8ABB75E, 0x50BD2CAF,
)


def symbol(index: int) -> bytes:
    high, low = divmod(index + 128, 256)
    return bytes((128 | high, low))


def pcode(names=("y", "demo", "x"), tokens=None, *, plain=None) -> bytes:
    if tokens is None:
        tokens = bytes((1,)) + symbol(0) + bytes((95,)) + symbol(1) + bytes((52,)) + symbol(2) + bytes((53, 100))
        tokens += symbol(0) + bytes((95,)) + symbol(2) + bytes((61, 50, 100, 8, 100))
    if plain is None:
        plain = struct.pack(">7I", len(names), 0, 0, 0, 0, 0, 0)
        plain += b"".join(name.encode("utf-8") + b"\0" for name in names) + tokens
    compressed = bytearray(zlib.compress(plain))
    if len(compressed) // 4 > len(SCRAMBLE_WORDS):
        raise AssertionError("Fixture exceeds its independent scramble constants")
    for word in range(len(compressed) // 4):
        offset = word * 4
        value = int.from_bytes(compressed[offset:offset + 4], "little") ^ SCRAMBLE_WORDS[word]
        compressed[offset:offset + 4] = value.to_bytes(4, "little")
    return b"v01.00v00.00" + struct.pack(">5I", 0, 0, 0, len(compressed), len(plain)) + compressed


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="portable-pcode-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def write(self, relative, data=None):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(pcode() if data is None else data)
        return path

    def run_cli(self, path, output=None):
        command = [sys.executable, str(SCRIPT), "--input", str(path)]
        if output is not None:
            command += ["--output", str(output)]
        return subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")

    def manifest(self, output):
        return json.loads((output / "recovery_manifest.json").read_text(encoding="utf-8"))

    def test_cross_project_single_file(self):
        path = self.write("other-project/demo.p")
        output = self.root / "output"
        before = (path.read_bytes(), path.stat().st_mtime_ns)
        result = self.run_cli(path, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), before)
        source = output / "sources/demo.m"
        self.assertEqual(source.read_text(encoding="utf-8"), "function y=demo(x)\n    y=x.';\nend\n")
        manifest = self.manifest(output)
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["tool"], "recover-matlab-pcode")
        self.assertEqual(Path(manifest["input_path"]), path.resolve())
        self.assertEqual(Path(manifest["layout_root"]), path.parent.resolve())
        self.assertEqual(Path(manifest["output_dir"]), output.resolve())
        record = manifest["files"][0]
        self.assertEqual(record["relative_path"], "demo.p")
        self.assertEqual(record["status"], "decoded_unverified")
        self.assertEqual(record["input_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertEqual(record["source_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertIsNone(record["error"])
        self.assertEqual(record["unknown_tokens"], [])
        for key in ("input_path", "source_path"):
            self.assertTrue(Path(record[key]).is_absolute())
        for evidence_path in record["evidence"].values():
            self.assertTrue(Path(evidence_path).is_absolute())
            self.assertTrue(Path(evidence_path).is_file())

    def test_directory_preserves_packages_classes_and_uppercase_suffix(self):
        folder = self.root / "project"
        self.write("project/+alpha/@Widget/run.P")
        self.write("project/plain/subroutine.p")
        self.write("project/readme.txt", b"not pcode")
        output = self.root / "decoded"
        result = self.run_cli(folder, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        manifest = self.manifest(output)
        self.assertEqual({r["relative_path"] for r in manifest["files"]}, {"+alpha/@Widget/run.P", "plain/subroutine.p"})
        self.assertTrue((output / "sources/+alpha/@Widget/run.m").is_file())
        self.assertTrue((output / "sources/plain/subroutine.m").is_file())
        self.assertFalse((output / "sources/readme.m").exists())

    def test_single_file_keeps_contiguous_package_and_class_parents(self):
        path = self.write("project/+outer/+inner/@Widget/run.P")
        output = self.root / "decoded"
        result = self.run_cli(path, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.manifest(output)["files"][0]["relative_path"], "+outer/+inner/@Widget/run.P")
        self.assertTrue((output / "sources/+outer/+inner/@Widget/run.m").exists())

    def test_literals_utf8_and_nonconjugate_transpose_are_preserved(self):
        names = ("x", "'a:b\\c  '", "'\u4e2d\u6587''quoted'", '"\u4e16\u754c"', "1.25")
        tokens = symbol(0) + bytes((95,)) + symbol(1) + bytes((50, 100))
        tokens += symbol(0) + bytes((95,)) + symbol(2) + bytes((50, 100))
        tokens += symbol(0) + bytes((95,)) + symbol(3) + bytes((50, 100))
        tokens += symbol(0) + bytes((95,)) + symbol(4) + bytes((61, 50, 100))
        path = self.write("literal.p", pcode(names, tokens))
        output = self.root / "decoded"
        result = self.run_cli(path, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = "x='a:b\\c  ';\nx='\u4e2d\u6587''quoted';\nx=\"\u4e16\u754c\";\nx=1.25.';\n"
        self.assertEqual((output / "sources/literal.m").read_text(encoding="utf-8"), expected)
        symbols = output / "evidence/literal.symbols.json"
        self.assertEqual(json.loads(symbols.read_text(encoding="utf-8")), list(names))

    def test_default_output_is_fresh_and_explicit_empty_directory_is_allowed(self):
        path = self.write("project/demo.p")
        self.assertEqual(self.run_cli(path).returncode, 0)
        first = path.parent / "demo_recovered"
        snapshot = (first / "sources/demo.m").read_bytes()
        self.assertEqual(self.run_cli(path).returncode, 0)
        self.assertEqual((first / "sources/demo.m").read_bytes(), snapshot)
        self.assertTrue((path.parent / "demo_recovered_1/recovery_manifest.json").is_file())
        explicit = self.root / "empty"
        explicit.mkdir()
        self.assertEqual(self.run_cli(path, explicit).returncode, 0)
        self.assertTrue((explicit / "sources/demo.m").is_file())

    def test_output_conflict_does_not_modify_any_existing_file(self):
        path = self.write("demo.p")
        output = self.root / "existing"
        output.mkdir()
        marker = output / "keep.txt"
        marker.write_bytes(b"user content")
        before = path.read_bytes()
        result = self.run_cli(path, output)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(marker.read_bytes(), b"user content")
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(list(output.iterdir()), [marker])

    def test_overlapping_output_is_rejected_before_creating_files(self):
        path = self.write("input/demo.p")
        folder = path.parent
        result = self.run_cli(folder, folder / "new-output")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((folder / "new-output").exists())
        self.assertEqual(list(folder.iterdir()), [path])

    def test_mixed_failures_continue_and_unknown_tokens_never_create_sources(self):
        folder = self.root / "input"
        self.write("input/good.p")
        self.write("input/newer.p", b"v02.00v00.00" + b"\0" * 20)
        self.write("input/broken.p", b"v01.00v00.00")
        self.write("input/unknown.p", pcode((), bytes((34, 100))))
        output = self.root / "decoded"
        result = self.run_cli(folder, output)
        self.assertEqual(result.returncode, 1, result.stderr)
        records = {r["relative_path"]: r for r in self.manifest(output)["files"]}
        self.assertEqual({name: record["status"] for name, record in records.items()}, {
            "good.p": "decoded_unverified", "newer.p": "unsupported_format",
            "broken.p": "decode_failed", "unknown.p": "unresolved_tokens"})
        self.assertTrue((output / "sources/good.m").exists())
        for name in ("newer.p", "broken.p", "unknown.p"):
            self.assertIsNone(records[name]["source_path"])
            self.assertIsNone(records[name]["source_sha256"])
            self.assertIsInstance(records[name]["error"], str)
            self.assertFalse((output / "sources" / Path(name).with_suffix(".m")).exists())
        self.assertEqual(records["unknown.p"]["unknown_tokens"][0]["id"], 34)
        self.assertTrue(records["unknown.p"]["evidence"])

    def test_corrupt_lengths_indices_symbols_and_decompression_limit(self):
        good = pcode()
        bad_size = bytearray(good)
        struct.pack_into(">I", bad_size, 24, len(good))
        too_large = bytearray(good)
        struct.pack_into(">I", too_large, 28, 64 * 1024 * 1024 + 1)
        bad_symbol = pcode(plain=struct.pack(">7I", 1, 0, 0, 0, 0, 0, 0) + b"\xff\0" + bytes((100,)))
        inputs = {"length.p": bytes(bad_size), "index.p": pcode(("x",), symbol(4)),
                  "truncated-reference.p": pcode((), bytes((128,))), "utf8.p": bad_symbol,
                  "limit.p": bytes(too_large), "trailing.p": good + b"extra"}
        for name, data in inputs.items():
            self.write("input/" + name, data)
        output = self.root / "decoded"
        result = self.run_cli(self.root / "input", output)
        self.assertEqual(result.returncode, 1, result.stderr)
        records = self.manifest(output)["files"]
        self.assertEqual(len(records), len(inputs))
        self.assertTrue(all(r["status"] == "decode_failed" and r["source_path"] is None for r in records))
        self.assertFalse((output / "sources").exists())

    def test_readonly_input_is_never_written(self):
        path = self.write("readonly.p")
        before = (path.read_bytes(), path.stat().st_mtime_ns)
        path.chmod(stat.S_IREAD)
        try:
            result = self.run_cli(path, self.root / "decoded")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((path.read_bytes(), path.stat().st_mtime_ns), before)
            self.assertFalse(path.with_suffix(".m").exists())
        finally:
            path.chmod(stat.S_IREAD | stat.S_IWRITE)

    def test_escaping_directory_junction_is_rejected_without_output(self):
        outside = self.root / "outside"
        outside.mkdir()
        self.write("outside/secret.p")
        folder = self.root / "input"
        folder.mkdir()
        link = folder / "escape"
        if os.name == "nt":
            result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True)
            if result.returncode:
                self.skipTest("Directory junctions unavailable")
        else:
            link.symlink_to(outside, target_is_directory=True)
        try:
            output = self.root / "decoded"
            result = self.run_cli(folder, output)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertTrue((outside / "secret.p").exists())
        finally:
            # Remove the link itself only, never recursively follow it.
            if os.name == "nt":
                os.rmdir(link)
            else:
                link.unlink()

    def test_default_output_skips_an_existing_directory_junction(self):
        path = self.write("demo.p")
        outside = self.root / "user-files"
        outside.mkdir()
        marker = outside / "keep.txt"
        marker.write_bytes(b"must stay unchanged")
        link = self.root / "demo_recovered"
        if os.name == "nt":
            created = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True)
            if created.returncode:
                self.skipTest("Directory junctions unavailable")
        else:
            link.symlink_to(outside, target_is_directory=True)
        try:
            result = self.run_cli(path)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((self.root / "demo_recovered_1/recovery_manifest.json").is_file())
            self.assertEqual(marker.read_bytes(), b"must stay unchanged")
            self.assertEqual(list(outside.iterdir()), [marker])
            explicit = self.run_cli(path, link)
            self.assertNotEqual(explicit.returncode, 0)
            self.assertEqual(list(outside.iterdir()), [marker])
        finally:
            if os.name == "nt":
                os.rmdir(link)
            else:
                link.unlink()

    def test_renderer_preserves_eof_newline_tokens_exactly(self):
        # MATLAB pcode retains terminal line breaks as tokens. Adding one when
        # the original stream ends at a semicolon changes its complete payload.
        statement = symbol(0) + bytes((95,)) + symbol(1) + bytes((50,))
        for newline_count in (0, 1, 2):
            with self.subTest(newline_count=newline_count):
                path = self.write(f"eof-{newline_count}.p", pcode(("x", "1"), statement + bytes((100,)) * newline_count))
                output = self.root / f"eof-output-{newline_count}"
                result = self.run_cli(path, output)
                self.assertEqual(result.returncode, 0, result.stderr)
                source = (output / "sources" / path.with_suffix(".m").name).read_bytes()
                self.assertEqual(source, b"x=1;" + b"\n" * newline_count)

    def test_empty_token_stream_does_not_acquire_a_newline(self):
        path = self.write("empty.p", pcode((), b""))
        output = self.root / "decoded"
        result = self.run_cli(path, output)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((output / "sources/empty.m").read_bytes(), b"")

    def test_help_runs_without_input_and_unsupported_extension_is_rejected(self):
        help_result = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True)
        self.assertEqual(help_result.returncode, 0)
        path = self.write("source.m", b"x=1;\n")
        result = self.run_cli(path, self.root / "decoded")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "decoded").exists())


if __name__ == "__main__":
    unittest.main()
