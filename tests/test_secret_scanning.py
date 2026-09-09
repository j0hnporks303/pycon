import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import python_pycon_source as pycon


class SecretScanningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pycon-secrets-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.value = "synthetic-only-42!"

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_regex_types_line_numbers_and_redaction(self):
        path = self.write("settings.txt", '\npassword="' + self.value + '"\n')
        report = pycon.scan_secrets(path, engine="regex")
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(report["findings"][0]["line"], 2)
        self.assertEqual(report["findings"][0]["type"], "Credential assignment")
        self.assertFalse(report["findings"][0]["verified"])
        self.assertNotIn(self.value, json.dumps(report))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pycon.print_report({"secret_scan": report})
        self.assertNotIn(self.value, output.getvalue())
        self.assertIn("[REDACTED]", output.getvalue())

    def test_additional_patterns_and_placeholders(self):
        self.assertEqual(list(pycon.regex_secret_types("-----BEGIN OPENSSH PRIVATE KEY-----")),
                         ["Private key header"])
        self.assertIn("URL with credentials", list(pycon.regex_secret_types(
            "postgres://user:" + self.value + "@localhost/db",
        )))
        for line in ("password=example", "token=${MY_TOKEN}", 'api_key="<placeholder>"',
                     "total=42", 'password=""'):
            self.assertEqual(list(pycon.regex_secret_types(line)), [])

    def test_recursion_hidden_and_excluded_directories(self):
        for name in ("root.env", ".env", "nested/config", ".venv/config", ".git/config"):
            self.write(name, "password=" + self.value)
        shallow = pycon.scan_secrets(self.root, engine="regex")
        self.assertEqual(shallow["files_scanned"], 2)
        recursive = pycon.scan_secrets(self.root, engine="regex", recursive=True)
        self.assertEqual(recursive["files_scanned"], 3)
        visible = pycon.scan_secrets(self.root, engine="regex", recursive=True, show_hidden=False)
        self.assertEqual(visible["files_scanned"], 2)

    def test_binary_large_symlink_and_fifo_are_skipped(self):
        self.write("large", "x" * 65)
        (self.root / "binary").write_bytes(b"\x00password=" + self.value.encode())
        target = self.write("small", "password=" + self.value)
        (self.root / "link").symlink_to(target)
        os.mkfifo(self.root / "pipe")
        report = pycon.scan_secrets(self.root, engine="regex", max_bytes=64)
        self.assertEqual(report["files_scanned"], 1)
        self.assertEqual(len(report["skipped"]), 4)
        self.assertEqual(report["errors"], [])

    def test_read_errors_remain_visible(self):
        report = pycon.scan_secrets(self.root / "missing", engine="regex")
        self.assertEqual(report["files_scanned"], 0)
        self.assertEqual(report["errors"][0]["type"], "FileNotFoundError")
        target = self.write("blocked", "password=" + self.value)
        with mock.patch.object(pycon, "read_secret_text", side_effect=PermissionError(13, "Permission denied")):
            report = pycon.scan_secrets(target, engine="regex")
        self.assertEqual(report["errors"][0]["type"], "PermissionError")

    def test_missing_optional_dependency(self):
        real_import = __import__

        def without_detect_secrets(name, *args, **kwargs):
            if name.startswith("detect_secrets"):
                raise ModuleNotFoundError(name)
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=without_detect_secrets):
            with self.assertRaisesRegex(RuntimeError, "--secret-engine regex"):
                pycon.scan_secrets(self.root)
            self.assertEqual(pycon.scan_secrets(self.root, engine="regex")["files_scanned"], 0)

    @unittest.skipUnless(importlib.util.find_spec("detect_secrets"), "optional dependency unavailable")
    def test_real_detect_secrets_is_offline_and_redacted(self):
        # Arbitrary test data, deliberately not a provider credential.
        value = "7Nq2Vb9Zx4Rm8Kp3Yd6Wa1Lc5Ft0HsEj"
        path = self.write("settings.env", 'SECRET_TOKEN="' + value + '"\n')
        with mock.patch("socket.socket.connect", side_effect=AssertionError("Network call")) as connect:
            for engine in ("detect-secrets", "both"):
                report = pycon.scan_secrets(path, engine=engine)
                self.assertTrue(any(item["engine"] == "detect-secrets" for item in report["findings"]))
                self.assertTrue(any("Entropy" in item["type"] for item in report["findings"]))
                self.assertNotIn(value, json.dumps(report))
                self.assertTrue(all(not item["verified"] for item in report["findings"]))
            connect.assert_not_called()

    def test_cli_json_contains_only_redacted_secret_report(self):
        path = self.write("settings.env", "password=" + self.value)
        command = [sys.executable, str(Path(pycon.__file__).resolve()), str(path),
                   "--scan-secrets", "--secret-engine", "regex", "--json"]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertIn("secret_scan", report)
        self.assertNotIn("path_inspection", report)
        self.assertNotIn(self.value, result.stdout + result.stderr)
        self.assertEqual(len(report["secret_scan"]["findings"]), 1)

    @unittest.skipUnless(importlib.util.find_spec("detect_secrets"), "optional dependency unavailable")
    def test_entropy_does_not_flag_ordinary_unquoted_text(self):
        path = self.write("ordinary.txt", ".venv/\nThe program reads files and prints a report.\n")
        report = pycon.scan_secrets(path, engine="detect-secrets")
        self.assertEqual(report["findings"], [])

    def test_cli_rejects_conflicting_modes(self):
        result = subprocess.run(
            [sys.executable, str(Path(pycon.__file__).resolve()), "--scan-secrets", "--recon-pid"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 2)

    def test_normal_inspection_still_reads_contents(self):
        path = self.write("plain.txt", "ordinary text")
        report = pycon.describe_path(path)
        self.assertEqual(report["text"], "ordinary text")


if __name__ == "__main__":
    unittest.main()
