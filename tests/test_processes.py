import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import python_pycon_source as pycon


class ProcessTests(unittest.TestCase):
    def setUp(self):
        class ProcessError(Exception):
            pass

        class AccessDenied(ProcessError):
            pass

        class NoSuchProcess(ProcessError):
            pass

        self.psutil = SimpleNamespace(
            Error=ProcessError, AccessDenied=AccessDenied, NoSuchProcess=NoSuchProcess,
            pids=mock.Mock(return_value=[30, 10, 20]),
            Process=mock.Mock(side_effect=self.process),
        )
        self.patch = mock.patch.dict(sys.modules, {"psutil": self.psutil})
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def process(self, pid):
        return SimpleNamespace(**{
            name: mock.Mock(return_value=value)
            for name, value in {
                "cmdline": ["/tmp/example tool", "argument with spaces"],
                "exe": "/tmp/example tool", "name": "example tool",
                "status": "sleeping", "ppid": 1, "username": "test-user",
                "num_threads": 2,
                "uids": SimpleNamespace(real=501, effective=502, saved=503),
                "gids": SimpleNamespace(real=20, effective=21, saved=22),
            }.items()
        })

    def test_platform_selection(self):
        for platform, backend in (("linux", "enum_linux_processes"),
                                  ("darwin", "enum_macos_processes")):
            with self.subTest(platform=platform), mock.patch.object(pycon.sys, "platform", platform):
                with mock.patch.object(pycon, backend, return_value={"selected": platform}) as call:
                    self.assertEqual(pycon.enum_processes(2), {"selected": platform})
                    call.assert_called_once_with(2)
        with mock.patch.object(pycon.sys, "platform", "freebsd"):
            with self.assertRaisesRegex(RuntimeError, "Linux and macOS"):
                pycon.enum_processes()

    def test_macos_limits_and_native_fields(self):
        report = pycon.enum_macos_processes(2)
        self.assertEqual([p["pid"] for p in report["processes"]], [10, 20])
        self.assertEqual(report["numeric_entries_observed"], 3)
        self.assertEqual(report["omitted_by_limit"], 1)
        self.assertEqual(report["returned"], 2)
        process = report["processes"][0]
        self.assertEqual(process["argv"], ["/tmp/example tool", "argument with spaces"])
        self.assertEqual(process["status"]["UID (effective)"], 502)
        self.assertEqual(process["status"]["GID (saved)"], 22)
        self.assertNotIn("CapEff", process["status"])
        self.assertEqual(process["errors"], [])
        json.dumps(report)
        self.assertEqual(pycon.enum_macos_processes()["returned"], 3)

    def test_denied_fields_preserve_readable_fields(self):
        process = self.process(10)
        process.cmdline.side_effect = self.psutil.AccessDenied("denied")
        process.exe.side_effect = PermissionError(13, "Permission denied")
        process.uids.side_effect = self.psutil.AccessDenied("denied")
        self.psutil.Process.side_effect = None
        self.psutil.Process.return_value = process
        report = pycon.enum_macos_processes(1)
        item = report["processes"][0]
        self.assertIsNone(item["cmdline"])
        self.assertIsNone(item["executable"])
        self.assertIsNone(item["status"]["UID (real)"])
        self.assertEqual(item["status"]["Name"], "example tool")
        self.assertEqual([e["field"] for e in item["errors"]], ["cmdline", "exe", "UID"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pycon.print_report({"process_scan": report})
        self.assertIn("<unavailable>", output.getvalue())
        self.assertIn("AccessDenied", output.getvalue())
        self.assertIn("Linux /proc/status fields are unavailable", output.getvalue())

    def test_exited_process_is_retained_and_scan_continues(self):
        def process(pid):
            if pid == 10:
                raise self.psutil.NoSuchProcess("exited")
            return self.process(pid)

        self.psutil.Process.side_effect = process
        report = pycon.enum_macos_processes()
        self.assertEqual(report["returned"], 3)
        self.assertIsNone(report["processes"][0]["status"])
        self.assertEqual(report["processes"][0]["errors"][0]["type"], "NoSuchProcess")
        self.assertEqual(report["processes"][1]["status"]["Name"], "example tool")

    def test_exit_during_field_read_is_reported(self):
        process = self.process(10)
        process.name.side_effect = self.psutil.NoSuchProcess("exited")
        self.psutil.Process.side_effect = None
        self.psutil.Process.return_value = process
        item = pycon.enum_macos_processes(1)["processes"][0]
        self.assertIsNone(item["status"]["Name"])
        self.assertEqual(item["errors"][0]["type"], "NoSuchProcess")

    def test_enumeration_failure_is_not_a_clean_empty_scan(self):
        self.psutil.pids.side_effect = self.psutil.AccessDenied("denied")
        report = pycon.enum_macos_processes()
        self.assertEqual(report["returned"], 0)
        self.assertEqual(report["errors"][0]["field"], "list_pids")
        self.assertNotIn("numeric_entries_observed", report)

    def test_missing_dependency_has_actionable_cli_error(self):
        with mock.patch.dict(sys.modules, {"psutil": None}):
            with self.assertRaisesRegex(RuntimeError, "requirements.txt"):
                pycon.enum_macos_processes()
            with mock.patch.object(sys, "platform", "darwin"), \
                    mock.patch.object(sys, "argv", ["pycon", "--recon-pid"]):
                output = io.StringIO()
                with contextlib.redirect_stderr(output), self.assertRaises(SystemExit) as exc:
                    pycon.main()
                self.assertEqual(exc.exception.code, 2)
                self.assertIn("./install.sh", output.getvalue())
                self.assertNotIn("Traceback", output.getvalue())

    def test_linux_proc_fields_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pid in (10, 20):
                process = root / str(pid)
                process.mkdir()
                (process / "cmdline").write_bytes(b"example\0argument with spaces\0")
                (process / "status").write_text("Name:\texample\nCapEff:\t0000\n")
                (process / "exe").symlink_to("/example")
            real_iterdir = Path.iterdir

            def iterdir(path):
                return real_iterdir(root if path == Path("/proc") else path)

            with mock.patch.object(Path, "iterdir", iterdir):
                report = pycon.enum_linux_processes(1)
            self.assertEqual(report["returned"], 1)
            self.assertEqual(report["omitted_by_limit"], 1)
            self.assertEqual(report["processes"][0]["argv"], ["example", "argument with spaces"])
            self.assertEqual(report["processes"][0]["status"]["CapEff"], "0000")
            self.assertEqual(report["processes"][0]["executable"], "/example")


class NativeProcessTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform in {"linux", "darwin"}, "requires Linux or macOS")
    def test_current_process_is_visible(self):
        report = pycon.enum_processes()
        self.assertEqual(report["errors"], [])
        current = next(p for p in report["processes"] if p["pid"] == os.getpid())
        self.assertTrue(current["argv"])
        self.assertTrue(current["executable"])
        self.assertIsNotNone(current["status"])
        self.assertEqual(current["errors"], [])

    @unittest.skipUnless(importlib.util.find_spec("psutil"), "psutil not installed on this platform")
    def test_psutil_backend_with_real_process(self):
        import psutil
        # Exercises the real psutil API on Linux too when installed there.
        with mock.patch.object(psutil, "pids", return_value=[os.getpid()]):
            report = pycon.enum_macos_processes()
        self.assertEqual(report["returned"], 1)
        self.assertEqual(report["processes"][0]["errors"], [])
        self.assertEqual(report["processes"][0]["status"]["UID (real)"], os.getuid())

    def test_process_cli_json_and_neutral_jail_message(self):
        result = subprocess.run(
            [sys.executable, str(Path(pycon.__file__).resolve()), "--recon-pid", "1",
             "--check-jail", "--json"], capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["process_scan"]["returned"], 1)
        self.assertIsNone(report["jail_check"]["jailed_or_sandboxed"])
        self.assertNotIn("/proc", report["jail_check"]["reason"])


if __name__ == "__main__":
    unittest.main()
