import contextlib
import ctypes
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


class LinuxJailTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="pycon-jail-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.write("proc/self/status", "Seccomp:\t0\nNoNewPrivs:\t0\nNSpid:\t123\n")
        self.write("proc/self/cgroup", "0::/\n")
        (self.root / "proc/1").mkdir()
        (self.root / "proc/1/root").symlink_to(self.root)
        self.start_patch(mock.patch.object(pycon.sys, "platform", "linux"))
        # Route only detection paths into the fixture, never inspect the host.
        for method in ("lstat", "stat", "read_text"):
            original = getattr(Path, method)

            def routed(path, *args, _original=original, **kwargs):
                name = str(path)
                if name in {"/", "/.dockerenv", "/run/.containerenv", "/run/systemd/container",
                            "/proc/self/status", "/proc/self/cgroup", "/proc/1/root"}:
                    path = self.root / name.lstrip("/")
                return _original(path, *args, **kwargs)

            self.start_patch(mock.patch.object(Path, method, routed))

    def start_patch(self, patch):
        value = patch.start()
        self.addCleanup(patch.stop)
        return value

    def write(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents)
        return path

    def test_no_indicators_does_not_claim_unrestricted_access(self):
        report = pycon.check_jail()
        self.assertIsNone(report["jailed_or_sandboxed"])
        self.assertEqual(report["indicators"], [])
        self.assertEqual(report["errors"], [])
        self.assertFalse(report["observations"]["root_differs_from_pid1"])
        self.assertIn("cannot be ruled out", report["reason"])

    def test_container_markers_work_with_namespaced_cgroup_v2_root(self):
        for marker, runtime in ((".dockerenv", "Docker"), ("run/.containerenv", "Podman")):
            with self.subTest(runtime=runtime):
                path = self.write(marker, "")
                report = pycon.check_jail()
                self.assertIs(report["jailed_or_sandboxed"], True)
                self.assertEqual(len(report["indicators"]), 1)
                self.assertIn(runtime, report["indicators"][0]["detail"])
                self.assertEqual(report["indicators"][0]["source"], "/" + marker)
                path.unlink()

    def test_marker_directory_and_symlink_are_not_container_evidence(self):
        marker = self.root / ".dockerenv"
        marker.mkdir()
        self.assertIsNone(pycon.check_jail()["jailed_or_sandboxed"])
        marker.rmdir()
        marker.symlink_to(self.root / "proc/self/status")
        self.assertIsNone(pycon.check_jail()["jailed_or_sandboxed"])

    def test_systemd_container_identifier(self):
        self.write("run/systemd/container", "systemd-nspawn\n")
        report = pycon.check_jail()
        self.assertIs(report["jailed_or_sandboxed"], True)
        self.assertEqual(report["observations"]["systemd_container"], "systemd-nspawn")

    def test_cgroup_v1_and_v2_runtime_paths(self):
        container_id = "a" * 64
        for membership, runtime in (
            (f"12:memory:/docker/{container_id}", "Docker"),
            (f"0::/system.slice/docker-{container_id}.scope", "Docker"),
            (f"0::/user.slice/libpod-{container_id}.scope", "Podman"),
            ("0::/kubepods/burstable/pod123/container", "Kubernetes"),
            ("0::/kubepods.slice/kubepods-burstable.slice/pod123", "Kubernetes"),
            ("1:name=systemd:/lxc/example", "LXC"),
            ("0::/lxc.payload.example", "LXC"),
        ):
            with self.subTest(membership=membership):
                self.write("proc/self/cgroup", membership + "\n")
                report = pycon.check_jail()
                self.assertIs(report["jailed_or_sandboxed"], True)
                self.assertEqual(report["observations"]["cgroup_runtimes"], [runtime])

    def test_host_runtime_services_and_malformed_cgroups_are_not_containers(self):
        self.write("proc/self/cgroup", "\n".join((
            "0::/system.slice/docker.service", "1:name=systemd:/system.slice/containerd.service",
            "0::/user.slice/my-kubepods-project", "docker", "0:docker:",
        )))
        self.assertIsNone(pycon.check_jail()["jailed_or_sandboxed"])

    def test_seccomp_modes_are_detected_without_a_container(self):
        for mode, label in ((1, "strict"), (2, "filter")):
            with self.subTest(mode=mode):
                self.write("proc/self/status", f"Seccomp:\t{mode}\nSeccomp_filters:\t2\n")
                report = pycon.check_jail()
                self.assertIs(report["jailed_or_sandboxed"], True)
                self.assertEqual(report["indicators"][0]["kind"], "seccomp")
                self.assertIn(label, report["indicators"][0]["detail"])
                self.assertEqual(report["observations"]["process_status"]["Seccomp_filters"], "2")

    def test_no_new_privs_and_missing_seccomp_field_do_not_prove_a_sandbox(self):
        self.write("proc/self/status", "NoNewPrivs:\t1\nNSpid:\t123\n")
        report = pycon.check_jail()
        self.assertIsNone(report["jailed_or_sandboxed"])
        self.assertEqual(report["observations"]["process_status"]["NoNewPrivs"], "1")
        self.assertIsNone(report["observations"]["process_status"]["Seccomp"])

    def test_nested_pid_namespace(self):
        self.write("proc/self/status", "Seccomp:\t0\nNSpid:\t123 5 1\n")
        report = pycon.check_jail()
        self.assertIs(report["jailed_or_sandboxed"], True)
        self.assertEqual(report["indicators"][0]["kind"], "pid_namespace")

    def test_different_root_is_reported_as_possible_chroot_or_namespace(self):
        other_root = self.root / "other"
        other_root.mkdir()
        (self.root / "proc/1/root").unlink()
        (self.root / "proc/1/root").symlink_to(other_root)
        report = pycon.check_jail()
        self.assertIs(report["jailed_or_sandboxed"], True)
        self.assertTrue(report["observations"]["root_differs_from_pid1"])
        self.assertIn("possible chroot", report["indicators"][0]["detail"])

    def test_missing_procfs_preserves_errors_and_unknown(self):
        for name in ("proc/self/status", "proc/self/cgroup", "proc/1/root"):
            (self.root / name).unlink()
        report = pycon.check_jail()
        self.assertIsNone(report["jailed_or_sandboxed"])
        self.assertEqual(len(report["errors"]), 3)
        self.assertTrue(all(error["type"] == "FileNotFoundError" for error in report["errors"]))
        self.assertIsNone(report["observations"]["root_differs_from_pid1"])

    def test_permission_failure_does_not_hide_other_evidence(self):
        self.write(".dockerenv", "")
        with mock.patch.object(Path, "read_text", side_effect=PermissionError(13, "Permission denied")):
            report = pycon.check_jail()
        self.assertIs(report["jailed_or_sandboxed"], True)
        self.assertEqual(len(report["errors"]), 3)
        self.assertTrue(all(error["type"] == "PermissionError" for error in report["errors"]))

    def test_unreadable_markers_are_not_treated_as_absent(self):
        with mock.patch.object(Path, "lstat", side_effect=PermissionError(13, "Permission denied")):
            report = pycon.check_jail()
        self.assertIsNone(report["jailed_or_sandboxed"])
        self.assertIsNone(report["observations"]["/.dockerenv"])
        self.assertEqual(len(report["errors"]), 2)

    def test_text_output_escapes_untrusted_indicator_values(self):
        self.write("run/systemd/container", "example\x1b[2J\nforged line")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            pycon.print_report({"jail_check": pycon.check_jail()})
        self.assertIn("Jailed/sandboxed: indicators detected", output.getvalue())
        self.assertNotIn("\x1b[2J", output.getvalue())
        self.assertNotIn("\nforged line", output.getvalue())


class MacOSJailTests(unittest.TestCase):
    def setUp(self):
        patch = mock.patch.object(pycon.sys, "platform", "darwin")
        patch.start()
        self.addCleanup(patch.stop)

    def test_seatbelt_runtime_result(self):
        for result in (0, 1):
            with self.subTest(result=result), mock.patch.object(ctypes, "CDLL") as load:
                check = load.return_value.sandbox_check
                check.return_value = result
                report = pycon.check_jail()
                check.assert_called_once_with(os.getpid(), None, 0)
                self.assertEqual(check.argtypes, [ctypes.c_int, ctypes.c_char_p, ctypes.c_int])
                self.assertEqual(report["observations"]["seatbelt_sandboxed"], bool(result))
                self.assertIs(report["jailed_or_sandboxed"], True if result else None)
                self.assertEqual(report["errors"], [])

    def test_unavailable_library_or_symbol_remains_unknown(self):
        for error in (OSError("Library unavailable"), AttributeError("Symbol unavailable")):
            with self.subTest(error=error), mock.patch.object(ctypes, "CDLL", side_effect=error):
                report = pycon.check_jail()
                self.assertIsNone(report["jailed_or_sandboxed"])
                self.assertIsNone(report["observations"]["seatbelt_sandboxed"])
                self.assertEqual(report["errors"][0]["type"], type(error).__name__)

    def test_native_api_error_is_not_positive_detection(self):
        with mock.patch.object(ctypes, "CDLL") as load:
            load.return_value.sandbox_check.return_value = -1
            report = pycon.check_jail()
        self.assertIsNone(report["jailed_or_sandboxed"])
        self.assertEqual(report["indicators"], [])
        self.assertIn("Unexpected sandbox_check result", report["errors"][0]["message"])


class JailIntegrationTests(unittest.TestCase):
    def test_unsupported_platform_remains_unknown(self):
        with mock.patch.object(pycon.sys, "platform", "unsupported"):
            report = pycon.check_jail()
        self.assertIsNone(report["jailed_or_sandboxed"])
        self.assertIn("Linux and macOS only", " ".join(report["limitations"]))

    def test_flag_works_with_path_process_and_secret_modes(self):
        expected = {"jailed_or_sandboxed": True, "reason": "Test indicator"}
        for arguments in ([], ["--recon-pid", "0"], ["--scan-secrets", "--recursive"]):
            with self.subTest(arguments=arguments), \
                    mock.patch.object(sys, "argv", ["pycon", *arguments, "--check-jail", "--json"]), \
                    mock.patch.object(pycon, "describe_path", return_value={}), \
                    mock.patch.object(pycon, "enum_processes", return_value={}), \
                    mock.patch.object(pycon, "scan_secrets", return_value={}), \
                    mock.patch.object(pycon, "check_jail", return_value=expected) as check, \
                    mock.patch.object(pycon, "print_json") as output:
                pycon.main()
                check.assert_called_once_with()
                self.assertEqual(output.call_args.args[0]["jail_check"], expected)

    def test_detection_only_runs_when_requested(self):
        with mock.patch.object(sys, "argv", ["pycon", "--json"]), \
                mock.patch.object(pycon, "describe_path", return_value={}), \
                mock.patch.object(pycon, "check_jail") as check, \
                mock.patch.object(pycon, "print_json") as output:
            pycon.main()
        check.assert_not_called()
        self.assertNotIn("jail_check", output.call_args.args[0])

    def test_native_secret_scan_keeps_redaction_with_jail_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_text("password=synthetic-test-value-42!\n")
            result = subprocess.run(
                [sys.executable, str(Path(pycon.__file__).resolve()), directory,
                 "--scan-secrets", "--recursive", "--secret-engine", "regex", "--check-jail", "--json"],
                capture_output=True, text=True, timeout=15,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["secret_scan"]["files_scanned"], 1)
        self.assertNotIn("synthetic-test-value-42!", result.stdout + result.stderr)
        self.assertEqual(report["jail_check"]["scope"], "current_process")


if __name__ == "__main__":
    unittest.main()
