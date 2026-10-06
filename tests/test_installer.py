import os
import stat
import subprocess
import unittest

from install_helpers import InstallationFixture


class InstallerTests(InstallationFixture, unittest.TestCase):
    def test_install_and_reinstall_creates_regular_executable(self):
        for _ in range(2):
            result = self.install()
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.command.is_file())
        self.assertFalse(self.command.is_symlink())
        self.assertEqual(stat.S_IMODE(self.command.stat().st_mode), 0o755)
        installed = self.command.read_text().splitlines()
        self.assertEqual(installed[0], f"#!{self.runtime}/venv/bin/python -I")
        self.assertEqual(installed[2:], self.source.read_text().splitlines()[1:])
        self.assertIn(["chown", "-R", "0:0", str(self.runtime)], self.commands())
        installs = [cmd for cmd in self.commands() if cmd[0] == "install"]
        self.assertTrue(installs)
        for cmd in installs:
            self.assertEqual(cmd[cmd.index("-o") + 1], "0")
            self.assertEqual(cmd[cmd.index("-g") + 1], "0")
        if os.geteuid() != 0:
            for rc in (".bashrc", ".zshrc"):
                self.assertEqual((self.home / rc).read_text().count("export PATH="), 1)

    def test_installed_copy_runs_without_checkout_or_user_pythonpath(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.checkout.rename(self.root / "moved checkout")
        (self.home / "json.py").write_text("raise RuntimeError('user code imported')")
        env = dict(self.env, PYTHONPATH=str(self.home))
        result = subprocess.run(
            [str(self.command), "--help"], cwd=self.home, env=env,
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Linux and macOS", result.stdout)

    def test_unrelated_installations_are_preserved(self):
        self.command.write_text("existing installation")
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(self.command.read_text(), "existing installation")
        self.command.unlink()
        self.command.symlink_to(self.root / "other-installation")
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(self.command.readlink(), self.root / "other-installation")

    def test_old_checkout_links_are_replaced_without_changing_sources(self):
        for old_target in (self.source, self.launcher):
            with self.subTest(target=old_target):
                original = old_target.read_text()
                self.command.symlink_to(old_target)
                result = self.install()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(self.command.is_symlink())
                self.assertEqual(old_target.read_text(), original)
                self.command.unlink()

    def test_old_user_local_link_is_removed(self):
        legacy = self.home / ".local/bin/pycon"
        legacy.parent.mkdir(parents=True)
        legacy.symlink_to(self.launcher)
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(legacy.is_symlink())
        self.assertFalse(self.command.is_symlink())

    def test_unrelated_user_local_installation_is_kept(self):
        legacy = self.home / ".local/bin/pycon"
        legacy.parent.mkdir(parents=True)
        legacy.write_text("other installation")
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(legacy.read_text(), "other installation")

    def test_unmanaged_runtime_is_preserved(self):
        self.runtime.mkdir()
        sentinel = self.runtime / "keep"
        sentinel.write_text("unrelated")
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(sentinel.read_text(), "unrelated")
        self.assertFalse(self.command.exists())

    def test_failed_dependency_install_preserves_existing_command(self):
        self.command.symlink_to(self.launcher)
        self.env["PYCON_TEST_PIP_FAIL"] = "1"
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(self.command.readlink(), self.launcher)


if __name__ == "__main__":
    unittest.main()
