import unittest

from install_helpers import InstallationFixture


class UninstallerTests(InstallationFixture, unittest.TestCase):
    def test_removes_installed_copy_and_runtime_but_keeps_checkout(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        original = self.source.read_text()
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.command.exists())
        self.assertFalse(self.runtime.exists())
        self.assertEqual(self.source.read_text(), original)
        self.assertEqual(self.launcher.read_text(), "old checkout launcher")
        self.assertEqual(self.uninstall().returncode, 0)

    def test_removes_legacy_checkout_links(self):
        for old_target in (self.source, self.launcher):
            with self.subTest(target=old_target):
                self.command.symlink_to(old_target)
                result = self.uninstall()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(self.command.is_symlink())
                self.assertTrue(old_target.exists())

    def test_removes_broken_checkout_link(self):
        self.launcher.unlink()
        self.command.symlink_to(self.launcher)
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.command.is_symlink())

    def test_missing_installation_is_successful(self):
        result = self.uninstall()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("not installed", result.stdout)

    def test_preserves_regular_file_and_directory(self):
        self.command.write_text("unrelated installation")
        self.assertNotEqual(self.uninstall().returncode, 0)
        self.assertEqual(self.command.read_text(), "unrelated installation")
        self.command.unlink()
        self.command.mkdir()
        self.assertNotEqual(self.uninstall().returncode, 0)
        self.assertTrue(self.command.is_dir())

    def test_preserves_unrelated_links(self):
        other = self.root / "other installation"
        for broken in (True, False):
            with self.subTest(broken=broken):
                if not broken:
                    other.write_text("unrelated installation")
                self.command.symlink_to(other)
                self.assertNotEqual(self.uninstall().returncode, 0)
                self.assertEqual(self.command.readlink(), other)
                if not broken:
                    self.assertEqual(other.read_text(), "unrelated installation")
                self.command.unlink()

    def test_unmanaged_runtime_stops_uninstall_before_removing_command(self):
        self.command.symlink_to(self.launcher)
        self.runtime.mkdir()
        sentinel = self.runtime / "keep"
        sentinel.write_text("unrelated")
        self.assertNotEqual(self.uninstall().returncode, 0)
        self.assertEqual(self.command.readlink(), self.launcher)
        self.assertEqual(sentinel.read_text(), "unrelated")

    def test_runtime_symlink_is_preserved(self):
        other = self.root / "other runtime"
        other.mkdir()
        self.runtime.symlink_to(other)
        self.assertNotEqual(self.uninstall().returncode, 0)
        self.assertEqual(self.runtime.readlink(), other)
        self.assertTrue(other.exists())


if __name__ == "__main__":
    unittest.main()
