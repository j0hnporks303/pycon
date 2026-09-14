import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


class InstallerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="pycon-install-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.checkout = self.root / "checkout with spaces"
        self.checkout.mkdir()
        source = Path(__file__).resolve().parents[1]
        for name in ("install.sh", "python_pycon_source.py", "requirements.txt", "requirements-secrets.txt"):
            shutil.copy2(source / name, self.checkout / name)
        self.home = self.root / "home with spaces"
        self.home.mkdir()
        self.env = dict(os.environ, HOME=str(self.home))
        self.command = self.home / ".local/bin/pycon"
        self.venv_bin = self.checkout / ".venv/bin"
        self.venv_bin.mkdir(parents=True)
        # Dependency installation is covered by CI's real installer run. Keep
        # these launcher/reinstallation tests offline and outside the user's home.
        python = self.venv_bin / "python"
        python.write_text(
            '#!/usr/bin/env bash\n'
            'if [[ "$1" == "-m" && "$2" == "pip" ]]; then exit 0; fi\n'
            f'exec {shlex.quote(sys.executable)} "$@"\n'
        )
        python.chmod(0o755)

    def install(self):
        return subprocess.run(
            ["bash", str(self.checkout / "install.sh")], env=self.env,
            capture_output=True, text=True, timeout=15,
        )

    def test_install_and_reinstall_with_spaces(self):
        for _ in range(2):
            result = self.install()
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.command.readlink(), self.venv_bin / "pycon")
        result = subprocess.run(
            [str(self.command), "--help"], env=self.env,
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Linux and macOS", result.stdout)
        for rc in (".bashrc", ".zshrc"):
            self.assertEqual((self.home / rc).read_text().count('export PATH='), 1)

    def test_unrelated_installations_are_preserved(self):
        self.command.parent.mkdir(parents=True)
        self.command.write_text("existing installation")
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(self.command.read_text(), "existing installation")
        self.command.unlink()
        self.command.symlink_to(self.root / "other-installation")
        self.assertNotEqual(self.install().returncode, 0)
        self.assertEqual(self.command.readlink(), self.root / "other-installation")

    def test_old_checkout_link_is_upgraded(self):
        self.command.parent.mkdir(parents=True)
        self.command.symlink_to(self.checkout / "python_pycon_source.py")
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.command.readlink(), self.venv_bin / "pycon")


if __name__ == "__main__":
    unittest.main()
