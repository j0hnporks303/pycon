import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile


class InstallationFixture:
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="pycon-install-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.checkout = self.root / "checkout with spaces"
        self.checkout.mkdir()
        self.home = self.root / "home with spaces"
        self.home.mkdir()
        self.bin_dir = self.root / "local bin"
        self.bin_dir.mkdir()
        self.command = self.bin_dir / "pycon"
        self.runtime = self.root / "runtime"
        self.launcher = self.checkout / ".venv/bin/pycon"
        self.launcher.parent.mkdir(parents=True)
        self.launcher.write_text("old checkout launcher")
        repo = Path(__file__).resolve().parents[1]
        for name in ("python_pycon_source.py", "requirements.txt", "requirements-secrets.txt"):
            shutil.copy2(repo / name, self.checkout / name)
        self.source = self.checkout / "python_pycon_source.py"
        for name in ("install.sh", "uninstall.sh"):
            script = (repo / name).read_text()
            self.assertIn('target="/usr/local/bin"', script)
            self.assertIn('runtime="/usr/local/lib/pycon"', script)
            script = script.replace('target="/usr/local/bin"', f"target={shlex.quote(str(self.bin_dir))}", 1)
            script = script.replace('runtime="/usr/local/lib/pycon"', f"runtime={shlex.quote(str(self.runtime))}", 1)
            (self.checkout / name).write_text(script)

        # Keep unit tests offline and unprivileged. CI runs the real system install.
        self.log = self.root / "commands.jsonl"
        mock_bin = self.root / "mock-bin"
        mock_bin.mkdir()
        driver = (
            f"#!{sys.executable}\n"
            "import json, os, pathlib, shlex, sys\n"
            "name = pathlib.Path(sys.argv[0]).name\n"
            "args = sys.argv[1:]\n"
            "with open(os.environ['PYCON_TEST_LOG'], 'a') as log:\n"
            "    log.write(json.dumps([name, *args]) + '\\n')\n"
            "if name == 'sudo':\n"
            "    os.execvpe(args[0], args, os.environ)\n"
            "elif name == 'install':\n"
            "    clean = []\n"
            "    while args:\n"
            "        arg = args.pop(0)\n"
            "        if arg in ('-o', '-g'):\n"
            "            assert args.pop(0) == '0'\n"
            "        else:\n"
            "            clean.append(arg)\n"
            f"    os.execv({shutil.which('install')!r}, ['install', *clean])\n"
            "elif name == 'chown':\n"
            "    assert args == ['-R', '0:0', os.environ['PYCON_TEST_RUNTIME']]\n"
            "elif name == 'python3' and args[:4] == ['-I', '-m', 'venv', '--copies']:\n"
            "    dest = pathlib.Path(args[4]) / 'bin' / 'python'\n"
            "    dest.parent.mkdir(parents=True)\n"
            "    dest.write_text('#!/bin/bash\\n'\n"
            "        'if [[ \"$1\" == -I && \"$2\" == -m && \"$3\" == pip ]]; then\\n'\n"
            "        '    test -z \"$PYCON_TEST_PIP_FAIL\"; exit $?\\nfi\\n'\n"
            "        + 'exec ' + shlex.quote(sys.executable) + ' \"$@\"\\n')\n"
            "    dest.chmod(0o755)\n"
            "else:\n"
            "    os.execv(sys.executable, [sys.executable, *args])\n"
        )
        for name in ("sudo", "install", "chown", "python3"):
            path = mock_bin / name
            path.write_text(driver)
            path.chmod(0o755)
        self.env = dict(
            os.environ, HOME=str(self.home),
            PATH=f"{mock_bin}{os.pathsep}{os.environ['PATH']}",
            PYCON_TEST_LOG=str(self.log), PYCON_TEST_RUNTIME=str(self.runtime),
        )

    def run_script(self, name):
        return subprocess.run(
            ["bash", str(self.checkout / name)], env=self.env,
            capture_output=True, text=True, timeout=30,
        )

    def install(self):
        return self.run_script("install.sh")

    def uninstall(self):
        return self.run_script("uninstall.sh")

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]
