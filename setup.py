"""Build hook: copy the web app and playbooks into the wheel.

In a source checkout, webui.py, templates/, static/, playbooks/ and
config.example.yaml live next to the oniops/ package. A wheel only ships
packages, so this copies them into oniops/_app/ at build time. The checkout
layout is unchanged. See oniops/paths.py for how the files are found at runtime.
"""
import shutil
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py

ROOT = Path(__file__).resolve().parent
APP_FILES = ["webui.py", "config.example.yaml"]
APP_DIRS = ["templates", "static", "playbooks"]


class BuildWithApp(build_py):
    def run(self):
        super().run()
        dest = Path(self.build_lib) / "oniops" / "_app"
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)
        for name in APP_FILES:
            shutil.copy2(ROOT / name, dest / name)
        for name in APP_DIRS:
            shutil.copytree(ROOT / name, dest / name,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))


setup(cmdclass={"build_py": BuildWithApp})
