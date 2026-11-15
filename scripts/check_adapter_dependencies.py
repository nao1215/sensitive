#!/usr/bin/env python3
"""Run adapter tests against their declared root dependency, without local replaces."""
import pathlib
import shutil
import subprocess
import tempfile

from download_modules import download

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    for module in ("zap", "zerolog", "logrus"):
        with tempfile.TemporaryDirectory(prefix="embargo-dependency-") as directory:
            target = pathlib.Path(directory) / module
            shutil.copytree(ROOT / "adapters" / module, target)
            subprocess.run(
                ["go", "mod", "edit", "-dropreplace=github.com/nao1215/embargo"],
                cwd=target, check=True,
            )
            subprocess.run(
                ["go", "list", "-m", "github.com/nao1215/embargo"],
                cwd=target, check=True,
            )
            download(target)
            subprocess.run(["go", "test", "-mod=mod", "./..."], cwd=target, check=True)


if __name__ == "__main__":
    main()
