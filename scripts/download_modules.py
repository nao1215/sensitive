"""Warm the shared module cache with three bounded attempts before running checks."""
from pathlib import Path
import subprocess
import sys
import time


def download(directory):
    for attempt in range(3):
        try:
            subprocess.run(['go', 'mod', 'download'], cwd=directory, check=True)
            return
        except subprocess.CalledProcessError:
            if attempt == 2:
                raise
            time.sleep(2 ** attempt)


if __name__ == '__main__':
    for name in sys.argv[1:]:
        download(Path(name))
