"""Generate the official lockfile while retaining reviewed full-SHA workflows."""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    originals = {path: path.read_bytes() for path in (ROOT/'.github/workflows').glob('*.yml')}
    try:
        subprocess.run(['gh', 'actions-lock'], cwd=ROOT, check=True)
    finally:
        # v0.4.1 renders tag names even for SHA inputs. The generated lockfile
        # accepts the original SHAs too; keep them for Scorecard's workflow scan.
        for path, data in originals.items():
            path.write_bytes(data)
    subprocess.run(['gh', 'actions-lock', '--verify'], cwd=ROOT, check=True)


if __name__ == '__main__':
    main()
