"""Generate the adoption table by running the actual application output cases."""
import argparse
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    env = dict(os.environ, UPDATE_DOCS='0' if args.check else '1')
    subprocess.run(['go', '-C', 'tests', 'test', '.', '-run', '^TestAdoption(Cases|DeclaredControls|CheckIndependence)$', '-count=1'],
                   cwd=Path(__file__).resolve().parents[1], env=env, check=True)


if __name__ == '__main__':
    main()
