"""Place Quint's pinned Rust evaluator where the Quint CLI looks for it.

The CLI otherwise asks the unauthenticated GitHub releases API for the asset,
which shared CI runners hit the rate limit on. The release download URL is not
an API call, and the archive digest is fixed here.
"""
import hashlib
import os
from pathlib import Path
import sys
import tarfile
import urllib.request

VERSION = 'v0.7.1'
ASSET = 'quint_evaluator-x86_64-unknown-linux-gnu.tar.gz'
URL = 'https://github.com/quint-co/quint/releases/download/evaluator%2F' + VERSION + '/' + ASSET
DIGEST = 'ce0502bdef65dc26c242a9e56379a9bb26de6f3db38f0e3989339d46a542f5eb'


MANAGER = Path(__file__).resolve().parent.parent / 'tests/models/node_modules/@informalsystems/quint/dist/src/rust/binaryManager.js'


def check_version(manager=MANAGER):
    # A Quint bump can move the evaluator version; fail instead of letting the
    # CLI fall back to the rate-limited API.
    wanted = "QUINT_EVALUATOR_VERSION = '" + VERSION + "'"
    if wanted not in manager.read_text(encoding='utf-8'):
        raise ValueError('Quint expects another evaluator; update VERSION and DIGEST in ' + Path(__file__).name)


def install(home):
    target = home / ('rust-evaluator-' + VERSION)
    executable = target / 'quint_evaluator'
    if executable.exists():
        return executable
    target.mkdir(parents=True, exist_ok=True)
    archive = target / ASSET
    if not archive.exists():
        urllib.request.urlretrieve(URL, archive)
    with archive.open('rb') as stream:
        if hashlib.file_digest(stream, 'sha256').hexdigest() != DIGEST:
            archive.unlink()
            raise ValueError('download checksum mismatch: ' + ASSET)
    with tarfile.open(archive) as bundle:
        member = bundle.getmember('quint_evaluator')
        bundle.extract(member, target, filter='data')
    executable.chmod(0o755)
    archive.unlink()
    return executable


def main():
    home = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ.get('QUINT_HOME', Path.home() / '.quint'))
    check_version()
    print(install(home.resolve()))


if __name__ == '__main__':
    main()
