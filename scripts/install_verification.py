"""Install pinned Linux reference tools into an explicit cache directory."""
import hashlib
from pathlib import Path
import subprocess
import sys
import urllib.request


def fetch(url, path, digest):
    if not path.exists():
        urllib.request.urlretrieve(url,path)
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != digest:
        raise ValueError('download checksum mismatch: '+path.name)


def main():
    destination=Path(sys.argv[1]).resolve();destination.mkdir(parents=True,exist_ok=True)
    archive=destination/'lean.tar.zst'
    fetch('https://github.com/leanprover/lean4/releases/download/v4.35.0/lean-4.35.0-linux.tar.zst',archive,'7289597a44543246c9227b8cae501767e095ce17f6d448b95fc4a8dc97268f6d')
    if not (destination/'lean-4.35.0-linux/bin/lean').exists():
        subprocess.run(['tar','--zstd','-xf',str(archive),'-C',str(destination)],check=True)
    print(destination/'lean-4.35.0-linux/bin')


if __name__=='__main__':main()
