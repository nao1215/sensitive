"""Merge Go set/count/atomic coverage by source block, without double counting statements."""
import sys
from pathlib import Path


def merge(paths):
    mode = None
    blocks = {}
    for path in paths:
        lines = Path(path).read_text().splitlines()
        if not lines or not lines[0].startswith("mode: "):
            raise ValueError(f"invalid coverage profile: {path}")
        current = lines[0]
        if current not in ("mode: set", "mode: count", "mode: atomic"):
            raise ValueError(f"unsupported mode: {current}")
        if mode is not None and current != mode:
            raise ValueError("coverage modes differ")
        mode = current
        for line in lines[1:]:
            location, statements, count = line.split()
            statements, count = int(statements), int(count)
            old_statements, old_count = blocks.get(location, (statements, 0))
            if statements != old_statements:
                raise ValueError(f"source blocks differ: {location}")
            blocks[location] = (statements, max(old_count, count) if mode == "mode: set" else old_count + count)
    if mode is None or not blocks:
        raise ValueError("empty coverage input")
    return mode + "\n" + "".join(f"{key} {n} {count}\n" for key, (n, count) in sorted(blocks.items()))


if __name__ == "__main__":
    sys.stdout.write(merge(sys.argv[1:]))
