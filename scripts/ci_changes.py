"""Classify GitHub changes without suppressing status checks or scheduled scans."""
import json
import os
from pathlib import PurePosixPath, Path
import subprocess


def classify(paths):
    """Unknown paths require all checks; renames must include both endpoints."""
    def documentation(path):
        return (path.startswith("doc/") or path in {"LICENSE", ".all-contributorsrc"}
                or PurePosixPath(path).suffix.lower() in
                {".md", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico"})
    return {
        "code": any(not documentation(path) for path in paths),
        "workflows": any(path.startswith(".github/workflows/") or path.startswith(".github/actions/")
                         or path in {"scripts/ci_changes.py", "scripts/test_ci_changes.py"} for path in paths),
    }


def changes(event_name, event):
    if event_name not in {"pull_request", "push"}:
        return {"code": True, "workflows": True}
    if event_name == "pull_request":
        base = event["pull_request"]["base"]["sha"]
        head = event["pull_request"]["head"]["sha"]
        revision = [base + "..." + head]
    else:
        base, head = event["before"], event["after"]
        if set(base) == {"0"}:
            return {"code": True, "workflows": True}
        revision = [base, head]
    # --no-renames includes the deleted source as well as the added destination.
    # Missing history fails this job instead of silently skipping code checks.
    raw = subprocess.check_output(["git", "diff", "--name-only", "--no-renames", "-z", *revision, "--"])
    return classify(raw.decode("utf-8", errors="surrogateescape").rstrip("\0").split("\0"))


if __name__ == "__main__":
    result = changes(os.environ["GITHUB_EVENT_NAME"], json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text()))
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        for key, value in result.items():
            print(f"{key}={str(value).lower()}", file=output)
