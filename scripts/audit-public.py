"""Bounded publication audit. Never print matching contents or secret values."""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
ALLOWED = {
    "README.md", "VERSION", "package.json", ".gitignore", ".gitlab-ci.yml",
    "plugin/index.mjs", "plugin/identity.mjs", "plugin/package.json",
    "tests/stalker-plugin.test.mjs", "scripts/audit-public.py",
}
PATTERNS = [
    r"\bstalker_[A-Za-z0-9_-]{43}\b",
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    r"\b(?:ghp_|github_pat_|glpat-|hvs\.)[A-Za-z0-9_.-]{12,}",
    r"\bAIza[A-Za-z0-9_-]{30,}",
    r"\b[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}\b",
    r"\b[a-f0-9]{64}\b",
    r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",
    r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",
    r"\.int\.[A-Za-z0-9.-]+",
]

def git(*args):
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, timeout=10)
    if result.returncode or len(result.stdout) > 1048576:
        raise ValueError("git_audit_failed")
    return result.stdout

def scan(data):
    if len(data) > 262144 or b"\0" in data:
        raise ValueError("non_source_blob")
    text = data.decode("utf8")
    if any(re.search(pattern, text) for pattern in PATTERNS):
        raise ValueError("forbidden_public_content")

def main():
    staged = git("ls-files").decode().splitlines()
    if set(staged) != ALLOWED:
        raise ValueError("unexpected_tracked_scope")
    for name in staged:
        path = ROOT / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("non_regular_source")
        scan(path.read_bytes())
    version = (ROOT / "VERSION").read_text().strip()
    if version != "0.3.2" or any(json.loads((ROOT / name).read_text())["version"] != version
        for name in ["package.json", "plugin/package.json"]):
        raise ValueError("manifest_version_mismatch")
    history = git("rev-list", "--all", "--parents").decode().splitlines()
    # This extraction begins with one new root commit, never a monorepo parent.
    if len(history) > 50:
        raise ValueError("unexpected_history_scope")
    roots = [line for line in history if len(line.split()) == 1]
    if history and len(roots) != 1:
        raise ValueError("unexpected_history_roots")
    blobs = 0
    for line in history:
        commit = line.split()[0]
        scan(git("show", "-s", "--format=%B%n%an%n%ae", commit))
        files = git("ls-tree", "-r", "--name-only", commit).decode().splitlines()
        if set(files) != ALLOWED:
            raise ValueError("unexpected_historical_scope")
        for name in files:
            scan(git("show", commit + ":" + name))
            blobs += 1
    branches = git("for-each-ref", "--format=%(refname)", "refs/heads", "refs/tags").decode().splitlines()
    if any(name not in {"refs/heads/dev", "refs/heads/main"} for name in branches):
        raise ValueError("unexpected_public_ref")
    print(json.dumps({"public_content_audit": "passed", "tracked_files": len(staged),
        "reachable_commits": len(history), "historical_blobs_checked": blobs,
        "local_branches": len(branches), "secret_values_printed": 0}))

if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(json.dumps({"public_content_audit": "failed", "reason": str(error) if isinstance(error, ValueError) else type(error).__name__}))
        sys.exit(2)
