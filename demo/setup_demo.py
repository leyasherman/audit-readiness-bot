"""Make demo-target a git repo with a clean baseline commit and (re)install the pre-commit gate.
Safe to re-run: resets demo-target to its baseline commit.  Run:  python demo/setup_demo.py"""
import subprocess
import sys
from pathlib import Path

project = Path(__file__).resolve().parent.parent
target = project / "demo-target"


def git(*args):
    subprocess.run(["git", "-C", str(target), *args], check=True)


if not (target / ".git").exists():
    git("init", "-q", "-b", "main")
    git("config", "user.name", "Acme Dev")
    git("config", "user.email", "dev@acme-health.example")
    git("config", "core.autocrlf", "false")
    git("add", "-A")
    git("commit", "-qm", "Initial infrastructure")
else:
    root = subprocess.run(["git", "-C", str(target), "rev-list", "--max-parents=0", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.split()[0]
    git("reset", "-q", "--hard", root)   # drops demo commits made with --no-verify
    git("clean", "-qfd")

subprocess.run([sys.executable, "-m", "auditbot", "install-hook", str(target)], cwd=project, check=True)
print("Demo repo ready.")
