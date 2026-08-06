import subprocess
import sys
from pathlib import Path


def test_frontend_cannot_regress_to_browser_local_persistence():
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, str(root / "scripts" / "check_persistence_contract.py")],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
