"""Check that the standalone SDK example runs as a separate Python process."""

import subprocess
import sys
from pathlib import Path


def test_separate_program_imports_sdk_and_recovers_file():
    project = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [sys.executable, "-m", "examples.integration_demo"],
        cwd=project, capture_output=True, text=True, check=True,
    )
    assert "Receiver created suite 4 keys." in result.stdout
    assert "SUCCESS: a separate Python app used QShield" in result.stdout
