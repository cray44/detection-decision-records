"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def valid_fixtures_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "valid"


@pytest.fixture
def negative_fixtures_dir(fixtures_dir: Path) -> Path:
    return fixtures_dir / "negative"


@pytest.fixture
def sample_sigma_rule(tmp_path: Path) -> Path:
    """A minimal valid Sigma rule file for hash/new-command tests."""
    rule = tmp_path / "sample_rule.yml"
    rule.write_text(
        """title: Suspicious PsExec Execution
id: d7a95147-145f-4678-b555-b7a3c9b16830
status: experimental
description: Detects PsExec execution which may indicate lateral movement.
references:
  - https://docs.microsoft.com/en-us/sysinternals/downloads/psexec
author: SigmaHQ
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - \\PsExec.exe
      - \\PsExec64.exe
  condition: selection
falsepositives:
  - Administrative activity
level: medium
tags:
  - attack.lateral_movement
  - attack.t1570
""",
        encoding="utf-8",
    )
    return rule
