"""Registry of built-in AST capability detection rules."""

from __future__ import annotations

from typing import List

from nutrilabel.rules.base import BaseCapabilityRule
from nutrilabel.rules.nl001_network import NetworkCapabilityRule
from nutrilabel.rules.nl002_process import ProcessExecutionRule
from nutrilabel.rules.nl003_env_fs import EnvAndFilesystemRule
from nutrilabel.rules.nl004_dynamic_setup import DynamicAndInstallRule


def get_default_rules() -> List[BaseCapabilityRule]:
    """Return all built-in package capability rules in canonical order."""
    return [
        NetworkCapabilityRule(),
        ProcessExecutionRule(),
        EnvAndFilesystemRule(),
        DynamicAndInstallRule(),
    ]
