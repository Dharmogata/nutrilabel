"""Base AST capability rule interface and symbol resolution helpers."""

from __future__ import annotations

from abc import ABC, abstractmethod
import ast
from typing import Dict, List

from nutrilabel.models import CapabilityCategory, CapabilityFinding


class BaseCapabilityRule(ABC):
    """Abstract base class for AST capability detection rules."""

    rule_id: str = ""
    name: str = ""
    category: CapabilityCategory = CapabilityCategory.NETWORK
    description: str = ""

    @abstractmethod
    def analyze_ast(
        self,
        tree: ast.AST,
        file_path: str,
        source_lines: List[str],
        alias_map: Dict[str, str],
    ) -> List[CapabilityFinding]:
        """Inspect a parsed Python AST and return discovered CapabilityFindings."""

    @staticmethod
    def get_line_snippet(source_lines: List[str], line_no: int) -> str:
        if 1 <= line_no <= len(source_lines):
            return source_lines[line_no - 1].strip()
        return ""


def build_import_alias_map(tree: ast.AST) -> Dict[str, str]:
    """Build a mapping of local alias -> canonical dotted module/symbol name."""
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                local_name = item.asname or item.name
                aliases[local_name] = item.name
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for item in node.names:
                local_name = item.asname or item.name
                aliases[local_name] = f"{mod}.{item.name}" if mod else item.name
    return aliases


def resolve_call_name(node: ast.Call, alias_map: Dict[str, str]) -> str:
    """Resolve an ast.Call target to a normalized dotted string using alias_map."""
    parts: List[str] = []
    curr: ast.AST = node.func
    while isinstance(curr, ast.Attribute):
        parts.append(curr.attr)
        curr = curr.value
    if isinstance(curr, ast.Name):
        parts.append(curr.id)
        parts.reverse()
        head = parts[0]
        if head in alias_map:
            resolved_head = alias_map[head]
            return ".".join([resolved_head] + parts[1:])
        return ".".join(parts)
    return ""
