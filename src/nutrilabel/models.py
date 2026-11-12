"""Core data models for package capability findings, nutrition labels, and version diffs."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class CapabilityCategory(str, Enum):
    """Standardized package runtime and install-time capability categories."""

    NETWORK = "network"
    PROCESS = "process"
    ENV_READ = "env_read"
    FILESYSTEM = "filesystem"
    INSTALL_HOOK = "install_hook"
    OBFUSCATION = "obfuscation"
    NATIVE_BINARY = "native_binary"


CATEGORY_LABELS: Dict[CapabilityCategory, str] = {
    CapabilityCategory.NETWORK: "Network Access",
    CapabilityCategory.PROCESS: "Process Execution",
    CapabilityCategory.ENV_READ: "Environment Read",
    CapabilityCategory.FILESYSTEM: "Home/Sensitive Files",
    CapabilityCategory.INSTALL_HOOK: "Install-Time Code",
    CapabilityCategory.OBFUSCATION: "Dynamic/Encoded Exec",
    CapabilityCategory.NATIVE_BINARY: "Native Binary Ext",
}


@dataclass(frozen=True)
class CapabilityFinding:
    """A single capability indicator discovered via static AST or archive inspection."""

    rule_id: str
    category: CapabilityCategory
    file_path: str
    line_no: int
    col_offset: int
    symbol: str
    detail: str
    code_snippet: str = ""
    notable: bool = False
    sub_kind: str = ""  # e.g. "hardcoded_url", "env_key", "sensitive_path"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category.value,
            "file_path": self.file_path,
            "line_no": self.line_no,
            "col_offset": self.col_offset,
            "symbol": self.symbol,
            "detail": self.detail,
            "code_snippet": self.code_snippet,
            "notable": self.notable,
            "sub_kind": self.sub_kind,
        }


@dataclass
class NutritionReport:
    """Complete Nutrition Facts summary for a single Python package version."""

    package_name: str
    version: str
    total_files: int
    total_lines: int
    dependencies: List[str] = field(default_factory=list)
    native_binaries: List[str] = field(default_factory=list)
    findings: List[CapabilityFinding] = field(default_factory=list)
    grade: str = "A"
    notable_count: int = 0
    badges: List[str] = field(default_factory=list)

    def findings_by_category(
        self, category: CapabilityCategory
    ) -> List[CapabilityFinding]:
        return [f for f in self.findings if f.category == category]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "total_files": self.total_files,
            "total_lines": self.total_lines,
            "dependencies": list(self.dependencies),
            "native_binaries": list(self.native_binaries),
            "grade": self.grade,
            "notable_count": self.notable_count,
            "badges": list(self.badges),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass(frozen=True)
class CapabilityDiffEntry:
    """Represents a capability change between two versions of a package."""

    category: CapabilityCategory
    old_count: int
    new_count: int
    status: str  # "added_capability", "increased", "decreased", "removed_capability", "unchanged"
    new_notable_details: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category.value,
            "label": CATEGORY_LABELS[self.category],
            "old_count": self.old_count,
            "new_count": self.new_count,
            "delta": self.new_count - self.old_count,
            "status": self.status,
            "new_notable_details": list(self.new_notable_details),
        }


@dataclass
class VersionDiffReport:
    """Comparison of capabilities and metadata between two package versions."""

    package_name: str
    old_version: str
    new_version: str
    old_files: int
    new_files: int
    old_lines: int
    new_lines: int
    added_dependencies: List[str] = field(default_factory=list)
    removed_dependencies: List[str] = field(default_factory=list)
    capability_diffs: List[CapabilityDiffEntry] = field(default_factory=list)
    old_grade: str = "A"
    new_grade: str = "A"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "old_files": self.old_files,
            "new_files": self.new_files,
            "old_lines": self.old_lines,
            "new_lines": self.new_lines,
            "added_dependencies": list(self.added_dependencies),
            "removed_dependencies": list(self.removed_dependencies),
            "old_grade": self.old_grade,
            "new_grade": self.new_grade,
            "capability_diffs": [d.to_dict() for d in self.capability_diffs],
        }
