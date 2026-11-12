"""Package capability analysis engine and version-to-version diff calculator."""

from __future__ import annotations

import ast
from typing import List, Optional, Sequence

from nutrilabel.extractor import ExtractedPackage, load_package_target
from nutrilabel.models import (
    CapabilityCategory,
    CapabilityDiffEntry,
    CapabilityFinding,
    NutritionReport,
    VersionDiffReport,
)
from nutrilabel.rules import get_default_rules
from nutrilabel.rules.base import BaseCapabilityRule, build_import_alias_map


class NutritionAnalyzer:
    """Runs AST capability rules across an ExtractedPackage to produce a NutritionReport."""

    def __init__(self, rules: Optional[Sequence[BaseCapabilityRule]] = None) -> None:
        self.rules: List[BaseCapabilityRule] = (
            list(rules) if rules is not None else get_default_rules()
        )

    def analyze_extracted(self, package: ExtractedPackage) -> NutritionReport:
        findings: List[CapabilityFinding] = []

        for file_path, source_text in sorted(package.python_files.items()):
            try:
                tree = ast.parse(source_text, filename=file_path)
            except SyntaxError:
                continue

            source_lines = source_text.splitlines()
            alias_map = build_import_alias_map(tree)
            for rule in self.rules:
                findings.extend(
                    rule.analyze_ast(tree, file_path, source_lines, alias_map)
                )

        for bin_path in sorted(package.native_binaries):
            findings.append(
                CapabilityFinding(
                    rule_id="NL005",
                    category=CapabilityCategory.NATIVE_BINARY,
                    file_path=bin_path,
                    line_no=1,
                    col_offset=0,
                    symbol=bin_path,
                    detail=f"Pre-compiled native extension `{bin_path}`",
                    code_snippet="",
                    notable=True,
                    sub_kind="native_binary",
                )
            )

        notable_count = sum(1 for f in findings if f.notable)
        grade = self._compute_grade(findings, notable_count)
        badges = self._compute_badges(findings)

        return NutritionReport(
            package_name=package.package_name,
            version=package.version,
            total_files=package.total_files,
            total_lines=package.total_lines,
            dependencies=package.dependencies,
            native_binaries=package.native_binaries,
            findings=findings,
            grade=grade,
            notable_count=notable_count,
            badges=badges,
        )

    def analyze_target(
        self, target: str, version: Optional[str] = None
    ) -> NutritionReport:
        extracted = load_package_target(target, version=version)
        return self.analyze_extracted(extracted)

    @staticmethod
    def _compute_grade(findings: List[CapabilityFinding], notable_count: int) -> str:
        has_encoded_exec = any(f.sub_kind == "encoded_exec" for f in findings)
        if has_encoded_exec or notable_count >= 5:
            return "D"
        if notable_count >= 3:
            return "C"
        if notable_count >= 1 or len(findings) >= 5:
            return "B"
        return "A"

    @staticmethod
    def _compute_badges(findings: List[CapabilityFinding]) -> List[str]:
        cats = {f.category for f in findings}
        badges: List[str] = []
        if not cats:
            return ["Pure-Computation"]
        if CapabilityCategory.NETWORK in cats:
            badges.append("Network-Enabled")
        if CapabilityCategory.PROCESS in cats:
            badges.append("Subprocess-Capable")
        if CapabilityCategory.ENV_READ in cats:
            badges.append("Env-Configured")
        if CapabilityCategory.FILESYSTEM in cats:
            badges.append("Sensitive-Path-Reader")
        if CapabilityCategory.INSTALL_HOOK in cats:
            badges.append("Setup-Script")
        if CapabilityCategory.OBFUSCATION in cats:
            badges.append("Dynamic-Eval")
        if CapabilityCategory.NATIVE_BINARY in cats:
            badges.append("Native-Extension")
        return badges


def diff_reports(
    old_report: NutritionReport,
    new_report: NutritionReport,
) -> VersionDiffReport:
    """Compare two NutritionReports and highlight newly introduced or changed capabilities."""
    old_deps = set(old_report.dependencies)
    new_deps = set(new_report.dependencies)
    added_deps = sorted(new_deps - old_deps)
    removed_deps = sorted(old_deps - new_deps)

    diff_entries: List[CapabilityDiffEntry] = []
    for category in CapabilityCategory:
        old_cat_findings = old_report.findings_by_category(category)
        new_cat_findings = new_report.findings_by_category(category)
        old_c = len(old_cat_findings)
        new_c = len(new_cat_findings)

        old_symbols = {(f.symbol, f.detail) for f in old_cat_findings}
        new_notables = [
            f"{f.detail} ({f.file_path}:{f.line_no})"
            for f in new_cat_findings
            if (f.symbol, f.detail) not in old_symbols
        ]

        if old_c == 0 and new_c > 0:
            status = "added_capability"
        elif old_c > 0 and new_c == 0:
            status = "removed_capability"
        elif new_c > old_c:
            status = "increased"
        elif new_c < old_c:
            status = "decreased"
        else:
            status = "unchanged"

        diff_entries.append(
            CapabilityDiffEntry(
                category=category,
                old_count=old_c,
                new_count=new_c,
                status=status,
                new_notable_details=new_notables,
            )
        )

    return VersionDiffReport(
        package_name=new_report.package_name or old_report.package_name,
        old_version=old_report.version,
        new_version=new_report.version,
        old_files=old_report.total_files,
        new_files=new_report.total_files,
        old_lines=old_report.total_lines,
        new_lines=new_report.total_lines,
        added_dependencies=added_deps,
        removed_dependencies=removed_deps,
        capability_diffs=diff_entries,
        old_grade=old_report.grade,
        new_grade=new_report.grade,
    )
