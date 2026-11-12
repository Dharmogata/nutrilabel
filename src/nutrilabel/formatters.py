"""Terminal Nutrition Facts label, explain view, JSON, and Markdown formatters."""

from __future__ import annotations

import json
from typing import List, Sequence

from nutrilabel.models import (
    CATEGORY_LABELS,
    CapabilityCategory,
    NutritionReport,
    VersionDiffReport,
)
from nutrilabel.rules.base import BaseCapabilityRule

BOX_INNER_WIDTH = 52


def _pad_box_line(text: str, width: int = BOX_INNER_WIDTH) -> str:
    if len(text) > width:
        text = text[: width - 1] + "…"
    return f" │ {text:<{width}} │"


def format_nutrition_label(
    report: NutritionReport,
    explain: bool = False,
    output_format: str = "text",
) -> str:
    """Format a NutritionReport as a terminal label, JSON, or Markdown."""
    if output_format == "json":
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)

    if output_format == "markdown":
        return _format_nutrition_markdown(report, explain=explain)

    top_border = " ┌" + ("─" * (BOX_INNER_WIDTH + 2)) + "┐"
    mid_border = " ├" + ("─" * (BOX_INNER_WIDTH + 2)) + "┤"
    bot_border = " └" + ("─" * (BOX_INNER_WIDTH + 2)) + "┘"

    title_left = "Package Nutrition Facts"
    title_right = f"{report.package_name} {report.version}"
    space_count = max(1, BOX_INNER_WIDTH - len(title_left) - len(title_right))
    title_line = f"{title_left}{' ' * space_count}{title_right}"

    meta_line = (
        f"Files: {report.total_files} · "
        f"Lines: {report.total_lines:,} · "
        f"Deps: {len(report.dependencies)}"
    )

    lines: List[str] = [
        top_border,
        _pad_box_line(title_line),
        _pad_box_line(meta_line),
        mid_border,
    ]

    # 1. Network Access
    net_findings = report.findings_by_category(CapabilityCategory.NETWORK)
    net_urls = [f for f in net_findings if f.sub_kind == "hardcoded_url"]
    if net_findings:
        lines.append(
            _pad_box_line(
                f"{'Network Access':<28}{'Present':<10}{len(net_findings)} place(s)"
            )
        )
        if net_urls:
            lines.append(
                _pad_box_line(
                    f"{'  └ Hardcoded Endpoints':<28}{len(net_urls)} found   ⚠"
                )
            )
    else:
        lines.append(_pad_box_line(f"{'Network Access':<28}{'None':<10}"))

    # 2. Process Execution
    proc_findings = report.findings_by_category(CapabilityCategory.PROCESS)
    if proc_findings:
        warn = " ⚠" if any(f.notable for f in proc_findings) else ""
        lines.append(
            _pad_box_line(
                f"{'Process Execution':<28}{'Present':<10}{len(proc_findings)} place(s){warn}"
            )
        )
    else:
        lines.append(_pad_box_line(f"{'Process Execution':<28}{'None':<10}"))

    # 3. Environment Read
    env_findings = report.findings_by_category(CapabilityCategory.ENV_READ)
    if env_findings:
        notable_env = [f.symbol for f in env_findings if f.notable]
        if notable_env:
            sample = notable_env[0]
            lines.append(
                _pad_box_line(
                    f"{'Environment Read':<28}{'Present':<10}{sample} ⚠"
                )
            )
        else:
            lines.append(
                _pad_box_line(
                    f"{'Environment Read':<28}{'Present':<10}{len(env_findings)} place(s)"
                )
            )
    else:
        lines.append(_pad_box_line(f"{'Environment Read':<28}{'None':<10}"))

    # 4. Home/Sensitive Files
    fs_findings = report.findings_by_category(CapabilityCategory.FILESYSTEM)
    if fs_findings:
        sample_path = fs_findings[0].symbol
        lines.append(
            _pad_box_line(
                f"{'Home/Sensitive Files':<28}{'Present':<10}{sample_path} ⚠"
            )
        )
    else:
        lines.append(_pad_box_line(f"{'Home/Sensitive Files':<28}{'None':<10}"))

    # 5. Install-Time Code
    hook_findings = report.findings_by_category(CapabilityCategory.INSTALL_HOOK)
    if hook_findings:
        has_cmdclass = any(f.sub_kind == "cmdclass_hook" for f in hook_findings)
        suffix = "cmdclass ⚠" if has_cmdclass else "setup.py"
        lines.append(
            _pad_box_line(f"{'Install-Time Execution':<28}{'Present':<10}{suffix}")
        )
    else:
        lines.append(_pad_box_line(f"{'Install-Time Execution':<28}{'None':<10}"))

    # 6. Obfuscation / Dynamic Exec
    obf_findings = report.findings_by_category(CapabilityCategory.OBFUSCATION)
    if obf_findings:
        lines.append(
            _pad_box_line(
                f"{'Obfuscation / Eval':<28}{'Present':<10}{len(obf_findings)} place(s) ⚠"
            )
        )
    else:
        lines.append(_pad_box_line(f"{'Obfuscation (base64+exec)':<28}{'None':<10}"))

    # 7. Native Binary
    bin_findings = report.findings_by_category(CapabilityCategory.NATIVE_BINARY)
    if bin_findings:
        lines.append(
            _pad_box_line(
                f"{'Native Binary Extensions':<28}{'Present':<10}{len(bin_findings)} file(s) ⚠"
            )
        )
    else:
        lines.append(_pad_box_line(f"{'Native Binary Extensions':<28}{'None':<10}"))

    lines.append(mid_border)
    summary_text = (
        f"Overall: Grade {report.grade} "
        f"({report.notable_count} notable item(s))"
    )
    lines.append(_pad_box_line(summary_text))
    if report.badges:
        badge_str = "Badges: " + ", ".join(f"[{b}]" for b in report.badges[:3])
        lines.append(_pad_box_line(badge_str))
    lines.append(bot_border)

    if not explain:
        lines.append(f" Details: nutrilabel {report.package_name} --explain")
    else:
        lines.append("")
        lines.append(" Detailed Capability Locations (--explain):")
        lines.append(" " + ("─" * 54))
        if not report.findings:
            lines.append("  No special runtime capabilities detected.")
        for f in report.findings:
            flag = " ⚠" if f.notable else ""
            lines.append(
                f"  [{f.rule_id}] {f.file_path}:{f.line_no} — {f.detail}{flag}"
            )
            if f.code_snippet:
                lines.append(f"         > {f.code_snippet}")

    return "\n".join(lines)


def _format_nutrition_markdown(
    report: NutritionReport,
    explain: bool = False,
) -> str:
    md: List[str] = [
        f"# Package Nutrition Facts: `{report.package_name}` `{report.version}`",
        "",
        f"- **Files:** {report.total_files} | **Lines:** {report.total_lines:,} | **Dependencies:** {len(report.dependencies)}",
        f"- **Overall Grade:** **{report.grade}** ({report.notable_count} notable item(s))",
        f"- **Badges:** {', '.join(f'`{b}`' for b in report.badges)}",
        "",
        "| Capability | Status | Count / Detail |",
        "| :--- | :--- | :--- |",
    ]
    for cat in CapabilityCategory:
        cat_findings = report.findings_by_category(cat)
        status = "Present" if cat_findings else "None"
        notable = " ⚠" if any(f.notable for f in cat_findings) else ""
        detail = f"{len(cat_findings)} location(s){notable}" if cat_findings else "—"
        md.append(f"| {CATEGORY_LABELS[cat]} | {status} | {detail} |")

    if explain and report.findings:
        md.extend(
            [
                "",
                "## Detailed Capability Locations",
                "",
                "| Rule | Location | Detail | Snippet |",
                "| :--- | :--- | :--- | :--- |",
            ]
        )
        for f in report.findings:
            md.append(
                f"| `{f.rule_id}` | `{f.file_path}:{f.line_no}` | {f.detail} | `{f.code_snippet}` |"
            )

    return "\n".join(md)


def format_diff_report(
    diff: VersionDiffReport,
    output_format: str = "text",
) -> str:
    """Format a VersionDiffReport comparing two package versions."""
    if output_format == "json":
        return json.dumps(diff.to_dict(), indent=2, ensure_ascii=False)

    if output_format == "markdown":
        lines = [
            f"# Package Capability Diff: `{diff.package_name}` (`{diff.old_version}` → `{diff.new_version}`)",
            "",
            f"- **Grade Transition:** `{diff.old_grade}` → `{diff.new_grade}`",
            f"- **Added Dependencies:** {', '.join(f'`{d}`' for d in diff.added_dependencies) or 'None'}",
            "",
            "| Capability | Old Count | New Count | Status |",
            "| :--- | ---: | ---: | :--- |",
        ]
        for entry in diff.capability_diffs:
            lines.append(
                f"| {CATEGORY_LABELS[entry.category]} | {entry.old_count} | {entry.new_count} | `{entry.status}` |"
            )
        return "\n".join(lines)

    lines = [
        f"Package Capability Diff: {diff.package_name} ({diff.old_version} -> {diff.new_version})",
        "─" * 64,
        f"  Files : {diff.old_files} -> {diff.new_files}   |   "
        f"Lines : {diff.old_lines:,} -> {diff.new_lines:,}   |   "
        f"Grade : {diff.old_grade} -> {diff.new_grade}",
    ]
    if diff.added_dependencies:
        lines.append(f"  + Added Dependencies   : {', '.join(diff.added_dependencies)}")
    if diff.removed_dependencies:
        lines.append(f"  - Removed Dependencies : {', '.join(diff.removed_dependencies)}")

    lines.append("─" * 64)
    lines.append(f"  {'Capability':<26}{'Old':>6} -> {'New':<6}  Status")
    lines.append("─" * 64)

    for entry in diff.capability_diffs:
        label = CATEGORY_LABELS[entry.category]
        if entry.status == "added_capability":
            tag = "★ NEW CAPABILITY ⚠"
        elif entry.status == "increased":
            tag = f"+{entry.new_count - entry.old_count} increased"
        elif entry.status == "removed_capability":
            tag = "removed"
        elif entry.status == "decreased":
            tag = f"{entry.new_count - entry.old_count} decreased"
        else:
            tag = "unchanged"

        lines.append(
            f"  {label:<26}{entry.old_count:>6} -> {entry.new_count:<6}  {tag}"
        )
        for item in entry.new_notable_details[:5]:
            lines.append(f"    + {item}")

    return "\n".join(lines)


def format_rules_catalog(rules: Sequence[BaseCapabilityRule]) -> str:
    lines = [
        "NutriLabel Built-in AST Capability Detectors:",
        "─" * 68,
    ]
    for r in rules:
        lines.append(f"  {r.rule_id} [{r.category.value:<12}] {r.name}")
        lines.append(f"        {r.description}")
    return "\n".join(lines)
