"""NL002: Subprocess and OS command execution capability detector."""

from __future__ import annotations

import ast
from typing import Dict, List

from nutrilabel.models import CapabilityCategory, CapabilityFinding
from nutrilabel.rules.base import BaseCapabilityRule, resolve_call_name

PROCESS_CALLS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "subprocess.getstatusoutput",
    "os.system",
    "os.popen",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnl",
    "pty.spawn",
}


class ProcessExecutionRule(BaseCapabilityRule):
    """Detects external process and shell command execution calls."""

    rule_id = "NL002"
    name = "process-execution"
    category = CapabilityCategory.PROCESS
    description = (
        "Detects child process creation and shell command invocations "
        "(subprocess.*, os.system, os.popen, os.exec*, pty.spawn)."
    )

    def analyze_ast(
        self,
        tree: ast.AST,
        file_path: str,
        source_lines: List[str],
        alias_map: Dict[str, str],
    ) -> List[CapabilityFinding]:
        findings: List[CapabilityFinding] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = resolve_call_name(node, alias_map)
                if call_name in PROCESS_CALLS:
                    line_no = getattr(node, "lineno", 1)
                    uses_shell = any(
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                        for kw in node.keywords
                    )
                    notable = uses_shell or call_name in ("os.system", "os.popen")
                    detail = (
                        f"Shell command execution `{call_name}(shell=True)`"
                        if uses_shell
                        else f"Process execution `{call_name}()`"
                    )
                    findings.append(
                        CapabilityFinding(
                            rule_id=self.rule_id,
                            category=self.category,
                            file_path=file_path,
                            line_no=line_no,
                            col_offset=getattr(node, "col_offset", 0),
                            symbol=call_name,
                            detail=detail,
                            code_snippet=self.get_line_snippet(source_lines, line_no),
                            notable=notable,
                            sub_kind="shell_exec" if notable else "process_call",
                        )
                    )
        return findings
