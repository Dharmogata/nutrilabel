"""NL004: Install-time execution hooks and dynamic/obfuscated code evaluation detector."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, List

from nutrilabel.models import CapabilityCategory, CapabilityFinding
from nutrilabel.rules.base import BaseCapabilityRule, resolve_call_name

DYNAMIC_EXEC_CALLS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "builtins.eval",
    "builtins.exec",
    "builtins.__import__",
}

DECODE_CALLS = {
    "base64.b64decode",
    "base64.urlsafe_b64decode",
    "zlib.decompress",
    "marshal.loads",
    "codecs.decode",
}


class DynamicAndInstallRule(BaseCapabilityRule):
    """Detects setup.py install hooks, eval/exec calls, and encoded payload execution."""

    rule_id = "NL004"
    name = "dynamic-and-install-exec"
    category = CapabilityCategory.OBFUSCATION
    description = (
        "Detects setup.py install-time hooks (cmdclass overrides, top-level execution) "
        "and dynamic code evaluation (eval, exec, base64+exec)."
    )

    def analyze_ast(
        self,
        tree: ast.AST,
        file_path: str,
        source_lines: List[str],
        alias_map: Dict[str, str],
    ) -> List[CapabilityFinding]:
        findings: List[CapabilityFinding] = []
        is_setup_py = Path(file_path).name == "setup.py"

        has_decode_in_file = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                cname = resolve_call_name(node, alias_map)
                if cname in DECODE_CALLS:
                    has_decode_in_file = True
                    break

        if is_setup_py:
            findings.append(
                CapabilityFinding(
                    rule_id=self.rule_id,
                    category=CapabilityCategory.INSTALL_HOOK,
                    file_path=file_path,
                    line_no=1,
                    col_offset=0,
                    symbol="setup.py",
                    detail="Contains executable `setup.py` build/install script",
                    code_snippet=self.get_line_snippet(source_lines, 1),
                    notable=False,
                    sub_kind="setup_py",
                )
            )

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = resolve_call_name(node, alias_map)

                # Detect custom cmdclass in setup(...)
                if is_setup_py and call_name in ("setup", "setuptools.setup"):
                    for kw in node.keywords:
                        if kw.arg == "cmdclass":
                            line_no = getattr(kw, "lineno", getattr(node, "lineno", 1))
                            findings.append(
                                CapabilityFinding(
                                    rule_id=self.rule_id,
                                    category=CapabilityCategory.INSTALL_HOOK,
                                    file_path=file_path,
                                    line_no=line_no,
                                    col_offset=getattr(node, "col_offset", 0),
                                    symbol="setup(cmdclass=...)",
                                    detail="Custom `cmdclass` install hook in `setup.py`",
                                    code_snippet=self.get_line_snippet(
                                        source_lines, line_no
                                    ),
                                    notable=True,
                                    sub_kind="cmdclass_hook",
                                )
                            )

                # Detect eval / exec / compile
                if call_name in DYNAMIC_EXEC_CALLS:
                    line_no = getattr(node, "lineno", 1)
                    snippet = self.get_line_snippet(source_lines, line_no)
                    paired_decode = has_decode_in_file or ("b64decode" in snippet)
                    detail = (
                        f"Encoded payload + `{call_name}()` execution"
                        if paired_decode
                        else f"Dynamic code execution via `{call_name}()`"
                    )
                    findings.append(
                        CapabilityFinding(
                            rule_id=self.rule_id,
                            category=CapabilityCategory.OBFUSCATION,
                            file_path=file_path,
                            line_no=line_no,
                            col_offset=getattr(node, "col_offset", 0),
                            symbol=f"base64+{call_name}" if paired_decode else call_name,
                            detail=detail,
                            code_snippet=snippet,
                            notable=True,
                            sub_kind="encoded_exec" if paired_decode else "dynamic_exec",
                        )
                    )

        return findings
