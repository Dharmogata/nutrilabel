"""NL003: Environment variable read and sensitive filesystem path detector."""

from __future__ import annotations

import ast
from typing import Dict, List, Optional

from nutrilabel.models import CapabilityCategory, CapabilityFinding
from nutrilabel.rules.base import BaseCapabilityRule, resolve_call_name

SENSITIVE_ENV_PREFIXES = (
    "AWS_",
    "GITHUB_",
    "GH_",
    "OPENAI_",
    "ANTHROPIC_",
    "GOOGLE_",
    "AZURE_",
    "SLACK_",
    "STRIPE_",
    "DATABASE_URL",
    "PRIVATE_KEY",
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "API_KEY",
)

SENSITIVE_PATHS = (
    "~/.ssh",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "~/.aws",
    ".aws/credentials",
    "~/.kube",
    ".kube/config",
    "~/.gnupg",
    "~/.netrc",
    ".git-credentials",
    "/etc/passwd",
    "/etc/shadow",
)


def _is_notable_env_key(key: str) -> bool:
    upper = key.upper()
    return any(
        upper.startswith(prefix) or prefix in upper
        for prefix in SENSITIVE_ENV_PREFIXES
    )


class EnvAndFilesystemRule(BaseCapabilityRule):
    """Detects environment variable access and sensitive user/system path references."""

    rule_id = "NL003"
    name = "env-and-filesystem"
    category = CapabilityCategory.ENV_READ
    description = (
        "Detects environment variable access (os.environ, os.getenv) and "
        "references to sensitive home or system paths (~/.ssh, ~/.aws, /etc/passwd)."
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
            # 1. os.getenv("KEY") or os.environ.get("KEY")
            if isinstance(node, ast.Call):
                call_name = resolve_call_name(node, alias_map)
                if call_name in ("os.getenv", "os.environ.get", "os.environ.pop"):
                    key_name: Optional[str] = None
                    if node.args and isinstance(node.args[0], ast.Constant):
                        if isinstance(node.args[0].value, str):
                            key_name = node.args[0].value
                    line_no = getattr(node, "lineno", 1)
                    notable = bool(key_name and _is_notable_env_key(key_name))
                    symbol = key_name or "os.environ"
                    detail = (
                        f"Reads environment variable `{key_name}`"
                        if key_name
                        else f"Reads environment via `{call_name}()`"
                    )
                    findings.append(
                        CapabilityFinding(
                            rule_id=self.rule_id,
                            category=CapabilityCategory.ENV_READ,
                            file_path=file_path,
                            line_no=line_no,
                            col_offset=getattr(node, "col_offset", 0),
                            symbol=symbol,
                            detail=detail,
                            code_snippet=self.get_line_snippet(source_lines, line_no),
                            notable=notable,
                            sub_kind="env_key",
                        )
                    )

            # 2. os.environ["KEY"] subscript
            elif isinstance(node, ast.Subscript):
                val = node.value
                is_os_environ = False
                if isinstance(val, ast.Attribute) and val.attr == "environ":
                    if isinstance(val.value, ast.Name) and alias_map.get(
                        val.value.id, val.value.id
                    ) == "os":
                        is_os_environ = True
                elif isinstance(val, ast.Name) and alias_map.get(val.id) == "os.environ":
                    is_os_environ = True

                if is_os_environ:
                    key_name = None
                    if isinstance(node.slice, ast.Constant) and isinstance(
                        node.slice.value, str
                    ):
                        key_name = node.slice.value
                    line_no = getattr(node, "lineno", 1)
                    notable = bool(key_name and _is_notable_env_key(key_name))
                    symbol = key_name or "os.environ"
                    detail = (
                        f"Reads environment variable `{key_name}`"
                        if key_name
                        else "Subscripts `os.environ`"
                    )
                    findings.append(
                        CapabilityFinding(
                            rule_id=self.rule_id,
                            category=CapabilityCategory.ENV_READ,
                            file_path=file_path,
                            line_no=line_no,
                            col_offset=getattr(node, "col_offset", 0),
                            symbol=symbol,
                            detail=detail,
                            code_snippet=self.get_line_snippet(source_lines, line_no),
                            notable=notable,
                            sub_kind="env_key",
                        )
                    )

            # 3. Sensitive filesystem path string constants
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                text = node.value.strip()
                for marker in SENSITIVE_PATHS:
                    if marker in text:
                        line_no = getattr(node, "lineno", 1)
                        findings.append(
                            CapabilityFinding(
                                rule_id=self.rule_id,
                                category=CapabilityCategory.FILESYSTEM,
                                file_path=file_path,
                                line_no=line_no,
                                col_offset=getattr(node, "col_offset", 0),
                                symbol=marker,
                                detail=f"References sensitive path `{text}`",
                                code_snippet=self.get_line_snippet(
                                    source_lines, line_no
                                ),
                                notable=True,
                                sub_kind="sensitive_path",
                            )
                        )
                        break

        return findings
