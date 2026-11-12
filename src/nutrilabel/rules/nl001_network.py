"""NL001: Network capability and hardcoded endpoint detector."""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Set

from nutrilabel.models import CapabilityCategory, CapabilityFinding
from nutrilabel.rules.base import BaseCapabilityRule, resolve_call_name

NETWORK_MODULES: Set[str] = {
    "socket",
    "urllib.request",
    "urllib3",
    "http.client",
    "requests",
    "httpx",
    "aiohttp",
    "ftplib",
    "smtplib",
    "websocket",
    "websockets",
}

NETWORK_CALL_PREFIXES = (
    "socket.socket",
    "socket.create_connection",
    "socket.getaddrinfo",
    "urllib.request.urlopen",
    "urllib.request.urlretrieve",
    "urllib.request.Request",
    "urllib3.PoolManager",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.request",
    "requests.Session",
    "httpx.get",
    "httpx.post",
    "httpx.Client",
    "httpx.AsyncClient",
    "aiohttp.ClientSession",
    "ftplib.FTP",
    "smtplib.SMTP",
)

URL_PATTERN = re.compile(r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)
SAFE_DOC_DOMAINS = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "example.com",
    "schemas.openxmlformats.org",
    "www.w3.org",
)


class NetworkCapabilityRule(BaseCapabilityRule):
    """Detects network client calls and hardcoded remote URLs or IP addresses."""

    rule_id = "NL001"
    name = "network-access"
    category = CapabilityCategory.NETWORK
    description = (
        "Detects outbound network calls (socket, urllib, requests, httpx, aiohttp) "
        "and hardcoded external URLs/IP endpoints."
    )

    def analyze_ast(
        self,
        tree: ast.AST,
        file_path: str,
        source_lines: List[str],
        alias_map: Dict[str, str],
    ) -> List[CapabilityFinding]:
        findings: List[CapabilityFinding] = []
        seen_lines: Set[int] = set()

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = resolve_call_name(node, alias_map)
                if any(
                    call_name == prefix or call_name.startswith(prefix + ".")
                    for prefix in NETWORK_CALL_PREFIXES
                ):
                    line_no = getattr(node, "lineno", 1)
                    seen_lines.add(line_no)
                    findings.append(
                        CapabilityFinding(
                            rule_id=self.rule_id,
                            category=self.category,
                            file_path=file_path,
                            line_no=line_no,
                            col_offset=getattr(node, "col_offset", 0),
                            symbol=call_name,
                            detail=f"Network API call `{call_name}()`",
                            code_snippet=self.get_line_snippet(source_lines, line_no),
                            notable=False,
                            sub_kind="api_call",
                        )
                    )

            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value.strip()
                if len(val) > 8 and (URL_PATTERN.match(val) or IPV4_PATTERN.match(val)):
                    if any(safe in val.lower() for safe in SAFE_DOC_DOMAINS):
                        continue
                    line_no = getattr(node, "lineno", 1)
                    # Skip module/class/function docstrings
                    snippet = self.get_line_snippet(source_lines, line_no)
                    if snippet.startswith(('"""', "'''", "#")):
                        continue
                    findings.append(
                        CapabilityFinding(
                            rule_id=self.rule_id,
                            category=self.category,
                            file_path=file_path,
                            line_no=line_no,
                            col_offset=getattr(node, "col_offset", 0),
                            symbol=val,
                            detail=f"Hardcoded endpoint `{val}`",
                            code_snippet=snippet,
                            notable=True,
                            sub_kind="hardcoded_url",
                        )
                    )

        return findings
