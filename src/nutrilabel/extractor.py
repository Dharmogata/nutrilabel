"""Safe archive and directory extractor for Python packages without code execution."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import tarfile
import tempfile
from typing import Dict, List, Optional, Tuple
import urllib.request
import zipfile

NATIVE_EXTENSIONS = {".so", ".pyd", ".dll", ".dylib"}
IGNORED_DIRS = {"__pycache__", ".git", ".pytest_cache", ".ruff_cache", ".venv", "venv"}


@dataclass
class ExtractedPackage:
    """In-memory representation of a package's source files and metadata."""

    package_name: str
    version: str
    python_files: Dict[str, str] = field(default_factory=dict)
    native_binaries: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    total_files: int = 0
    total_lines: int = 0


def _parse_metadata_text(text: str) -> Tuple[Optional[str], Optional[str], List[str]]:
    name: Optional[str] = None
    version: Optional[str] = None
    deps: List[str] = []
    for raw_line in text.splitlines():
        if raw_line.startswith("Name:") and name is None:
            name = raw_line.split(":", 1)[1].strip()
        elif raw_line.startswith("Version:") and version is None:
            version = raw_line.split(":", 1)[1].strip()
        elif raw_line.startswith("Requires-Dist:"):
            spec = raw_line.split(":", 1)[1].strip()
            # Skip conditional extra-only dependencies
            if "extra ==" in spec:
                continue
            dep_name = re.split(r"[\s;<>=!~(\[]", spec, maxsplit=1)[0].strip()
            if dep_name and dep_name not in deps:
                deps.append(dep_name)
    return name, version, deps


def _parse_pyproject_text(text: str) -> Tuple[Optional[str], Optional[str], List[str]]:
    name_match = re.search(r'(?m)^\s*name\s*=\s*["\']([^"\']+)["\']', text)
    ver_match = re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']', text)
    name = name_match.group(1) if name_match else None
    version = ver_match.group(1) if ver_match else None

    deps: List[str] = []
    dep_block = re.search(r"(?ms)^\s*dependencies\s*=\s*\[(.*?)\]", text)
    if dep_block:
        for item in re.findall(r'["\']([^"\']+)["\']', dep_block.group(1)):
            dep_name = re.split(r"[\s;<>=!~(\[]", item.strip(), maxsplit=1)[0].strip()
            if dep_name and dep_name not in deps:
                deps.append(dep_name)
    return name, version, deps


def _parse_setup_py_ast(text: str) -> Tuple[Optional[str], Optional[str], List[str]]:
    name: Optional[str] = None
    version: Optional[str] = None
    deps: List[str] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None, None, []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = ""
            if isinstance(node.func, ast.Name):
                func_name = node.func.id
            elif isinstance(node.func, ast.Attribute):
                func_name = node.func.attr
            if func_name == "setup":
                for kw in node.keywords:
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                        name = str(kw.value.value)
                    elif kw.arg == "version" and isinstance(kw.value, ast.Constant):
                        version = str(kw.value.value)
                    elif kw.arg == "install_requires" and isinstance(
                        kw.value, (ast.List, ast.Tuple)
                    ):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(
                                elt.value, str
                            ):
                                dep_name = re.split(
                                    r"[\s;<>=!~(\[]", elt.value.strip(), maxsplit=1
                                )[0].strip()
                                if dep_name and dep_name not in deps:
                                    deps.append(dep_name)
    return name, version, deps


def extract_from_directory(
    directory: Path,
    fallback_name: Optional[str] = None,
    fallback_version: str = "0.0.0",
) -> ExtractedPackage:
    """Scan a directory of unpacked package files without executing any code."""
    root = directory.resolve()
    pkg_name: Optional[str] = None
    pkg_version: Optional[str] = None
    deps: List[str] = []
    python_files: Dict[str, str] = {}
    native_binaries: List[str] = []
    total_lines = 0

    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in IGNORED_DIRS for part in rel_parts):
            continue

        rel_posix = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()

        if any(
            rel_posix.endswith(ext) for ext in (".so", ".pyd", ".dll", ".dylib")
        ) or suffix in NATIVE_EXTENSIONS:
            native_binaries.append(rel_posix)
            continue

        if path.name in ("METADATA", "PKG-INFO"):
            text = path.read_text(encoding="utf-8", errors="replace")
            n, v, d = _parse_metadata_text(text)
            pkg_name = pkg_name or n
            pkg_version = pkg_version or v
            for dep in d:
                if dep not in deps:
                    deps.append(dep)
            continue

        if path.name == "pyproject.toml":
            text = path.read_text(encoding="utf-8", errors="replace")
            n, v, d = _parse_pyproject_text(text)
            pkg_name = pkg_name or n
            pkg_version = pkg_version or v
            for dep in d:
                if dep not in deps:
                    deps.append(dep)
            continue

        if suffix == ".py":
            text = path.read_text(encoding="utf-8", errors="replace")
            python_files[rel_posix] = text
            total_lines += len(text.splitlines())
            if path.name == "setup.py":
                n, v, d = _parse_setup_py_ast(text)
                pkg_name = pkg_name or n
                pkg_version = pkg_version or v
                for dep in d:
                    if dep not in deps:
                        deps.append(dep)

    final_name = pkg_name or fallback_name or root.name
    final_version = pkg_version or fallback_version

    return ExtractedPackage(
        package_name=final_name,
        version=final_version,
        python_files=python_files,
        native_binaries=native_binaries,
        dependencies=deps,
        total_files=len(python_files),
        total_lines=total_lines,
    )


def extract_from_archive(
    archive_path: Path,
    fallback_name: Optional[str] = None,
    fallback_version: str = "0.0.0",
) -> ExtractedPackage:
    """Safely unpack a .whl, .zip, or .tar.gz archive into a temp directory and inspect it."""
    name_guess = fallback_name
    ver_guess = fallback_version
    stem = archive_path.name
    for suffix in (".tar.gz", ".tgz", ".whl", ".zip"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    parts = stem.split("-")
    if len(parts) >= 2 and re.match(r"^\d", parts[1]):
        name_guess = name_guess or parts[0]
        ver_guess = parts[1]

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_root = Path(tmp_dir)
        lower_name = archive_path.name.lower()
        if lower_name.endswith((".whl", ".zip")):
            with zipfile.ZipFile(archive_path, "r") as zf:
                for member in zf.infolist():
                    target = (tmp_root / member.filename).resolve()
                    if tmp_root.resolve() in target.parents or target == tmp_root.resolve():
                        zf.extract(member, tmp_root)
        elif lower_name.endswith((".tar.gz", ".tgz", ".tar")):
            with tarfile.open(archive_path, "r:*") as tf:
                has_filter = hasattr(tarfile, "data_filter")
                for member in tf.getmembers():
                    target = (tmp_root / member.name).resolve()
                    if tmp_root.resolve() in target.parents or target == tmp_root.resolve():
                        if has_filter:
                            tf.extract(member, tmp_root, filter="data")
                        else:
                            tf.extract(member, tmp_root)
        else:
            raise ValueError(f"Unsupported archive format: {archive_path}")

        return extract_from_directory(
            tmp_root,
            fallback_name=name_guess,
            fallback_version=ver_guess,
        )


def fetch_and_extract_pypi(
    package_name: str,
    version: Optional[str] = None,
    timeout: int = 15,
) -> ExtractedPackage:
    """Download a package distribution from PyPI without installing it and extract its contents."""
    if version:
        api_url = f"https://pypi.org/pypi/{package_name}/{version}/json"
    else:
        api_url = f"https://pypi.org/pypi/{package_name}/json"

    req = urllib.request.Request(
        api_url,
        headers={"Accept": "application/json", "User-Agent": "nutrilabel/0.1.0"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))

    info = data.get("info", {})
    resolved_name = info.get("name", package_name)
    resolved_version = info.get("version", version or "0.0.0")
    urls = data.get("urls", [])
    if not urls:
        raise ValueError(f"No downloadable distributions found for {package_name}")

    # Prefer sdist (.tar.gz) so setup.py is included if present, else wheel (.whl)
    chosen_url: Optional[str] = None
    chosen_filename: str = "package.tar.gz"
    for entry in urls:
        if entry.get("packagetype") == "sdist":
            chosen_url = entry.get("url")
            chosen_filename = entry.get("filename", "package.tar.gz")
            break
    if not chosen_url:
        chosen_url = urls[0].get("url")
        chosen_filename = urls[0].get("filename", "package.whl")

    if not chosen_url:
        raise ValueError(f"Missing distribution URL for {package_name}")

    with tempfile.TemporaryDirectory() as tmp_dir:
        archive_file = Path(tmp_dir) / chosen_filename
        dl_req = urllib.request.Request(
            chosen_url,
            headers={"User-Agent": "nutrilabel/0.1.0"},
        )
        with urllib.request.urlopen(dl_req, timeout=timeout) as dl_resp:
            archive_file.write_bytes(dl_resp.read())

        extracted = extract_from_archive(
            archive_file,
            fallback_name=resolved_name,
            fallback_version=resolved_version,
        )
        # Supplement dependencies from PyPI JSON requires_dist if needed
        requires_dist = info.get("requires_dist") or []
        for req_str in requires_dist:
            if "extra ==" in req_str:
                continue
            dep_name = re.split(r"[\s;<>=!~(\[]", req_str.strip(), maxsplit=1)[0].strip()
            if dep_name and dep_name not in extracted.dependencies:
                extracted.dependencies.append(dep_name)
        return extracted


def load_package_target(
    target: str,
    version: Optional[str] = None,
) -> ExtractedPackage:
    """Resolve a target (directory path, archive path, or PyPI package name) into an ExtractedPackage."""
    path = Path(target)
    if path.exists():
        if path.is_dir():
            return extract_from_directory(
                path,
                fallback_name=path.name,
                fallback_version=version or "0.1.0",
            )
        if path.is_file():
            return extract_from_archive(
                path,
                fallback_version=version or "0.1.0",
            )
    return fetch_and_extract_pypi(target, version=version)
