"""Unit test suite for NutriLabel package capability inspector and version differ."""

from __future__ import annotations

import io
import json
from pathlib import Path
import tarfile
import tempfile
import textwrap
import unittest
from unittest.mock import patch
import zipfile

from nutrilabel.analyzer import NutritionAnalyzer, diff_reports
from nutrilabel.cli import main
from nutrilabel.extractor import extract_from_archive, extract_from_directory
from nutrilabel.formatters import format_diff_report, format_nutrition_label
from nutrilabel.models import CapabilityCategory


class TestASTCapabilityDetectors(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.analyzer = NutritionAnalyzer()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_detects_network_process_env_and_sensitive_paths(self) -> None:
        pkg_dir = self.root / "requests_toolkit"
        pkg_dir.mkdir()
        (pkg_dir / "pyproject.toml").write_text(
            textwrap.dedent(
                """\
                [project]
                name = "requests-toolkit"
                version = "2.1.0"
                dependencies = ["requests>=2.31.0", "urllib3"]
                """
            ),
            encoding="utf-8",
        )
        (pkg_dir / "setup.py").write_text(
            textwrap.dedent(
                """\
                from setuptools import setup
                setup(name="requests-toolkit", version="2.1.0", cmdclass={"install": object})
                """
            ),
            encoding="utf-8",
        )
        (pkg_dir / "client.py").write_text(
            textwrap.dedent(
                """\
                import os
                import subprocess
                import urllib.request

                ENDPOINT = "https://telemetry.internal-collector.io/v1/events"

                def sync_data():
                    aws_key = os.getenv("AWS_SECRET_ACCESS_KEY")
                    ssh_path = "~/.ssh/id_rsa"
                    subprocess.run(["git", "status"], check=False)
                    urllib.request.urlopen(ENDPOINT)
                    return aws_key, ssh_path
                """
            ),
            encoding="utf-8",
        )

        report = self.analyzer.analyze_target(str(pkg_dir))
        self.assertEqual(report.package_name, "requests-toolkit")
        self.assertEqual(report.version, "2.1.0")
        self.assertEqual(len(report.dependencies), 2)

        net = report.findings_by_category(CapabilityCategory.NETWORK)
        proc = report.findings_by_category(CapabilityCategory.PROCESS)
        env = report.findings_by_category(CapabilityCategory.ENV_READ)
        fs = report.findings_by_category(CapabilityCategory.FILESYSTEM)
        hooks = report.findings_by_category(CapabilityCategory.INSTALL_HOOK)

        self.assertEqual(len(net), 2)  # urlopen + hardcoded URL
        self.assertEqual(len(proc), 1)
        self.assertEqual(len(env), 1)
        self.assertEqual(env[0].symbol, "AWS_SECRET_ACCESS_KEY")
        self.assertTrue(env[0].notable)
        self.assertEqual(len(fs), 1)
        self.assertIn("~/.ssh", fs[0].symbol)
        self.assertGreaterEqual(len(hooks), 1)
        self.assertIn(report.grade, ("C", "D"))

        label_text = format_nutrition_label(report, explain=True)
        self.assertIn("Package Nutrition Facts", label_text)
        self.assertIn("requests-toolkit 2.1.0", label_text)
        self.assertIn("Hardcoded Endpoints", label_text)
        self.assertIn("AWS_SECRET_ACCESS_KEY", label_text)
        self.assertIn("~/.ssh", label_text)

    def test_detects_obfuscated_base64_exec_and_native_binary(self) -> None:
        pkg_dir = self.root / "suspect_pkg"
        pkg_dir.mkdir()
        (pkg_dir / "loader.py").write_text(
            textwrap.dedent(
                """\
                import base64
                payload = base64.b64decode("cHJpbnQoMSk=")
                exec(payload)
                """
            ),
            encoding="utf-8",
        )
        (pkg_dir / "_accel.pyd").write_bytes(b"\x00\x01\x02")

        extracted = extract_from_directory(pkg_dir, fallback_name="suspect-pkg")
        report = self.analyzer.analyze_extracted(extracted)
        obf = report.findings_by_category(CapabilityCategory.OBFUSCATION)
        bins = report.findings_by_category(CapabilityCategory.NATIVE_BINARY)
        self.assertEqual(len(obf), 1)
        self.assertEqual(obf[0].sub_kind, "encoded_exec")
        self.assertEqual(len(bins), 1)
        self.assertEqual(report.grade, "D")


class TestArchiveExtractionAndVersionDiff(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.analyzer = NutritionAnalyzer()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_extract_wheel_and_targz_archives(self) -> None:
        whl_path = self.root / "demo_pkg-1.0.0-py3-none-any.whl"
        with zipfile.ZipFile(whl_path, "w") as zf:
            zf.writestr(
                "demo_pkg-1.0.0.dist-info/METADATA",
                "Name: demo-pkg\nVersion: 1.0.0\nRequires-Dist: click (>=8.0)\n",
            )
            zf.writestr("demo_pkg/__init__.py", "x = 1\n")

        extracted_whl = extract_from_archive(whl_path)
        self.assertEqual(extracted_whl.package_name, "demo-pkg")
        self.assertEqual(extracted_whl.version, "1.0.0")
        self.assertEqual(extracted_whl.dependencies, ["click"])

        tgz_path = self.root / "demo_pkg-1.1.0.tar.gz"
        src_file = self.root / "mod.py"
        src_file.write_text("import os\nos.system('ls')\n", encoding="utf-8")
        with tarfile.open(tgz_path, "w:gz") as tf:
            tf.add(src_file, arcname="demo_pkg-1.1.0/mod.py")

        extracted_tgz = extract_from_archive(tgz_path)
        self.assertEqual(extracted_tgz.version, "1.1.0")
        self.assertEqual(extracted_tgz.total_files, 1)

    def test_version_diff_highlights_new_capabilities(self) -> None:
        v1_dir = self.root / "pkg_v1"
        v1_dir.mkdir()
        (v1_dir / "pyproject.toml").write_text(
            'name = "math-helper"\nversion = "2.0.0"\ndependencies = []\n',
            encoding="utf-8",
        )
        (v1_dir / "core.py").write_text(
            "def add(a, b):\n    return a + b\n",
            encoding="utf-8",
        )

        v2_dir = self.root / "pkg_v2"
        v2_dir.mkdir()
        (v2_dir / "pyproject.toml").write_text(
            'name = "math-helper"\nversion = "2.1.0"\ndependencies = ["requests"]\n',
            encoding="utf-8",
        )
        (v2_dir / "core.py").write_text(
            textwrap.dedent(
                """\
                import requests
                import subprocess

                def add(a, b):
                    requests.post("https://collector.bad-domain.org/ping")
                    subprocess.Popen(["whoami"])
                    return a + b
                """
            ),
            encoding="utf-8",
        )

        r1 = self.analyzer.analyze_target(str(v1_dir))
        r2 = self.analyzer.analyze_target(str(v2_dir))
        diff = diff_reports(r1, r2)

        self.assertEqual(diff.old_grade, "A")
        self.assertIn(diff.new_grade, ("B", "C"))
        self.assertEqual(diff.added_dependencies, ["requests"])

        by_cat = {d.category: d for d in diff.capability_diffs}
        self.assertEqual(by_cat[CapabilityCategory.NETWORK].status, "added_capability")
        self.assertEqual(by_cat[CapabilityCategory.PROCESS].status, "added_capability")

        diff_text = format_diff_report(diff, output_format="text")
        self.assertIn("NEW CAPABILITY", diff_text)
        self.assertIn("requests", diff_text)

    def test_cli_shorthand_inspect_diff_and_rules(self) -> None:
        pkg_v1 = self.root / "v1"
        pkg_v1.mkdir()
        (pkg_v1 / "mod.py").write_text("a = 1\n", encoding="utf-8")

        pkg_v2 = self.root / "v2"
        pkg_v2.mkdir()
        (pkg_v2 / "mod.py").write_text(
            "import socket\ns = socket.socket()\n", encoding="utf-8"
        )

        # Shorthand: nutrilabel <path> --format json
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            rc = main([str(pkg_v2), "--format", "json"])
            self.assertEqual(rc, 0)
            data = json.loads(mock_out.getvalue())
            self.assertEqual(len(data["findings"]), 1)

        # Diff command: nutrilabel diff <v1> <v2> --format markdown
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            rc = main(["diff", str(pkg_v1), str(pkg_v2), "--format", "markdown"])
            self.assertEqual(rc, 0)
            self.assertIn("# Package Capability Diff", mock_out.getvalue())

        # Rules catalog command: nutrilabel rules
        with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
            rc = main(["rules"])
            self.assertEqual(rc, 0)
            self.assertIn("NL001", mock_out.getvalue())
            self.assertIn("NL004", mock_out.getvalue())


if __name__ == "__main__":
    unittest.main()
