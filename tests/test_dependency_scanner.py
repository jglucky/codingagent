"""Tests for NuGet/npm dependency (SCA) scanning — Snyk Open Source style CVEs."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory
from repo_scanner.dependency_scanner import (
    collect_dependencies,
    parse_csproj_packages,
    scan_dependencies,
    _is_affected,
    Advisory,
)


class VersionRangeTests(unittest.TestCase):
    def test_odata_version_affected(self) -> None:
        adv = Advisory(
            ecosystem="NuGet",
            package="Microsoft.Data.OData",
            cve="CVE-2018-8269",
            severity="high",
            title="t",
            summary="s",
            cwe=("CWE-400",),
            remediation="r",
            version_max_exclusive="5.8.4",
            is_dos=True,
        )
        self.assertTrue(_is_affected("5.6.4", adv))
        self.assertTrue(_is_affected("5.8.3", adv))
        self.assertFalse(_is_affected("5.8.4", adv))
        self.assertFalse(_is_affected("7.0.0", adv))


class CsprojParseTests(unittest.TestCase):
    def test_package_reference(self) -> None:
        xml = """
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="Microsoft.Data.OData" Version="5.6.4" />
            <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
          </ItemGroup>
        </Project>
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "App.csproj"
            path.write_text(xml, encoding="utf-8")
            deps = parse_csproj_packages(path, root)
            names = {d.name: d.version for d in deps}
            self.assertEqual(names["Microsoft.Data.OData"], "5.6.4")
            self.assertEqual(names["Newtonsoft.Json"], "13.0.1")


class DependencyScanTests(unittest.TestCase):
    def test_builtin_cve_2018_8269(self) -> None:
        xml = """
        <Project Sdk="Microsoft.NET.Sdk.Web">
          <ItemGroup>
            <PackageReference Include="Microsoft.Data.OData" Version="5.6.4" />
          </ItemGroup>
        </Project>
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "WebApp.csproj").write_text(xml, encoding="utf-8")
            findings = scan_dependencies(root, use_osv=False, only_dos=True)
            self.assertTrue(findings, "expected CVE-2018-8269 finding")
            cves = " ".join(f.message for f in findings)
            self.assertIn("CVE-2018-8269", cves)
            self.assertTrue(any(f.category == "denial_of_service" for f in findings))
            self.assertTrue(any("WebApp.csproj" in f.file_path for f in findings))

    def test_fixed_version_not_flagged(self) -> None:
        xml = """
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="Microsoft.Data.OData" Version="5.8.4" />
          </ItemGroup>
        </Project>
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "App.csproj").write_text(xml, encoding="utf-8")
            findings = scan_dependencies(root, use_osv=False, only_dos=True)
            self.assertFalse(any("CVE-2018-8269" in f.message for f in findings))

    def test_only_dos_scan_includes_csproj_cve(self) -> None:
        xml = """
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="Microsoft.Data.OData" Version="5.7.0" />
          </ItemGroup>
        </Project>
        """
        src = 'password = "SuperSecret99!"\n'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "App.csproj").write_text(xml, encoding="utf-8")
            (root / "app.py").write_text(src, encoding="utf-8")
            findings, _, _, _, _ = scan_directory(
                root, only_types=["dos"], use_osv=False,
            )
            messages = " ".join(f.message for f in findings)
            self.assertIn("CVE-2018-8269", messages)
            # secrets should not appear in dos-only scan
            self.assertFalse(any(f.policy == "hardcoded_passwords" for f in findings))


if __name__ == "__main__":
    unittest.main()
