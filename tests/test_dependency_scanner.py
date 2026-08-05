"""Tests for NuGet/npm dependency (SCA) scanning — Snyk Open Source style CVEs."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory
from repo_scanner.dependency_scanner import (
    classify_vuln_type,
    parse_csproj_packages,
    parse_packages_lock_json,
    parse_package_lock_json,
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
            vuln_type="denial_of_service",
        )
        self.assertTrue(_is_affected("5.6.4", adv))
        self.assertTrue(_is_affected("5.8.3", adv))
        self.assertFalse(_is_affected("5.8.4", adv))
        self.assertFalse(_is_affected("7.0.0", adv))


class ClassifyTests(unittest.TestCase):
    def test_cwe_mapping(self) -> None:
        self.assertEqual(classify_vuln_type(["CWE-400"]), "denial_of_service")
        self.assertEqual(classify_vuln_type(["CWE-476"]), "null_pointer")
        self.assertEqual(classify_vuln_type(["CWE-89"]), "sql_injection")
        self.assertEqual(classify_vuln_type(["CWE-79"]), "xss")
        self.assertEqual(classify_vuln_type(["CWE-502"]), "deserialization")
        self.assertEqual(classify_vuln_type(["CWE-918"]), "ssrf")
        self.assertEqual(classify_vuln_type([]), "dependencies")

    def test_keyword_fallback(self) -> None:
        self.assertEqual(
            classify_vuln_type([], "A denial of service vulnerability exists"),
            "denial_of_service",
        )
        self.assertEqual(
            classify_vuln_type([], "NULL pointer dereference in parser"),
            "null_pointer",
        )


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


class LockfileParseTests(unittest.TestCase):
    def test_packages_lock_json(self) -> None:
        lock = {
            "version": 1,
            "dependencies": {
                "net6.0": {
                    "Microsoft.Data.OData": {
                        "type": "Direct",
                        "requested": "[5.6.4, )",
                        "resolved": "5.6.4",
                    }
                }
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "packages.lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            deps = parse_packages_lock_json(path, root)
            self.assertEqual(len(deps), 1)
            self.assertEqual(deps[0].name, "Microsoft.Data.OData")
            self.assertEqual(deps[0].version, "5.6.4")

    def test_package_lock_json_v2(self) -> None:
        lock = {
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.11"},
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "package-lock.json"
            path.write_text(json.dumps(lock), encoding="utf-8")
            deps = parse_package_lock_json(path, root)
            names = {d.name: d.version for d in deps}
            self.assertEqual(names.get("lodash"), "4.17.11")


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
            findings = scan_dependencies(
                root, use_osv=False, type_filter={"denial_of_service"},
            )
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
            findings = scan_dependencies(
                root, use_osv=False, type_filter={"denial_of_service"},
            )
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
            self.assertFalse(any(f.policy == "hardcoded_passwords" for f in findings))

    def test_pyyaml_deserialization_type_filter(self) -> None:
        req = "pyyaml==5.3.1\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text(req, encoding="utf-8")
            deser = scan_dependencies(
                root, use_osv=False, type_filter={"deserialization"},
            )
            self.assertTrue(any("CVE-2020-14343" in f.message for f in deser))
            self.assertTrue(all(f.category == "deserialization" for f in deser))
            # Should not appear under null_pointer filter
            null = scan_dependencies(
                root, use_osv=False, type_filter={"null_pointer"},
            )
            self.assertFalse(any("CVE-2020-14343" in f.message for f in null))

    def test_lockfile_preferred_for_scan(self) -> None:
        xml = """
        <Project Sdk="Microsoft.NET.Sdk">
          <ItemGroup>
            <PackageReference Include="Microsoft.Data.OData" Version="5.8.4" />
          </ItemGroup>
        </Project>
        """
        lock = {
            "dependencies": {
                "net6.0": {
                    "Microsoft.Data.OData": {"resolved": "5.6.4", "type": "Direct"}
                }
            }
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "App.csproj").write_text(xml, encoding="utf-8")
            (root / "packages.lock.json").write_text(json.dumps(lock), encoding="utf-8")
            findings = scan_dependencies(
                root, use_osv=False, type_filter={"denial_of_service"},
            )
            # Lockfile resolved 5.6.4 is vulnerable even if csproj says 5.8.4
            self.assertTrue(any("CVE-2018-8269" in f.message for f in findings))


if __name__ == "__main__":
    unittest.main()
