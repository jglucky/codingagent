"""Tests for password / connection-string detection vs web-form false positives."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory


def _password_findings(findings):
    return [
        f
        for f in findings
        if f.policy == "hardcoded_passwords"
        or (f.rule_id or "").startswith("policy-1/")
    ]


def _scan(filename: str, source: str):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / filename).write_text(source, encoding="utf-8")
        findings, _, _, _, _ = scan_directory(root)
        return _password_findings(findings)


def _rule_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


class PasswordConnectionTruePositives(unittest.TestCase):
    def test_ado_net_connection_string(self) -> None:
        rules = _rule_ids(_scan(
            "app.py",
            'conn = "Server=db;Database=app;Password=SuperSecret99;User Id=sa;"\n',
        ))
        self.assertIn("policy-1/password-in-connection", rules)

    def test_pwd_connection_fragment(self) -> None:
        rules = _rule_ids(_scan(
            "app.py",
            'cs = "PWD=SuperSecret99;Server=localhost"\n',
        ))
        self.assertIn("policy-1/password-in-connection", rules)

    def test_jdbc_style_password(self) -> None:
        rules = _rule_ids(_scan(
            "app.py",
            'url = "jdbc:mysql://localhost/db?user=root&password=SuperSecret99"\n',
        ))
        self.assertIn("policy-1/password-in-connection", rules)

    def test_hardcoded_password_assignment(self) -> None:
        rules = _rule_ids(_scan("app.py", 'password = "SuperSecret99"\n'))
        self.assertIn("policy-1/password-assignment", rules)


class PasswordWebFormFalsePositives(unittest.TestCase):
    def test_selenium_java_find_element(self) -> None:
        findings = _scan(
            "LoginTest.java",
            "WebElement password = driver.findElement(By.id(\"pwd\"));\n"
            "driver.findElement(By.name(\"password\")).sendKeys(userPwd);\n"
            "driver.findElement(By.cssSelector(\"input[type=password]\"));\n",
        )
        self.assertEqual(findings, [])

    def test_selenium_python_find_element(self) -> None:
        findings = _scan(
            "test_login.py",
            "password = driver.find_element(By.ID, \"password\")\n"
            "driver.find_element(By.NAME, \"password\").send_keys(pwd)\n"
            "driver.find_element(By.CSS_SELECTOR, \"input[type=password]\")\n",
        )
        self.assertEqual(findings, [])

    def test_selenium_csharp_find_element(self) -> None:
        findings = _scan(
            "LoginTests.cs",
            "IWebElement password = driver.FindElement(By.Id(\"password\"));\n"
            "driver.FindElement(By.Name(\"password\")).SendKeys(userPwd);\n"
            "driver.FindElement(By.CssSelector(\"input[type=password]\"));\n",
        )
        self.assertEqual(findings, [])

    def test_by_locator_variable_named_password(self) -> None:
        findings = _scan(
            "Test.java",
            "By password = By.name(\"password\");\n",
        )
        self.assertEqual(findings, [])

    def test_angular_component_form_fields(self) -> None:
        """Form field binding in UI tests must not be reported as connection strings."""
        findings = _scan(
            "authentication.component.spec.js",
            "comp.password = comp.confirmPassword = 'myPassword';\n"
            "comp.password = 'myPassword';\n",
        )
        # Test files skip password rules; also pattern must not treat .password = as conn string.
        self.assertEqual(findings, [])

    def test_component_password_property_outside_tests(self) -> None:
        findings = _scan(
            "auth.component.js",
            "comp.password = comp.confirmPassword = userInput;\n"
            "this.password = this.confirmPassword;\n",
        )
        self.assertEqual(findings, [])

    def test_playwright_and_cypress_selectors(self) -> None:
        findings = _scan(
            "e2e.js",
            "await page.fill('input[name=password]', secret);\n"
            "cy.get('input[type=password]').type(password);\n"
            "document.querySelector('input[type=password]');\n",
        )
        self.assertEqual(findings, [])

    def test_html_password_input(self) -> None:
        findings = _scan(
            "login.html",
            '<input type="password" name="password" id="password" />\n'
            "<input type=password name=userpass />\n",
        )
        self.assertEqual(findings, [])

    def test_css_attribute_selectors(self) -> None:
        findings = _scan(
            "selectors.py",
            'sel = "input[password=hidden]"\n'
            's = "[pwd=adminlogin]"\n'
            'x = "//input[@Password=secretvalue]"\n',
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
