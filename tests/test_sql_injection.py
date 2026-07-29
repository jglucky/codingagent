"""Tests for SQL injection detection accuracy (true positives and false positives)."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from repo_scanner.analyzer import scan_directory


def _sql_rule_ids(findings) -> set[str]:
    return {
        f.rule_id
        for f in findings
        if f.rule_id.startswith("injection/sql") or f.rule_id.startswith("injection/csharp-sql")
    }


def _scan_source(filename: str, source: str) -> set[str]:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / filename).write_text(source, encoding="utf-8")
        findings, _, _, _, _ = scan_directory(root)
        return _sql_rule_ids(findings)


class SqlInjectionTruePositives(unittest.TestCase):
    def test_python_fstring_sql(self) -> None:
        rules = _scan_source(
            "app.py",
            'query = f"SELECT * FROM users WHERE name = \'{user_input}\'"\n',
        )
        self.assertTrue(rules, "expected SQL injection finding for f-string SQL")

    def test_python_execute_concat(self) -> None:
        rules = _scan_source(
            "app.py",
            'db.execute("SELECT * FROM users WHERE id = " + user_id)\n',
        )
        self.assertIn("injection/sql-concat", rules)

    def test_python_percent_format(self) -> None:
        rules = _scan_source(
            "app.py",
            'cursor.execute("SELECT * FROM t WHERE a = %s" % value)\n',
        )
        self.assertTrue(rules)

    def test_python_str_format(self) -> None:
        rules = _scan_source(
            "app.py",
            'sql = "SELECT * FROM users WHERE id = {}".format(user_id)\n',
        )
        self.assertIn("injection/sql-format", rules)

    def test_csharp_string_concat(self) -> None:
        rules = _scan_source(
            "Controller.cs",
            'var sql = "SELECT * FROM users WHERE id = " + userId;\n'
            'new SqlCommand(sql, conn);\n',
        )
        self.assertTrue(rules)

    def test_csharp_sqlcommand_inline_concat(self) -> None:
        rules = _scan_source(
            "Controller.cs",
            'new SqlCommand("SELECT * FROM users WHERE id = " + userId, conn);\n',
        )
        self.assertTrue(
            "injection/csharp-sql-concat" in rules or "injection/sql-format" in rules
        )

    def test_csharp_string_format(self) -> None:
        rules = _scan_source(
            "Controller.cs",
            'cmd.CommandText = string.Format("SELECT * FROM users WHERE id = {0}", id);\n',
        )
        self.assertIn("injection/sql-format", rules)

    def test_multi_column_select(self) -> None:
        rules = _scan_source(
            "app.py",
            'sql = "SELECT id, name, email FROM users WHERE id = " + user_id\n',
        )
        self.assertTrue(rules)


class SqlInjectionFalsePositives(unittest.TestCase):
    def test_parameterized_execute_percent(self) -> None:
        rules = _scan_source(
            "app.py",
            'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n',
        )
        self.assertEqual(rules, set())

    def test_parameterized_execute_qmark(self) -> None:
        rules = _scan_source(
            "app.py",
            'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))\n',
        )
        self.assertEqual(rules, set())

    def test_parameterized_execute_dollar(self) -> None:
        rules = _scan_source(
            "app.py",
            'db.execute("SELECT * FROM users WHERE id = $1", [id])\n',
        )
        self.assertEqual(rules, set())

    def test_static_raw_sql(self) -> None:
        rules = _scan_source(
            "app.py",
            'Model.objects.raw("SELECT * FROM myapp_person")\n'
            'raw("SELECT 1")\n'
            'query("SELECT * FROM users")\n',
        )
        self.assertEqual(rules, set())

    def test_sqlalchemy_orm_query(self) -> None:
        rules = _scan_source(
            "app.py",
            "session.query(User).filter(User.id == id)\n"
            "db.query(models.Item).all()\n"
            "session.execute(select(User).where(User.id == user_id))\n",
        )
        self.assertEqual(rules, set())

    def test_literal_string_concat(self) -> None:
        rules = _scan_source(
            "app.py",
            'sql = "SELECT * FROM users " + "WHERE active = 1"\n'
            'x = "SELECT * FROM t WHERE a = " + "1"\n',
        )
        self.assertEqual(rules, set())

    def test_graphql_and_dom_query(self) -> None:
        rules = _scan_source(
            "app.js",
            'graphql.query("{ users { id } }")\n'
            "client.query({ query: GET_USERS })\n"
            'document.querySelector(".item")\n',
        )
        self.assertEqual(rules, set())

    def test_english_text_not_sql(self) -> None:
        rules = _scan_source(
            "app.py",
            'message = "Please SELECT your option" + name\n'
            'logger.debug(f"DELETE completed for {count} rows")\n'
            'print("SELECT count was %s" % n)\n',
        )
        self.assertEqual(rules, set())

    def test_ef_core_safe_apis(self) -> None:
        rules = _scan_source(
            "Data.cs",
            'context.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Id = {id}");\n'
            'context.Users.FromSqlRaw("SELECT * FROM Users WHERE Id = {0}", id);\n'
            'var cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn);\n',
        )
        self.assertEqual(rules, set())

    def test_sqlalchemy_text_bound_params(self) -> None:
        rules = _scan_source(
            "app.py",
            'conn.execute(text("SELECT * FROM users WHERE id = :id"), {"id": user_id})\n',
        )
        self.assertEqual(rules, set())


if __name__ == "__main__":
    unittest.main()
