"""
APEXEYE — Architecture Separation Test

Confirms that Client code does NOT directly import or access
the Master's SQLite database module.
"""

import ast
import os
import sys
import unittest
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)


class TestArchitectureSeparation(unittest.TestCase):
    """
    Statically verify that no file under client/ or client_linux/
    imports from master.app.database or uses sqlite3 directly.
    """

    def _get_client_py_files(self):
        client_dir = Path(_project_root) / "client"
        client_linux_dir = Path(_project_root) / "client_linux"
        files = list(client_dir.rglob("*.py"))
        if client_linux_dir.exists():
            files.extend(list(client_linux_dir.rglob("*.py")))
        return files

    def test_client_does_not_import_master_database(self):
        """Client code (Windows & Linux) must not import master.app.database."""
        violations = []
        for py_file in self._get_client_py_files():
            source = py_file.read_text(encoding="utf-8")
            if "master.app.database" in source or "from master" in source:
                violations.append(str(py_file))
        self.assertEqual(
            violations, [],
            f"Client files illegally import Master code: {violations}",
        )

    def test_client_does_not_import_sqlite3(self):
        """Client code must not use sqlite3 directly."""
        violations = []
        for py_file in self._get_client_py_files():
            source = py_file.read_text(encoding="utf-8")
            try:
                tree = ast.parse(source)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name == "sqlite3":
                            violations.append(str(py_file))
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.module.startswith("sqlite3"):
                        violations.append(str(py_file))
        self.assertEqual(
            violations, [],
            f"Client files illegally import sqlite3: {violations}",
        )


if __name__ == "__main__":
    unittest.main()
