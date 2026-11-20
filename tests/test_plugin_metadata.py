#!/usr/bin/env python3
"""Validate the metadata KeePass uses to recognize and update this plugin."""

import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
ASSEMBLY_INFO = REPO_ROOT / "HaveIBeenPwned" / "Properties" / "AssemblyInfo.cs"
VERSION_FILE = REPO_ROOT / "VERSION"


def assembly_attribute(name):
    source = ASSEMBLY_INFO.read_text(encoding="utf-8-sig")
    match = re.search(rf'\[assembly:\s*{re.escape(name)}\("([^"]+)"\)\]', source)
    if match is None:
        raise AssertionError(f"Missing assembly attribute: {name}")
    return match.group(1)


def keepass_version(value):
    parts = value.split(".")
    while parts and parts[-1] == "0":
        parts.pop()
    return ".".join(parts)


class PluginMetadataTest(unittest.TestCase):
    def test_version_manifest_matches_keepass_plugin_metadata(self):
        title = assembly_attribute("AssemblyTitle")
        file_version = assembly_attribute("AssemblyFileVersion")
        assembly_version = assembly_attribute("AssemblyVersion")
        product = assembly_attribute("AssemblyProduct")

        self.assertEqual(product, "KeePass Plugin")
        self.assertNotIn("*", file_version)
        self.assertEqual(assembly_version, file_version)

        lines = VERSION_FILE.read_text(encoding="utf-8-sig").splitlines()
        self.assertGreaterEqual(len(lines), 3)
        separator = lines[0]
        self.assertEqual(len(separator), 1)
        self.assertEqual(lines[-1], separator)

        entries = [line.split(separator, 1) for line in lines[1:-1] if separator in line]
        matching = [version for name, version in entries if name == title]
        self.assertEqual(len(matching), 1)
        self.assertEqual(matching[0], keepass_version(file_version))


if __name__ == "__main__":
    unittest.main(verbosity=2)
