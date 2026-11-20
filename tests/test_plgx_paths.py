#!/usr/bin/env python3
"""KeePass 2.62 rejects PLGX entries that escape the project directory."""

import re
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path, PureWindowsPath

REPO_ROOT = Path(__file__).resolve().parents[1]
PROJECT_DIR = REPO_ROOT / "HaveIBeenPwned"
PROJECT_FILE = PROJECT_DIR / "HaveIBeenPwned.csproj"
PACKAGED_ITEMS = {
    "Compile",
    "EmbeddedResource",
    "None",
    "Content",
    "Resource",
    "Page",
    "ApplicationDefinition",
}


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def is_msbuild_expression(path):
    return any(token in path for token in ("$(", "@(", "%("))


def is_relative_to_project(path):
    normalized = path.replace("\\", "/")
    if PureWindowsPath(path).is_absolute() or re.match(r"^[A-Za-z]:", path):
        return False
    project_root = PROJECT_DIR.resolve()
    resolved = (PROJECT_DIR / normalized).resolve()
    return resolved == project_root or project_root in resolved.parents


class PlgxPathTest(unittest.TestCase):
    def test_packaged_paths_stay_inside_project_and_exist(self):
        root = ET.parse(PROJECT_FILE).getroot()
        for item in root.iter():
            item_type = local_name(item.tag)
            if item_type not in PACKAGED_ITEMS:
                continue
            include = item.get("Include") or item.get("Update")
            if not include or is_msbuild_expression(include):
                continue

            with self.subTest(item_type=item_type, include=include):
                self.assertTrue(
                    is_relative_to_project(include),
                    f"PLGX path escapes project root: {item_type} Include={include}",
                )
                file_path = PROJECT_DIR / include.replace("\\", "/")
                self.assertTrue(file_path.is_file(), f"Missing PLGX input: {include}")

    def test_local_reference_hint_paths_stay_inside_project(self):
        root = ET.parse(PROJECT_FILE).getroot()
        for reference in root.iter():
            if local_name(reference.tag) != "Reference":
                continue
            for child in reference:
                if local_name(child.tag) != "HintPath":
                    continue
                hint_path = (child.text or "").strip()
                if not hint_path or is_msbuild_expression(hint_path):
                    continue
                if PureWindowsPath(hint_path).is_absolute() or re.match(r"^[A-Za-z]:", hint_path):
                    continue

                with self.subTest(reference=reference.get("Include"), hint_path=hint_path):
                    self.assertTrue(
                        is_relative_to_project(hint_path),
                        f"Local assembly HintPath escapes project root: {hint_path}",
                    )
                    file_path = PROJECT_DIR / hint_path.replace("\\", "/")
                    self.assertTrue(file_path.is_file(), f"Missing local assembly: {hint_path}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
