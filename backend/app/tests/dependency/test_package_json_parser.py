"""
tests/dependency/test_package_json_parser.py

Unit tests for PackageJsonParser.
"""

import os
import pytest
from app.parsers.package_json_parser import PackageJsonParser
from app.models.manifest import ManifestInfo


def test_parse_package_json_with_lockfile():
    fixtures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_fixtures"))
    pkg_json_path = os.path.join(fixtures_dir, "package.json")
    lock_path = os.path.join(fixtures_dir, "package-lock.json")

    manifest = ManifestInfo(
        path="package.json",
        absolute_path=pkg_json_path,
        manifest_type="package.json",
        ecosystem="npm",
        has_lockfile=True,
        lockfile_path="package-lock.json",
        lockfile_absolute_path=lock_path,
    )

    parser = PackageJsonParser()
    deps = parser.parse(manifest)

    # In package.json:
    # dependencies: express (^4.18.2), lodash (^4.17.21) -> locked to 4.18.2 and 4.17.21
    # devDependencies: jest, eslint
    # optionalDependencies: fsevents
    # peerDependencies: react
    dep_map = {d.name: d for d in deps}

    assert "express" in dep_map
    assert dep_map["express"].version == "4.18.2"
    assert dep_map["express"].version_spec == "^4.18.2"
    assert dep_map["express"].dependency_type == "runtime"

    assert "lodash" in dep_map
    assert dep_map["lodash"].version == "4.17.21"
    assert dep_map["lodash"].dependency_type == "runtime"

    assert "jest" in dep_map
    assert dep_map["jest"].dependency_type == "development"
    assert dep_map["jest"].version_spec == "^29.5.0"

    assert "fsevents" in dep_map
    assert dep_map["fsevents"].dependency_type == "optional"

    assert "react" in dep_map
    assert dep_map["react"].dependency_type == "peer"


def test_malformed_package_json(tmp_path):
    bad_file = tmp_path / "package.json"
    bad_file.write_text("{ broken json", encoding="utf-8")

    manifest = ManifestInfo(
        path="package.json",
        absolute_path=str(bad_file),
        manifest_type="package.json",
        ecosystem="npm",
    )

    parser = PackageJsonParser()
    with pytest.raises(ValueError, match="Invalid JSON"):
        parser.parse(manifest)
