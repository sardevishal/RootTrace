"""
tests/dependency/test_manifest_detector.py

Unit tests for ManifestDetector and RepositoryScanner.
"""

import os
import pytest
from app.services.dependency.manifest_detector import ManifestDetector
from app.services.dependency.repository_scanner import RepositoryScanner


def test_repository_scanner_and_manifest_detector():
    fixtures_dir = os.path.join(os.path.dirname(__file__), "..", "test_fixtures")
    fixtures_dir = os.path.abspath(fixtures_dir)

    scanner = RepositoryScanner()
    files = scanner.scan(fixtures_dir)

    assert len(files) >= 6

    detector = ManifestDetector()
    manifests = detector.detect(files, fixtures_dir)

    # We expect:
    # 1. package.json (root)
    # 2. requirements.txt
    # 3. pom.xml
    # 4. go.mod
    # 5. Dockerfile
    # 6. frontend/package.json
    manifest_paths = [m.path for m in manifests]
    assert "package.json" in manifest_paths
    assert "requirements.txt" in manifest_paths
    assert "pom.xml" in manifest_paths
    assert "go.mod" in manifest_paths
    assert "Dockerfile" in manifest_paths
    assert "frontend/package.json" in manifest_paths

    root_pkg = next(m for m in manifests if m.path == "package.json")
    assert root_pkg.has_lockfile is True
    assert root_pkg.lockfile_path == "package-lock.json"


def test_empty_repository(tmp_path):
    scanner = RepositoryScanner()
    files = scanner.scan(str(tmp_path))
    assert files == []

    detector = ManifestDetector()
    manifests = detector.detect(files, str(tmp_path))
    assert manifests == []


def test_invalid_path():
    scanner = RepositoryScanner()
    with pytest.raises(FileNotFoundError):
        scanner.scan("non_existent_dir_123456")
