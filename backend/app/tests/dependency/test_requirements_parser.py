"""
tests/dependency/test_requirements_parser.py

Unit tests for RequirementsParser.
"""

import os
import pytest
from app.parsers.requirements_parser import RequirementsParser
from app.models.manifest import ManifestInfo


def test_parse_requirements_txt():
    fixtures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_fixtures"))
    req_path = os.path.join(fixtures_dir, "requirements.txt")

    manifest = ManifestInfo(
        path="requirements.txt",
        absolute_path=req_path,
        manifest_type="requirements.txt",
        ecosystem="PyPI",
    )

    parser = RequirementsParser()
    deps = parser.parse(manifest)

    dep_map = {d.name: d for d in deps}

    # requests==2.31.0
    assert "requests" in dep_map
    assert dep_map["requests"].version == "2.31.0"
    assert dep_map["requests"].version_spec == "==2.31.0"

    # flask>=2.0.0
    assert "flask" in dep_map
    assert dep_map["flask"].version is None
    assert dep_map["flask"].version_spec == ">=2.0.0"

    # django~=4.2.0
    assert "django" in dep_map
    assert dep_map["django"].version is None
    assert dep_map["django"].version_spec == "~=4.2.0"

    # celery[redis]==5.3.1
    assert "celery" in dep_map
    assert dep_map["celery"].version == "5.3.1"
    assert "redis" in dep_map["celery"].metadata["extras"]

    # pytest (no version)
    assert "pytest" in dep_map
    assert dep_map["pytest"].version is None
    assert dep_map["pytest"].version_spec is None


def test_requirements_with_comments_and_blank_lines(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("""
    # Main packages
    black==23.3.0  # code formatter
    
    # Utilities
    click>=8.0.0
    -r other-requirements.txt
    git+https://github.com/psf/requests.git
    """, encoding="utf-8")

    manifest = ManifestInfo(
        path="requirements.txt",
        absolute_path=str(req_file),
        manifest_type="requirements.txt",
        ecosystem="PyPI",
    )

    parser = RequirementsParser()
    deps = parser.parse(manifest)
    names = [d.name for d in deps]

    assert "black" in names
    assert "click" in names
    assert len(deps) == 2
