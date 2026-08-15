"""
tests/dependency/test_dockerfile_parser.py

Unit tests for DockerfileParser.
"""

import os
from app.parsers.dockerfile_parser import DockerfileParser
from app.models.manifest import ManifestInfo


def test_parse_dockerfile():
    fixtures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_fixtures"))
    dockerfile_path = os.path.join(fixtures_dir, "Dockerfile")

    manifest = ManifestInfo(
        path="Dockerfile",
        absolute_path=dockerfile_path,
        manifest_type="Dockerfile",
        ecosystem="mixed",
    )

    parser = DockerfileParser()
    deps = parser.parse(manifest)
    dep_map = {f"{d.ecosystem}:{d.name}": d for d in deps}

    # apt: curl, git
    assert "apt:curl" in dep_map
    assert "apt:git" in dep_map
    assert dep_map["apt:git"].version == "1:2.34.1"

    # pip: requests, flask
    assert "PyPI:requests" in dep_map
    assert dep_map["PyPI:requests"].version == "2.31.0"
    assert "PyPI:flask" in dep_map

    # npm: pnpm
    assert "npm:pnpm" in dep_map
    assert dep_map["npm:pnpm"].version == "8.6.0"


def test_dockerfile_no_packages(tmp_path):
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("""
    FROM alpine:latest
    CMD ["echo", "hello"]
    """, encoding="utf-8")

    manifest = ManifestInfo(
        path="Dockerfile",
        absolute_path=str(dockerfile),
        manifest_type="Dockerfile",
        ecosystem="mixed",
    )

    parser = DockerfileParser()
    deps = parser.parse(manifest)
    assert deps == []
