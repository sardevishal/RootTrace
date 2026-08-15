"""
tests/dependency/test_go_mod_parser.py

Unit tests for GoModParser.
"""

import os
from app.parsers.go_mod_parser import GoModParser
from app.models.manifest import ManifestInfo


def test_parse_go_mod():
    fixtures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_fixtures"))
    gomod_path = os.path.join(fixtures_dir, "go.mod")

    manifest = ManifestInfo(
        path="go.mod",
        absolute_path=gomod_path,
        manifest_type="go.mod",
        ecosystem="Go",
    )

    parser = GoModParser()
    deps = parser.parse(manifest)
    dep_map = {d.name: d for d in deps}

    # Own module "github.com/roottrace/sample-service" should NOT be in dependencies
    assert "github.com/roottrace/sample-service" not in dep_map

    # github.com/gin-gonic/gin v1.9.1
    assert "github.com/gin-gonic/gin" in dep_map
    gin = dep_map["github.com/gin-gonic/gin"]
    assert gin.version == "v1.9.1"
    assert gin.go_indirect is False
    assert gin.dependency_type == "runtime"

    # github.com/stretchr/testify v1.8.4 // indirect
    assert "github.com/stretchr/testify" in dep_map
    testify = dep_map["github.com/stretchr/testify"]
    assert testify.version == "v1.8.4"
    assert testify.go_indirect is True
    assert testify.dependency_type == "indirect"

    # Single-line require: github.com/mattn/go-isatty v0.0.19
    assert "github.com/mattn/go-isatty" in dep_map
    isatty = dep_map["github.com/mattn/go-isatty"]
    assert isatty.version == "v0.0.19"
    assert isatty.go_indirect is False
