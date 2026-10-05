"""
tests/dependency/test_transitive_analyzer.py

Unit tests for TransitiveAnalyzer.
"""

from app.models.dependency import Dependency
from app.services.dependency.transitive_analyzer import TransitiveAnalyzer


def test_transitive_analyzer():
    analyzer = TransitiveAnalyzer()

    deps = [
        Dependency(
            id="Go:github.com/gin-gonic/gin@v1.9.1",
            name="github.com/gin-gonic/gin",
            ecosystem="Go",
            source_manifest="go.mod",
            source_path="go.mod",
            dependency_type="runtime",
            direct=True,
            parent_ids=[],
        ),
        Dependency(
            id="Go:github.com/stretchr/testify@v1.8.4",
            name="github.com/stretchr/testify",
            ecosystem="Go",
            source_manifest="go.mod",
            source_path="go.mod",
            dependency_type="indirect",
            direct=False,
            parent_ids=["Go:github.com/gin-gonic/gin@v1.9.1"],
        ),
    ]

    classified = analyzer.analyze(deps)

    gin = next(d for d in classified if d.name == "github.com/gin-gonic/gin")
    assert gin.direct is True
    assert gin.transitive is False
    assert gin.depth == 1

    testify = next(d for d in classified if d.name == "github.com/stretchr/testify")
    assert testify.direct is False
    assert testify.transitive is True
    assert testify.depth == 2
