"""
tests/dependency/test_graph_builder.py

Unit tests for GraphBuilder and GraphAnalyzer.
"""

from app.models.dependency import Dependency
from app.models.dependency_graph import DependencyNode, DependencyEdge, DependencyGraph
from app.services.dependency.graph_builder import GraphBuilder, ROOT_NODE_ID
from app.services.dependency.graph_analyzer import GraphAnalyzer


def test_graph_builder_and_analyzer():
    deps = [
        Dependency(
            id="npm:express@4.18.2",
            name="express",
            version="4.18.2",
            ecosystem="npm",
            source_manifest="package.json",
            source_path="package.json",
            direct=True,
            depth=1,
        ),
        Dependency(
            id="PyPI:requests@2.31.0",
            name="requests",
            version="2.31.0",
            ecosystem="PyPI",
            source_manifest="requirements.txt",
            source_path="requirements.txt",
            direct=True,
            depth=1,
        ),
        Dependency(
            id="Go:github.com/stretchr/testify@v1.8.4",
            name="github.com/stretchr/testify",
            version="v1.8.4",
            ecosystem="Go",
            source_manifest="go.mod",
            source_path="go.mod",
            direct=False,
            transitive=True,
            depth=2,
        ),
    ]

    builder = GraphBuilder()
    graph = builder.build(deps)

    # 1 root node + 3 dep nodes = 4 nodes
    assert len(graph.nodes) == 4
    assert ROOT_NODE_ID in graph.nodes

    # Direct deps have edges from ROOT
    assert len(graph.edges) == 2
    assert "npm:express@4.18.2" in graph.adjacency[ROOT_NODE_ID]
    assert "PyPI:requests@2.31.0" in graph.adjacency[ROOT_NODE_ID]

    # GraphAnalyzer test
    analyzer = GraphAnalyzer()
    analyzed_graph = analyzer.analyze(graph)
    assert analyzed_graph.stats.cycles_detected is False


def test_cycle_detection():
    graph = DependencyGraph()
    for nid in ["A", "B", "C"]:
        graph.nodes[nid] = DependencyNode(
            id=nid,
            name=nid,
            ecosystem="npm",
            source_manifest="package.json",
            source_path="package.json",
        )
    # A -> B -> C -> A (cycle)
    graph.adjacency = {
        "A": ["B"],
        "B": ["C"],
        "C": ["A"],
    }
    graph.reverse_adjacency = {
        "A": ["C"],
        "B": ["A"],
        "C": ["B"],
    }

    analyzer = GraphAnalyzer()
    cycles = analyzer.detect_cycles(graph)
    assert len(cycles) > 0
    assert "A" in cycles[0]
