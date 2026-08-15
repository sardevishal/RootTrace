"""
models/dependency_graph.py

Pydantic models for the dependency graph structure.

The graph consists of:
  - DependencyNode:  a vertex in the graph (corresponds to a Dependency)
  - DependencyEdge:  a directed edge from parent to child (depends_on)
  - DependencyGraph: the complete graph with nodes, edges, and metadata

The graph is NOT assumed to be a tree. The same package can be required
by multiple parents (multiple incoming edges). Different versions of the
same package are distinct nodes.

Cycle detection is supported but cycles are recorded rather than raising
errors (dependency ecosystems can have cycles in edge cases).
"""

from typing import Optional, Any
from pydantic import BaseModel, Field


class DependencyNode(BaseModel):
    """
    A single vertex in the dependency graph.

    One node per unique (name, version, ecosystem, source_path) combination.
    Two packages with the same name but different versions are different nodes.
    """

    id: str = Field(
        ...,
        description="Unique node identifier. Matches Dependency.id.",
    )
    name: str = Field(..., description="Package name.")
    version: Optional[str] = Field(
        default=None,
        description="Resolved/exact version, or None if unresolved.",
    )
    version_spec: Optional[str] = Field(
        default=None,
        description="Raw version specifier from the manifest.",
    )
    ecosystem: str = Field(..., description="Canonical ecosystem name.")
    dependency_type: str = Field(default="runtime", description="runtime/development/optional/peer/...")
    direct: bool = Field(default=True, description="True if directly declared in a manifest.")
    transitive: bool = Field(default=False, description="True if pulled in transitively.")
    depth: int = Field(default=0, ge=0, description="Tree depth. 0=root, 1=direct, 2+=transitive.")
    source_manifest: str = Field(..., description="Manifest file type.")
    source_path: str = Field(..., description="Relative manifest path.")

    model_config = {"str_strip_whitespace": True}


class DependencyEdge(BaseModel):
    """
    A directed edge in the dependency graph.

    Represents: source depends_on target
    (source requires target as a dependency)
    """

    source: str = Field(
        ...,
        description="ID of the parent/requiring dependency node.",
    )
    target: str = Field(
        ...,
        description="ID of the child/required dependency node.",
    )
    relationship: str = Field(
        default="depends_on",
        description=(
            "Edge label describing the dependency relationship. "
            "One of: depends_on / dev_depends_on / peer_depends_on / optional_depends_on"
        ),
    )

    model_config = {"str_strip_whitespace": True}


class GraphStats(BaseModel):
    """Summary statistics for the dependency graph."""

    total_nodes: int = Field(default=0, description="Total number of nodes in the graph.")
    total_edges: int = Field(default=0, description="Total number of edges in the graph.")
    direct_nodes: int = Field(default=0, description="Nodes representing direct dependencies.")
    transitive_nodes: int = Field(default=0, description="Nodes representing transitive dependencies.")
    maximum_depth: int = Field(default=0, description="Maximum depth reached in the graph.")
    ecosystems: list[str] = Field(default_factory=list, description="Distinct ecosystems present.")
    root_dependency_ids: list[str] = Field(
        default_factory=list,
        description="IDs of root-level (direct) dependency nodes.",
    )
    cycles_detected: bool = Field(
        default=False,
        description="True if one or more cycles were found in the graph.",
    )
    cycle_paths: list[list[str]] = Field(
        default_factory=list,
        description="Lists of node IDs forming detected cycles.",
    )


class DependencyGraph(BaseModel):
    """
    The complete dependency graph for a repository scan.

    Contains all nodes (dependencies) and edges (relationships)
    discovered during analysis.
    """

    nodes: dict[str, DependencyNode] = Field(
        default_factory=dict,
        description="Mapping of node_id → DependencyNode.",
    )
    edges: list[DependencyEdge] = Field(
        default_factory=list,
        description="All directed dependency edges.",
    )
    stats: GraphStats = Field(
        default_factory=GraphStats,
        description="Computed graph statistics.",
    )
    adjacency: dict[str, list[str]] = Field(
        default_factory=dict,
        description=(
            "Adjacency list: node_id → list of child node_ids. "
            "Populated by GraphBuilder for efficient traversal."
        ),
    )
    reverse_adjacency: dict[str, list[str]] = Field(
        default_factory=dict,
        description=(
            "Reverse adjacency list: node_id → list of parent node_ids. "
            "Used for ancestor lookups and path tracing."
        ),
    )

    def get_node(self, node_id: str) -> Optional[DependencyNode]:
        """Return a node by ID, or None if not present."""
        return self.nodes.get(node_id)

    def get_children(self, node_id: str) -> list[DependencyNode]:
        """Return child nodes for a given node ID."""
        child_ids = self.adjacency.get(node_id, [])
        return [self.nodes[cid] for cid in child_ids if cid in self.nodes]

    def get_parents(self, node_id: str) -> list[DependencyNode]:
        """Return parent nodes for a given node ID."""
        parent_ids = self.reverse_adjacency.get(node_id, [])
        return [self.nodes[pid] for pid in parent_ids if pid in self.nodes]

    def get_all_paths(self, source_id: str, target_id: str) -> list[list[str]]:
        """
        Find all paths from source to target using DFS.
        Returns a list of paths, where each path is a list of node IDs.
        """
        all_paths: list[list[str]] = []
        visited: set[str] = set()

        def dfs(current: str, path: list[str]) -> None:
            if current == target_id:
                all_paths.append(list(path))
                return
            if current in visited:
                return
            visited.add(current)
            for child_id in self.adjacency.get(current, []):
                path.append(child_id)
                dfs(child_id, path)
                path.pop()
            visited.discard(current)

        dfs(source_id, [source_id])
        return all_paths
