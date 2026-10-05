"""
services/dependency/graph_builder.py

Builds the dependency graph from a flat list of Dependency objects.

The graph is a directed graph (NOT a tree):
  - Nodes: one per unique dependency (by ID)
  - Edges: parent → child (depends_on)
  - The same dependency can have multiple parents
  - Different versions of the same package are distinct nodes

Phase 1 graph construction:
  - Creates one node per dependency
  - Does NOT create edges between dependencies (no transitive edge data
    without full resolution — Phase 2 will add edges)
  - Computes graph statistics

Phase 2 (future): Add edges from lockfile transitive data.

The virtual ROOT node represents the application itself.
Direct dependencies get edges: ROOT → dep
"""

from app.models.dependency import Dependency
from app.models.dependency_graph import (
    DependencyGraph,
    DependencyNode,
    DependencyEdge,
    GraphStats,
)
from app.utils.constants import EDGE_DEPENDS_ON, EDGE_DEV_DEPENDS_ON, EDGE_PEER_DEPENDS_ON, EDGE_OPTIONAL_DEPENDS_ON
from app.utils.logger import get_logger

logger = get_logger(__name__)

# Virtual root node ID representing the application itself
ROOT_NODE_ID = "root:application@0.0.0"

# Dependency type → edge relationship label
_TYPE_TO_EDGE = {
    "runtime": EDGE_DEPENDS_ON,
    "development": EDGE_DEV_DEPENDS_ON,
    "peer": EDGE_PEER_DEPENDS_ON,
    "optional": EDGE_OPTIONAL_DEPENDS_ON,
    "provided": EDGE_DEPENDS_ON,
    "test": EDGE_DEV_DEPENDS_ON,
    "system": EDGE_DEPENDS_ON,
    "indirect": EDGE_DEPENDS_ON,
    "build": EDGE_DEPENDS_ON,
    "unknown": EDGE_DEPENDS_ON,
}


class GraphBuilder:
    """
    Builds a DependencyGraph from a flat list of Dependency objects.

    Phase 1: Creates nodes for each dependency. Direct deps get an
    edge from the virtual root node.
    """

    def build(self, dependencies: list[Dependency]) -> DependencyGraph:
        """
        Build a DependencyGraph from dependency list.

        Args:
            dependencies: Normalized, resolved, classified dependency list.

        Returns:
            DependencyGraph with nodes, edges, adjacency lists, and stats.
        """
        logger.info("GraphBuilder | Building graph from %d dependencies", len(dependencies))

        graph = DependencyGraph()

        # Add virtual root node
        root_node = DependencyNode(
            id=ROOT_NODE_ID,
            name="application",
            version="0.0.0",
            version_spec=None,
            ecosystem="root",
            dependency_type="root",
            direct=False,
            transitive=False,
            depth=0,
            source_manifest="root",
            source_path="",
        )
        graph.nodes[ROOT_NODE_ID] = root_node
        graph.adjacency[ROOT_NODE_ID] = []
        graph.reverse_adjacency[ROOT_NODE_ID] = []

        # Add all dependency nodes
        for dep in dependencies:
            node = DependencyNode(
                id=dep.id,
                name=dep.name,
                version=dep.version,
                version_spec=dep.version_spec,
                ecosystem=dep.ecosystem,
                dependency_type=dep.dependency_type,
                direct=dep.direct,
                transitive=dep.transitive,
                depth=dep.depth,
                source_manifest=dep.source_manifest,
                source_path=dep.source_path,
            )

            if dep.id not in graph.nodes:
                graph.nodes[dep.id] = node
                graph.adjacency[dep.id] = []
                graph.reverse_adjacency[dep.id] = []
            else:
                # Duplicate ID — node already exists (deduplication happened in normalizer)
                logger.debug("GraphBuilder | Duplicate node ID skipped: %s", dep.id)

            # Create edges from root → direct dependencies
            if dep.direct:
                edge_label = _TYPE_TO_EDGE.get(dep.dependency_type, EDGE_DEPENDS_ON)
                edge = DependencyEdge(
                    source=ROOT_NODE_ID,
                    target=dep.id,
                    relationship=edge_label,
                )
                graph.edges.append(edge)

                # Update adjacency lists
                if dep.id not in graph.adjacency[ROOT_NODE_ID]:
                    graph.adjacency[ROOT_NODE_ID].append(dep.id)
                if ROOT_NODE_ID not in graph.reverse_adjacency.get(dep.id, []):
                    graph.reverse_adjacency.setdefault(dep.id, []).append(ROOT_NODE_ID)

            # Create edges from parent_ids
            for parent_id in dep.parent_ids:
                if parent_id in graph.nodes or parent_id == ROOT_NODE_ID:
                    edge = DependencyEdge(
                        source=parent_id,
                        target=dep.id,
                        relationship=EDGE_DEPENDS_ON,
                    )
                    graph.edges.append(edge)
                    
                    if dep.id not in graph.adjacency.get(parent_id, []):
                        graph.adjacency.setdefault(parent_id, []).append(dep.id)
                    if parent_id not in graph.reverse_adjacency.get(dep.id, []):
                        graph.reverse_adjacency.setdefault(dep.id, []).append(parent_id)

        # Compute graph statistics
        graph.stats = self._compute_stats(graph, dependencies)

        logger.info(
            "GraphBuilder | Graph built: %d nodes, %d edges",
            len(graph.nodes),
            len(graph.edges),
        )
        return graph

    def _compute_stats(
        self,
        graph: DependencyGraph,
        dependencies: list[Dependency],
    ) -> GraphStats:
        """Compute summary statistics for the graph."""
        direct_nodes = [d for d in dependencies if d.direct]
        transitive_nodes = [d for d in dependencies if d.transitive]
        ecosystems = list({d.ecosystem for d in dependencies})
        max_depth = max((d.depth for d in dependencies), default=0)

        return GraphStats(
            total_nodes=len(graph.nodes),  # includes root node
            total_edges=len(graph.edges),
            direct_nodes=len(direct_nodes),
            transitive_nodes=len(transitive_nodes),
            maximum_depth=max_depth,
            ecosystems=sorted(ecosystems),
            root_dependency_ids=[d.id for d in direct_nodes],
            cycles_detected=False,   # Phase 3: GraphAnalyzer will detect cycles
            cycle_paths=[],
        )
