"""
services/dependency/graph_analyzer.py

Provides graph analysis operations on a DependencyGraph.

Phase 1: Basic statistics and cycle detection (DFS-based).
Phase 3 (future): Full path analysis, ancestor/descendant lookups,
  affected dependency path tracing for vulnerable packages.

Operations:
  - detect_cycles():     Find circular dependency chains
  - get_ancestors():     All ancestors of a node
  - get_descendants():   All descendants of a node
  - get_path():          Shortest path between two nodes
  - compute_depths():    Recalculate depth for all nodes via BFS
"""

from collections import deque
from typing import Optional

from app.models.dependency_graph import DependencyGraph, GraphStats
from app.utils.logger import get_logger
from app.services.dependency.graph_builder import ROOT_NODE_ID

logger = get_logger(__name__)


class GraphAnalyzer:
    """
    Provides analysis operations on a DependencyGraph.

    All operations are read-only — the graph is not mutated.
    """

    def analyze(self, graph: DependencyGraph) -> DependencyGraph:
        """
        Run all Phase 1 analysis passes on the graph.

        Mutates graph.stats in place to add cycle information.

        Args:
            graph: A DependencyGraph built by GraphBuilder.

        Returns:
            The same graph object with updated stats.
        """
        # Detect cycles
        cycles = self.detect_cycles(graph)
        graph.stats.cycles_detected = len(cycles) > 0
        graph.stats.cycle_paths = cycles

        if cycles:
            logger.warning(
                "GraphAnalyzer | %d cycle(s) detected in dependency graph",
                len(cycles),
            )
            for cycle in cycles:
                logger.warning("GraphAnalyzer | Cycle: %s", " → ".join(cycle))

        return graph

    def detect_cycles(self, graph: DependencyGraph) -> list[list[str]]:
        """
        Detect all cycles in the graph using DFS with coloring.

        Returns:
            List of cycles, where each cycle is a list of node IDs
            forming the cycle path.
        """
        WHITE, GRAY, BLACK = 0, 1, 2
        color: dict[str, int] = {nid: WHITE for nid in graph.nodes}
        cycles: list[list[str]] = []
        path: list[str] = []

        def dfs(node_id: str) -> None:
            color[node_id] = GRAY
            path.append(node_id)

            for child_id in graph.adjacency.get(node_id, []):
                if child_id not in color:
                    continue
                if color[child_id] == GRAY:
                    # Found a back edge — record the cycle
                    cycle_start = path.index(child_id)
                    cycle = path[cycle_start:] + [child_id]
                    cycles.append(cycle)
                elif color[child_id] == WHITE:
                    dfs(child_id)

            path.pop()
            color[node_id] = BLACK

        for node_id in graph.nodes:
            if color[node_id] == WHITE:
                dfs(node_id)

        return cycles

    def compute_depths(self, graph: DependencyGraph) -> dict[str, int]:
        """
        Compute BFS-based depth for all nodes from the root.

        Returns:
            dict mapping node_id → depth (distance from root node).
        """
        depths: dict[str, int] = {}
        queue: deque[tuple[str, int]] = deque()

        if ROOT_NODE_ID in graph.nodes:
            queue.append((ROOT_NODE_ID, 0))
            depths[ROOT_NODE_ID] = 0
        else:
            # No root node — start from all nodes with no parents
            for node_id in graph.nodes:
                if not graph.reverse_adjacency.get(node_id):
                    queue.append((node_id, 0))
                    depths[node_id] = 0

        while queue:
            current_id, current_depth = queue.popleft()
            for child_id in graph.adjacency.get(current_id, []):
                if child_id not in depths:
                    depths[child_id] = current_depth + 1
                    queue.append((child_id, current_depth + 1))

        return depths

    def get_ancestors(self, graph: DependencyGraph, node_id: str) -> set[str]:
        """
        Return all ancestor node IDs for the given node (BFS upward).

        Args:
            graph:   The dependency graph.
            node_id: The target node.

        Returns:
            Set of node IDs that are ancestors of the target.
        """
        ancestors: set[str] = set()
        queue: deque[str] = deque([node_id])

        while queue:
            current = queue.popleft()
            for parent_id in graph.reverse_adjacency.get(current, []):
                if parent_id not in ancestors:
                    ancestors.add(parent_id)
                    queue.append(parent_id)

        ancestors.discard(node_id)
        return ancestors

    def get_descendants(self, graph: DependencyGraph, node_id: str) -> set[str]:
        """
        Return all descendant node IDs for the given node (BFS downward).

        Args:
            graph:   The dependency graph.
            node_id: The source node.

        Returns:
            Set of node IDs that are descendants of the source.
        """
        descendants: set[str] = set()
        queue: deque[str] = deque([node_id])

        while queue:
            current = queue.popleft()
            for child_id in graph.adjacency.get(current, []):
                if child_id not in descendants:
                    descendants.add(child_id)
                    queue.append(child_id)

        descendants.discard(node_id)
        return descendants

    def get_shortest_path(
        self,
        graph: DependencyGraph,
        source_id: str,
        target_id: str,
    ) -> Optional[list[str]]:
        """
        Find the shortest path from source to target using BFS.

        Args:
            graph:     The dependency graph.
            source_id: Starting node ID.
            target_id: Target node ID.

        Returns:
            List of node IDs representing the shortest path,
            or None if no path exists.
        """
        if source_id not in graph.nodes or target_id not in graph.nodes:
            return None
        if source_id == target_id:
            return [source_id]

        visited: set[str] = {source_id}
        queue: deque[list[str]] = deque([[source_id]])

        while queue:
            path = queue.popleft()
            current = path[-1]

            for child_id in graph.adjacency.get(current, []):
                if child_id == target_id:
                    return path + [child_id]
                if child_id not in visited:
                    visited.add(child_id)
                    queue.append(path + [child_id])

        return None
