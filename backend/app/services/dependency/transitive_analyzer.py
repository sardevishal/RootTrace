"""
services/dependency/transitive_analyzer.py

Performs direct vs. transitive dependency classification.

Phase 1: All parsed dependencies are direct by default.
  - go.mod marks indirect dependencies with "// indirect" → dep.go_indirect
  - These are reclassified as transitive at depth=1

Phase 2 (future): Full recursive resolution via ecosystem APIs or
  local lock files (npm, pip, Maven) to discover the complete
  transitive dependency tree.

Design:
  - Direct: explicitly declared in a manifest file
  - Transitive: pulled in by another dependency (not directly declared)
  - Depth 0: application root
  - Depth 1: direct dependencies
  - Depth 2+: transitive dependencies

For Phase 1, we perform the following:
  1. Mark go.mod "indirect" dependencies as transitive (depth=1)
  2. All others remain direct (depth=1 after classification,
     where depth=0 is the application root)
  3. Build basic parent/child relationships from lockfile data
     (npm package-lock.json for Phase 1)
"""

from app.models.dependency import Dependency
from app.utils.logger import get_logger

logger = get_logger(__name__)


class TransitiveAnalyzer:
    """
    Classifies dependencies as direct or transitive and assigns depth values.

    Phase 1: Static classification using available manifest metadata.
    """

    def analyze(
        self,
        dependencies: list[Dependency],
    ) -> list[Dependency]:
        """
        Classify each dependency as direct or transitive.

        Args:
            dependencies: Normalized dependency list from DependencyResolver.

        Returns:
            Updated dependency list with direct/transitive/depth fields set.
        """
        direct_count = 0
        transitive_count = 0

        # Create a lookup for quick access
        dep_map = {d.id: d for d in dependencies}

        # Iteratively calculate depth based on parents
        # Direct dependencies (no parents) have depth 1
        for dep in dependencies:
            if dep.direct:
                dep.depth = 1
                direct_count += 1
            else:
                dep.transitive = True
                transitive_count += 1

        # Simple BFS to assign depth to transitive dependencies
        queue = [d for d in dependencies if d.direct]
        visited = {d.id for d in queue}
        
        while queue:
            current = queue.pop(0)
            
            # Find all dependencies that have `current.id` in their parent_ids
            children = [d for d in dependencies if current.id in d.parent_ids]
            
            for child in children:
                if child.id not in visited:
                    child.depth = current.depth + 1
                    visited.add(child.id)
                    queue.append(child)
                else:
                    # Update depth to the minimum possible path if seen again
                    child.depth = min(child.depth, current.depth + 1)

        # Unreachable nodes (e.g. detached transitive deps without a direct parent)
        for dep in dependencies:
            if dep.id not in visited:
                dep.depth = 2 # fallback
                
        logger.info(
            "TransitiveAnalyzer | Phase 1 classification complete: "
            "%d direct, %d transitive",
            direct_count,
            transitive_count,
        )

        return dependencies

    def _is_transitive(self, dep: Dependency) -> bool:
        """
        Determine if a dependency is transitive based on available metadata.

        Phase 1 rules:
          - go.mod "// indirect" marker → transitive
          - dependency_type == "indirect" → transitive
          - All others → direct
        """
        # Go indirect marker
        if dep.go_indirect:
            return True

        # Explicit indirect type
        if dep.dependency_type == "indirect":
            return True

        return False
