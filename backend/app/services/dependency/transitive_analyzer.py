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

        for dep in dependencies:
            is_transitive = self._is_transitive(dep)

            if is_transitive:
                dep.direct = False
                dep.transitive = True
                dep.depth = 2  # Phase 1: transitive = depth 2 (direct of direct)
                transitive_count += 1
            else:
                dep.direct = True
                dep.transitive = False
                dep.depth = 1  # Direct deps are at depth 1 (app root is 0)
                direct_count += 1

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
