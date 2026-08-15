"""
schemas/dependency_graph_schema.py

API output schemas for the dependency graph.
"""

from typing import Optional
from pydantic import BaseModel, Field


class DependencyNodeOut(BaseModel):
    """A single dependency node as returned by the API."""
    id: str
    name: str
    version: Optional[str] = None
    version_spec: Optional[str] = None
    ecosystem: str
    dependency_type: str
    direct: bool
    transitive: bool
    depth: int
    source_manifest: str
    source_path: str


class DependencyEdgeOut(BaseModel):
    """A directed dependency edge as returned by the API."""
    source: str
    target: str
    relationship: str


class GraphStatsOut(BaseModel):
    """Graph summary statistics as returned by the API."""
    total_nodes: int
    total_edges: int
    direct_nodes: int
    transitive_nodes: int
    maximum_depth: int
    ecosystems: list[str]
    root_dependency_ids: list[str]
    cycles_detected: bool
    cycle_paths: list[list[str]] = Field(default_factory=list)


class DependencyGraphOut(BaseModel):
    """Full dependency graph as returned by the API."""
    nodes: dict[str, DependencyNodeOut]
    edges: list[DependencyEdgeOut]
    stats: GraphStatsOut
