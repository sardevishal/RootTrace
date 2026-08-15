"""
tests/dependency/test_normalizer.py

Unit tests for DependencyNormalizer and DependencyResolver.
"""

from app.parsers.base import ParsedDependency
from app.services.dependency.dependency_normalizer import DependencyNormalizer
from app.services.dependency.dependency_resolver import DependencyResolver


def test_normalizer_and_resolver():
    normalizer = DependencyNormalizer()

    parsed_list = [
        ParsedDependency(
            name="Django_REST_Framework",
            ecosystem="pypi",
            source_manifest="requirements.txt",
            source_path="requirements.txt",
            version=None,
            version_spec="==3.14.0",
        ),
        ParsedDependency(
            name="lodash",
            ecosystem="node",
            source_manifest="package.json",
            source_path="package.json",
            version="4.17.21",
            version_spec="^4.17.0",
        ),
        # Duplicate entry
        ParsedDependency(
            name="lodash",
            ecosystem="npm",
            source_manifest="package.json",
            source_path="package.json",
            version="4.17.21",
            version_spec="^4.17.0",
        ),
    ]

    deps, warnings = normalizer.normalize_all(parsed_list)

    # 3 inputs with 1 duplicate -> 2 normalized
    assert len(deps) == 2

    # Check ecosystem and name normalization
    django = next(d for d in deps if "django" in d.name)
    assert django.name == "django-rest-framework"
    assert django.ecosystem == "PyPI"

    lodash = next(d for d in deps if d.name == "lodash")
    assert lodash.ecosystem == "npm"

    # Resolver test
    resolver = DependencyResolver()
    resolved_deps, unresolved = resolver.resolve(deps)

    # django should have version extracted from ==3.14.0
    django_resolved = next(d for d in resolved_deps if d.name == "django-rest-framework")
    assert django_resolved.version == "3.14.0"
