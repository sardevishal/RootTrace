"""
tests/dependency/test_pom_parser.py

Unit tests for PomParser.
"""

import os
import pytest
from app.parsers.pom_parser import PomParser
from app.models.manifest import ManifestInfo


def test_parse_pom_xml():
    fixtures_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "test_fixtures"))
    pom_path = os.path.join(fixtures_dir, "pom.xml")

    manifest = ManifestInfo(
        path="pom.xml",
        absolute_path=pom_path,
        manifest_type="pom.xml",
        ecosystem="Maven",
    )

    parser = PomParser()
    deps = parser.parse(manifest)
    dep_map = {d.name: d for d in deps}

    # org.springframework.boot:spring-boot-starter-web
    assert "org.springframework.boot:spring-boot-starter-web" in dep_map
    spring = dep_map["org.springframework.boot:spring-boot-starter-web"]
    assert spring.version == "2.7.5"
    assert spring.group_id == "org.springframework.boot"
    assert spring.artifact_id == "spring-boot-starter-web"
    assert spring.dependency_type == "runtime"

    # org.apache.logging.log4j:log4j-core
    assert "org.apache.logging.log4j:log4j-core" in dep_map
    log4j = dep_map["org.apache.logging.log4j:log4j-core"]
    assert log4j.version == "2.14.1"

    # junit:junit (test scope)
    assert "junit:junit" in dep_map
    junit = dep_map["junit:junit"]
    assert junit.dependency_type == "test"

    # org.projectlombok:lombok (optional=true)
    assert "org.projectlombok:lombok" in dep_map
    lombok = dep_map["org.projectlombok:lombok"]
    assert lombok.dependency_type == "optional"


def test_malformed_pom_xml(tmp_path):
    bad_pom = tmp_path / "pom.xml"
    bad_pom.write_text("<project><broken></project>", encoding="utf-8")

    manifest = ManifestInfo(
        path="pom.xml",
        absolute_path=str(bad_pom),
        manifest_type="pom.xml",
        ecosystem="Maven",
    )

    parser = PomParser()
    with pytest.raises(ValueError, match="Invalid XML"):
        parser.parse(manifest)
