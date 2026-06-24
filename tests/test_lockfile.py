from pathlib import Path

from dep_health_scanner import Ecosystem
from dep_health_scanner.lockfile import LockfileDetector


SINGLE_REQUIRE = """
module github.com/example/app

go 1.23

require github.com/pkg/errors v0.9.1
"""


MULTI_REQUIRE = """
module github.com/example/app

go 1.23

require (
    github.com/pkg/errors v0.9.1
    github.com/stretchr/testify v1.8.4
)
"""


MULTI_INDIRECT = """
module github.com/example/app

go 1.23

require (
    github.com/pkg/errors v0.9.1
    github.com/example/lib v1.2.3 // indirect
)
"""


def _write(tmp_path: Path, name: str, content: str) -> Path:
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return path


def test_parse_single_go_mod(tmp_path: Path):
    path = _write(tmp_path, "go.mod", SINGLE_REQUIRE)
    lock = LockfileDetector._parse(path, Ecosystem.GO)
    assert len(lock.dependencies) == 1
    assert lock.dependencies[0].name == "github.com/pkg/errors"
    assert lock.dependencies[0].version == "0.9.1"
    assert lock.dependencies[0].ecosystem.value == "go"
    assert lock.dependencies[0].transitive is False


def test_parse_multi_go_mod(tmp_path: Path):
    path = _write(tmp_path, "go.mod", MULTI_REQUIRE)
    lock = LockfileDetector._parse(path, Ecosystem.GO)
    assert len(lock.dependencies) == 2
    assert {d.name for d in lock.dependencies} == {
        "github.com/pkg/errors",
        "github.com/stretchr/testify",
    }


def test_parse_go_mod_indirect(tmp_path: Path):
    path = _write(tmp_path, "go.mod", MULTI_INDIRECT)
    lock = LockfileDetector._parse(path, Ecosystem.GO)
    assert len(lock.dependencies) == 2
    indirect = [d for d in lock.dependencies if d.transitive]
    assert len(indirect) == 1
    assert indirect[0].name == "github.com/example/lib"


def test_detect_go_mod(tmp_path: Path):
    (tmp_path / "go.mod").write_text(SINGLE_REQUIRE, encoding="utf-8")
    lock = LockfileDetector.detect(tmp_path)
    assert lock is not None
    assert lock.ecosystem.value == "go"


def test_detect_missing_go_mod(tmp_path: Path):
    lock = LockfileDetector.detect(tmp_path)
    assert lock is None
