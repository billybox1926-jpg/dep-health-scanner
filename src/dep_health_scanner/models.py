from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional


class Ecosystem(str, Enum):
    NPM = "npm"
    CARGO = "cargo"
    PIP = "pip"
    GO = "go"
    UNKNOWN = "unknown"


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: Ecosystem = Ecosystem.UNKNOWN
    source: Optional[str] = None
    transitive: bool = False
    dependencies: List[str] = field(default_factory=list)


@dataclass
class Lockfile:
    path: Path
    ecosystem: Ecosystem
    dependencies: List[Dependency] = field(default_factory=list)


@dataclass
class Vulnerability:
    id: str
    summary: str
    severity: float  # CVSS score
    cve: Optional[str] = None
    fixed_versions: List[str] = field(default_factory=list)


@dataclass
class Alternative:
    name: str
    version: str
    stars: int = 0
    weekly_downloads: int = 0
    size_kb: Optional[int] = None
    score: float = 0.0


@dataclass
class ScanResult:
    dependency: Dependency
    latest_version: Optional[str] = None
    outdated: bool = False
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    license: Optional[str] = None
    bus_factor_score: Optional[int] = None
    alternatives: List[Alternative] = field(default_factory=list)
