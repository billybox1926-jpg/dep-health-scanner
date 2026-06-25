from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional

from .models import Dependency, Ecosystem, Lockfile


class LockfileDetector:
    PATTERNS: List[tuple[str, Ecosystem]] = [
        ("package-lock.json", Ecosystem.NPM),
        ("yarn.lock", Ecosystem.NPM),
        ("pnpm-lock.yaml", Ecosystem.NPM),
        ("Cargo.lock", Ecosystem.CARGO),
        ("Pipfile.lock", Ecosystem.PIP),
        ("poetry.lock", Ecosystem.PIP),
        ("go.mod", Ecosystem.GO),
    ]

    @classmethod
    def detect(cls, root: Path) -> Optional[Lockfile]:
        for filename, eco in cls.PATTERNS:
            path = root / filename
            if path.exists():
                return cls._parse(path, eco)
        return None

    @classmethod
    def _parse(cls, path: Path, ecosystem: Ecosystem) -> Lockfile:
        if ecosystem == Ecosystem.NPM:
            deps = cls._parse_npm(path)
        elif ecosystem == Ecosystem.CARGO:
            deps = cls._parse_cargo(path)
        elif ecosystem == Ecosystem.PIP:
            deps = cls._parse_pip(path)
        elif ecosystem == Ecosystem.GO:
            deps = cls._parse_go_mod(path)
        else:
            raise ValueError(f"Unsupported ecosystem: {ecosystem}")
        return Lockfile(path=path, ecosystem=ecosystem, dependencies=deps)

    @classmethod
    def _parse_npm(cls, path: Path) -> List[Dependency]:
        data = json.loads(path.read_text())
        deps: List[Dependency] = []
        # package-lock.json v2+
        packages = data.get("packages") or data.get("dependencies") or {}
        if isinstance(packages, dict):
            for key, info in packages.items():
                if not key or not isinstance(info, dict):
                    continue
                version = info.get("version")
                if not version:
                    continue
                name = (
                    key.split("/")[0]
                    if not key.startswith("node_modules/")
                    else key.replace("node_modules/", "")
                )
                deps.append(
                    Dependency(
                        name=name,
                        version=str(version),
                        ecosystem=Ecosystem.NPM,
                        transitive="node_modules/" in key,
                    )
                )
        return deps

    @classmethod
    def _parse_cargo(cls, path: Path) -> List[Dependency]:
        data = json.loads(path.read_text())
        packages = data.get("package") or data.get("packages") or []
        deps: List[Dependency] = []
        if isinstance(packages, list):
            for pkg in packages:
                deps.append(
                    Dependency(
                        name=pkg["name"],
                        version=pkg["version"],
                        ecosystem=Ecosystem.CARGO,
                        source=pkg.get("source"),
                        transitive=True,
                    )
                )
        return deps

    @classmethod
    def _parse_pip(cls, path: Path) -> List[Dependency]:
        # Pipfile.lock is JSON; poetry.lock is TOML. Handle both.
        if path.suffix == ".toml":
            import tomllib

            with path.open("rb") as f:
                data = tomllib.load(f)
            packages = data.get("package", [])
            deps = [
                Dependency(name=p["name"], version=p["version"], ecosystem=Ecosystem.PIP)
                for p in packages
            ]
            return deps
        data = json.loads(path.read_text())
        deps: List[Dependency] = []
        for section in ("default", "develop"):
            if section in data and isinstance(data[section], dict):
                for name, info in data[section].items():
                    version = info.get("version")
                    if version:
                        deps.append(
                            Dependency(
                                name=name,
                                version=version,
                                ecosystem=Ecosystem.PIP,
                                transitive=False,
                            )
                        )
        return deps

    @classmethod
    def _parse_go_mod(cls, path: Path) -> List[Dependency]:
        lines = path.read_text().splitlines()
        deps: List[Dependency] = []
        inside_block = False

        for raw in lines:
            stripped = raw.strip()

            if inside_block:
                if stripped.startswith(")"):
                    inside_block = False
                    continue
                if not stripped or stripped.startswith("//"):
                    continue
                name, version, *_ = re.split(r"\s+", stripped)
                is_indirect = "// indirect" in stripped
                deps.append(
                    Dependency(
                        name=name,
                        version=version.lstrip("v"),
                        ecosystem=Ecosystem.GO,
                        transitive=is_indirect,
                    )
                )
                continue

            if not stripped.startswith("require"):
                continue

            block = stripped[len("require") :].strip()
            if block.startswith("("):
                inside_block = True
                # drop the opening paren on the same line
                after_paren = block[1:].strip()
                if after_paren and not after_paren.startswith("//"):
                    name, version, *_ = re.split(r"\s+", after_paren)
                    is_indirect = "// indirect" in after_paren
                    deps.append(
                        Dependency(
                            name=name,
                            version=version.lstrip("v"),
                            ecosystem=Ecosystem.GO,
                            transitive=is_indirect,
                        )
                    )
                continue

            name, version, *_ = re.split(r"\s+", block)
            is_indirect = "// indirect" in block
            deps.append(
                Dependency(
                    name=name,
                    version=version.lstrip("v"),
                    ecosystem=Ecosystem.GO,
                    transitive=is_indirect,
                )
            )

        return deps
