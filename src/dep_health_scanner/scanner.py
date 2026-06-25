from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

import httpx
from packaging.version import Version

from .cache import Cache
from .models import Dependency, Ecosystem, ScanResult, Vulnerability


class RegistryClient:
    def __init__(self, cache: Cache):
        self.cache = cache
        self._client = httpx.Client(timeout=httpx.Timeout(10.0), follow_redirects=True)

    def close(self):
        self._client.close()

    def get_latest(self, dep: Dependency) -> Optional[str]:
        cached = self.cache.get_latest_version(dep.ecosystem.value, dep.name)
        if cached:
            version, _ = cached
            return version
        try:
            if dep.ecosystem == Ecosystem.NPM:
                latest = self._fetch_npm_latest(dep.name)
            elif dep.ecosystem == Ecosystem.CARGO:
                latest = self._fetch_cargo_latest(dep.name)
            elif dep.ecosystem == Ecosystem.GO:
                latest = self._fetch_go_latest(dep.name)
            else:
                return None
            if latest:
                self.cache.set_latest_version(dep.ecosystem.value, dep.name, latest)
            return latest
        except Exception:
            return None

    def _fetch_npm_latest(self, name: str) -> Optional[str]:
        url = f"https://registry.npmjs.org/{name}"
        resp = self._client.get(url)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("dist-tags", {}).get("latest")
        return None

    def _fetch_cargo_latest(self, name: str) -> Optional[str]:
        url = f"https://crates.io/api/v1/crates/{name}"
        resp = self._client.get(url)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("crate", {}).get("newest_version")
        return None

    def _fetch_go_latest(self, name: str) -> Optional[str]:
        encoded = name.strip("/")
        if not encoded.startswith("@"):
            encoded = f"@{encoded}"
        url = f"https://proxy.golang.org{encoded}/@latest"
        resp = self._client.get(url)
        if resp.status_code != 200:
            return None
        data = resp.json()
        version = data.get("Version")
        if version:
            return version.lstrip("v")
        return None


class VulnerabilityClient:
    OSV_API = "https://api.osv.dev/v1/query"

    def __init__(self, cache: Cache):
        self.cache = cache
        self._client = httpx.Client(timeout=httpx.Timeout(15.0))

    def close(self):
        self._client.close()

    def check(self, dep: Dependency) -> List[Vulnerability]:
        cached = self.cache.get_vulnerabilities(dep.ecosystem.value, dep.name)
        if cached:
            return cached
        try:
            vulns = self._query_osv(dep)
            for v in vulns:
                self.cache.add_vulnerability(v, dep.ecosystem.value, dep.name)
            return vulns
        except Exception:
            return []

    def _query_osv(self, dep: Dependency) -> List[Vulnerability]:
        payload = {
            "package": {"name": dep.name, "ecosystem": dep.ecosystem.value},
            "version": dep.version,
        }
        resp = self._client.post(self.OSV_API, json=payload)
        if resp.status_code != 200:
            return []
        data = resp.json()
        results = []
        for v in data.get("vulns", []):
            severity = 0.0
            if "severity" in v and v["severity"]:
                scores = []
                for s in v["severity"]:
                    if s.get("type") == "CVSS_V3":
                        try:
                            scores.append(float(s["score"].split("/")[0]))
                        except Exception:
                            pass
                if scores:
                    severity = max(scores)
            fixed = []
            for affected in v.get("affected", []):
                for r in affected.get("ranges", []):
                    for e in r.get("events", []):
                        if "fixed" in e:
                            fixed.append(e["fixed"])
            results.append(
                Vulnerability(
                    id=v.get("id", "UNKNOWN"),
                    summary=v.get("summary", ""),
                    severity=severity,
                    cve=v.get("aliases", [None])[0] if v.get("aliases") else None,
                    fixed_versions=sorted(set(fixed)),
                )
            )
        return results


class Scanner:
    def __init__(self, cache: Cache):
        self.cache = cache
        self.registry = RegistryClient(cache)
        self.vuln_client = VulnerabilityClient(cache)

    def scan(self, deps: List[Dependency]) -> List[ScanResult]:
        results: List[ScanResult] = []
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(self._scan_one, dep): dep for dep in deps}
            for future in as_completed(futures):
                results.append(future.result())
        return results

    def _scan_one(self, dep: Dependency) -> ScanResult:
        latest, vulns = self._update_one(dep)
        outdated = False
        if latest and latest != dep.version:
            try:
                if Version(latest) > Version(dep.version):
                    outdated = True
            except Exception:
                pass

        return ScanResult(
            dependency=dep,
            latest_version=latest,
            outdated=outdated,
            vulnerabilities=vulns,
        )

    def _update_one(self, dep: Dependency) -> tuple[Optional[str], List[Vulnerability]]:
        latest = self.registry.get_latest(dep)
        vulns = self.vuln_client.check(dep)
        return latest, vulns

    def update(
        self,
        deps: List[Dependency],
        progress_callback=None,
    ) -> dict:
        updated = 0
        vulns_found = 0
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(self._update_one, dep): dep for dep in deps}
            for future in as_completed(futures):
                latest, vulns = future.result()
                if progress_callback:
                    progress_callback()
                if latest or vulns:
                    updated += 1
                vulns_found += len(vulns)
        return {"updated": updated, "vulns_found": vulns_found}

    def close(self):
        self.registry.close()
        self.vuln_client.close()
