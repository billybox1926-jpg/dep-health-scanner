use super::{
    cache::Cache,
    dependency::{Dependency, Ecosystem, ScanResult, Vulnerability},
    lockfile::LockfileDetector,
    reporter::Reporter,
};
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::path::PathBuf;

pub struct Scanner {
    cache: Cache,
    scan_path: PathBuf,
    bus_factor: bool,
    suggest: bool,
    fail_on_critical: bool,
    min_severity: String,
}

impl Scanner {
    pub fn new(cache: Cache, scan_path: PathBuf) -> Self {
        Self {
            cache,
            scan_path,
            bus_factor: false,
            suggest: false,
            fail_on_critical: false,
            min_severity: "low".to_string(),
        }
    }

    pub async fn configure(
        &mut self,
        bus_factor: bool,
        suggest: bool,
        fail_on_critical: bool,
        min_severity: String,
    ) -> Result<()> {
        self.bus_factor = bus_factor;
        self.suggest = suggest;
        self.fail_on_critical = fail_on_critical;
        self.min_severity = min_severity;
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        let lockfiles =
            LockfileDetector::detect_all(&self.scan_path).context("Failed to detect lockfiles")?;

        if lockfiles.is_empty() {
            eprintln!("No lockfiles found in {}", self.scan_path.display());
            return Ok(());
        }

        let mut all_results = Vec::new();

        for lockfile in lockfiles {
            println!(
                "Scanning {} ({})",
                lockfile.path.display().to_string().cyan(),
                lockfile.ecosystem
            );

            let deps = lockfile.dependencies;
            if deps.is_empty() {
                continue;
            }

            println!(
                "Found {} dependencies, scanning...",
                deps.len().to_string().cyan()
            );

            let results: Vec<ScanResult> = deps
                .into_par_iter()
                .map(|dep| self.scan_dependency(dep))
                .collect();

            all_results.extend(results);
        }

        let reporter = Reporter::new(self.fail_on_critical, self.min_severity.clone());
        reporter.print_report(&all_results)?;

        Ok(())
    }

    fn scan_dependency(&self, dep: Dependency) -> ScanResult {
        let ecosystem_str = dep.ecosystem.to_string();
        
        // Check cache first
        let latest_version = self.cache
            .get_latest_version(&ecosystem_str, &dep.name)
            .ok()
            .flatten();

        // Placeholder: in real implementation, this would query registry APIs
        // For now, we simulate a result based on what's in cache or unknown
        let (latest_version, outdated) = match latest_version {
            Some((v, _)) if v != dep.version => (Some(v), true),
            Some((v, _)) => (Some(v), false),
            None => (None, false),
        };

        // Check vulnerabilities
        let vulnerabilities = self.cache
            .get_vulnerabilities(&ecosystem_str, &dep.name)
            .ok()
            .unwrap_or_default();

        // Placeholder for bus factor
        let bus_factor_score = if self.bus_factor {
            Some(50) // placeholder
        } else {
            None
        };

        ScanResult {
            dependency: dep.clone(),
            latest_version,
            outdated,
            vulnerabilities,
            license: None, // placeholder
            bus_factor_score,
            alternatives: Vec::new(),
        }
    }
}
