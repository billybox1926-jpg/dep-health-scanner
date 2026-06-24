use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub source: Option<String>,
    pub transitive: bool,
    pub dependencies: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ecosystem {
    Npm,
    Cargo,
    Pip,
    Go,
    Unknown,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ecosystem::Npm => write!(f, "npm"),
            Ecosystem::Cargo => write!(f, "cargo"),
            Ecosystem::Pip => write!(f, "pip"),
            Ecosystem::Go => write!(f, "go"),
            Ecosystem::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub dependency: Dependency,
    pub latest_version: Option<String>,
    pub outdated: bool,
    pub vulnerabilities: Vec<Vulnerability>,
    pub license: Option<String>,
    pub bus_factor_score: Option<u8>,
    pub alternatives: Vec<Alternative>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub id: String,
    pub summary: String,
    pub severity: f32,
    pub cve: Option<String>,
    pub fixed_versions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alternative {
    pub name: String,
    pub version: String,
    pub stars: u32,
    pub weekly_downloads: u64,
    pub size_kb: Option<u64>,
    pub score: f32,
}

#[derive(Debug, Clone)]
pub struct Lockfile {
    pub path: PathBuf,
    pub ecosystem: Ecosystem,
    pub dependencies: Vec<Dependency>,
}
