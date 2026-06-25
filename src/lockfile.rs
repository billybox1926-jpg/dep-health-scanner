use super::dependency::{Dependency, Ecosystem, Lockfile};
use super::Error;
use glob::glob;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

pub struct LockfileDetector;

impl LockfileDetector {
    pub fn detect(root: &Path) -> Result<Option<Lockfile>> {
        let patterns = vec![
            ("package-lock.json", Ecosystem::Npm),
            ("yarn.lock", Ecosystem::Npm),
            ("pnpm-lock.yaml", Ecosystem::Npm),
            ("Cargo.lock", Ecosystem::Cargo),
            ("Pipfile.lock", Ecosystem::Pip),
            ("poetry.lock", Ecosystem::Pip),
            ("go.sum", Ecosystem::Go),
        ];

        for (filename, eco) in patterns {
            let path = root.join(filename);
            if path.exists() {
                let lockfile = Self::parse(&path, eco)?;
                return Ok(Some(lockfile));
            }
        }

        // Recursive search for lockfiles (limited depth)
        for entry in glob(root.join("**/package-lock.json").to_str().unwrap()).unwrap() {
            if let Ok(path) = entry {
                let lockfile = Self::parse(&path, Ecosystem::Npm)?;
                return Ok(Some(lockfile));
            }
        }

        Ok(None)
    }

    pub fn detect_all(root: &Path) -> Result<Vec<Lockfile>> {
        let mut lockfiles = Vec::new();
        let patterns = vec![
            ("package-lock.json", Ecosystem::Npm),
            ("Cargo.lock", Ecosystem::Cargo),
            ("Pipfile.lock", Ecosystem::Pip),
        ];

        for (filename, eco) in patterns {
            for entry in glob(root.join(format!("**/{}", filename)).to_str().unwrap()).unwrap() {
                if let Ok(path) = entry {
                    if let Ok(lf) = Self::parse(&path, eco) {
                        lockfiles.push(lf);
                    }
                }
            }
        }

        if lockfiles.is_empty() {
            return Err(Error::NoLockfileFound);
        }

        Ok(lockfiles)
    }

    fn parse(path: &Path, ecosystem: Ecosystem) -> Result<Lockfile> {
        let content = fs::read_to_string(path)?;
        let deps = match ecosystem {
            Ecosystem::Npm => Self::parse_npm(&content)?,
            Ecosystem::Cargo => Self::parse_cargo(&content)?,
            Ecosystem::Pip => Self::parse_pip(&content)?,
            _ => return Err(Error::UnsupportedFormat(format!("{:?}", ecosystem))),
        };

        Ok(Lockfile {
            path: path.to_path_buf(),
            ecosystem,
            dependencies: deps,
        })
    }

    fn parse_npm(content: &str) -> Result<Vec<Dependency>> {
        #[derive(Deserialize)]
        struct PackageLock {
            packages: Option<serde_json::Value>,
            dependencies: Option<serde_json::Value>,
        }

        let lock: PackageLock = serde_json::from_str(content)?;
        let mut deps = Vec::new();

        if let Some(packages) = lock.packages {
            if let Some(obj) = packages.as_object() {
                for (key, value) in obj {
                    if key == "" {
                        continue;
                    }
                    if let Some(version) = value.get("version").and_then(|v| v.as_str()) {
                        let name = key.split('/').next().unwrap_or(key).to_string();
                        let transitive = key.contains("node_modules/");
                        deps.push(Dependency {
                            name,
                            version: version.to_string(),
                            ecosystem: Ecosystem::Npm,
                            source: None,
                            transitive,
                            dependencies: Vec::new(),
                        });
                    }
                }
            }
        } else if let Some(deps) = lock.dependencies {
            Self::extract_npm_deps(&deps, &mut deps, false);
        }

        Ok(deps)
    }

    fn extract_npm_deps(value: &serde_json::Value, deps: &mut Vec<Dependency>, transitive: bool) {
        if let Some(obj) = value.as_object() {
            for (name, info) in obj {
                if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                    deps.push(Dependency {
                        name: name.clone(),
                        version: version.to_string(),
                        ecosystem: Ecosystem::Npm,
                        source: None,
                        transitive,
                        dependencies: Vec::new(),
                    });
                }
                if let Some(sub) = info.get("dependencies") {
                    Self::extract_npm_deps(sub, deps, true);
                }
            }
        }
    }

    fn parse_cargo(content: &str) -> Result<Vec<Dependency>> {
        #[derive(Deserialize)]
        struct CargoLock {
            package: Option<Vec<CargoPackage>>,
        }

        #[derive(Deserialize)]
        struct CargoPackage {
            name: String,
            version: String,
            source: Option<String>,
        }

        let lock: CargoLock = serde_json::from_str(content)?;
        let mut deps = Vec::new();

        if let Some(packages) = lock.package {
            for pkg in packages {
                deps.push(Dependency {
                    name: pkg.name,
                    version: pkg.version,
                    ecosystem: Ecosystem::Cargo,
                    source: pkg.source,
                    transitive: true,
                    dependencies: Vec::new(),
                });
            }
        }

        Ok(deps)
    }

    fn parse_pip(content: &str) -> Result<Vec<Dependency>> {
        #[derive(Deserialize)]
        struct PipfileLock {
            default: Option<std::collections::HashMap<String, serde_json::Value>>,
            develop: Option<std::collections::HashMap<String, serde_json::Value>>,
        }

        let lock: PipfileLock = serde_json::from_str(content)?;
        let mut deps = Vec::new();

        let add_section =
            |section: Option<&std::collections::HashMap<String, serde_json::Value>>,
             deps: &mut Vec<Dependency>| {
                if let Some(map) = section {
                    for (name, info) in map {
                        if let Some(version) = info.get("version").and_then(|v| v.as_str()) {
                            deps.push(Dependency {
                                name: name.clone(),
                                version: version.to_string(),
                                ecosystem: Ecosystem::Pip,
                                source: None,
                                transitive: false,
                                dependencies: Vec::new(),
                            });
                        }
                    }
                }
            };

        add_section(lock.default.as_ref(), &mut deps);
        add_section(lock.develop.as_ref(), &mut deps);

        Ok(deps)
    }
}
