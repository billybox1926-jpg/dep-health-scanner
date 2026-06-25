use crate::error::Result;
use crate::Error;
use chrono::{DateTime, Utc};
use colored::Colorize;
use rusqlite::{params, Connection};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

pub struct Cache {
    conn: Arc<Mutex<Connection>>,
    #[allow(dead_code)]
    cache_dir: PathBuf,
}

impl Cache {
    pub fn new(cache_dir: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&cache_dir)?;
        let db_path = cache_dir.join("cache.db");
        let conn = Connection::open(&db_path)?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS registry_versions (
                package TEXT PRIMARY KEY,
                ecosystem TEXT NOT NULL,
                latest_version TEXT NOT NULL,
                last_updated TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id TEXT PRIMARY KEY,
                ecosystem TEXT NOT NULL,
                package TEXT NOT NULL,
                affected TEXT NOT NULL,
                summary TEXT NOT NULL,
                severity REAL,
                cve TEXT,
                fixed_versions TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS github_activity (
                repo TEXT PRIMARY KEY,
                contributors INTEGER,
                last_commit TEXT,
                score INTEGER,
                last_updated TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_vuln_ecosystem ON vulnerabilities(ecosystem);
            CREATE INDEX IF NOT EXISTS idx_vuln_package ON vulnerabilities(package);
        ",
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            cache_dir,
        })
    }

    pub fn new_default() -> Result<Self> {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("dep-health-scanner");
        Self::new(cache_dir)
    }

    pub fn get_latest_version(
        &self,
        ecosystem: &str,
        package: &str,
    ) -> Result<Option<(String, DateTime<Utc>)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT latest_version, last_updated FROM registry_versions WHERE package = ?1 AND ecosystem = ?2"
        )?;
        let result = stmt.query_row(params![package, ecosystem], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        });

        match result {
            Ok((version, ts)) => {
                let dt = DateTime::parse_from_rfc3339(&ts)
                    .map_err(|e| Error::ParseError(e.to_string()))?
                    .with_timezone(&Utc);
                Ok(Some((version, dt)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(Error::Sqlite(e)),
        }
    }

    pub fn set_latest_version(&self, ecosystem: &str, package: &str, version: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO registry_versions (package, ecosystem, latest_version, last_updated) VALUES (?1, ?2, ?3, ?4)",
            params![package, ecosystem, version, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn get_vulnerabilities(
        &self,
        ecosystem: &str,
        package: &str,
    ) -> Result<Vec<VulnerabilityRecord>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare_cached(
            "SELECT id, affected, summary, severity, cve, fixed_versions FROM vulnerabilities WHERE ecosystem = ?1 AND package = ?2"
        )?;
        let rows = stmt.query_map(params![ecosystem, package], |row| {
            Ok(VulnerabilityRecord {
                id: row.get(0)?,
                ecosystem: row.get(1)?,
                package: row.get(2)?,
                affected: row.get(3)?,
                summary: row.get(4)?,
                severity: row.get(5)?,
                cve: row.get(6)?,
                fixed_versions: serde_json::from_str(&row.get::<_, String>(7)?).unwrap_or_default(),
            })
        })?;

        let mut vulns = Vec::new();
        for row in rows {
            vulns.push(row?);
        }
        Ok(vulns)
    }

    pub fn add_vulnerability(&self, vuln: &VulnerabilityRecord) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO vulnerabilities (id, ecosystem, package, affected, summary, severity, cve, fixed_versions) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                vuln.id,
                vuln.ecosystem,
                vuln.package,
                vuln.affected,
                vuln.summary,
                vuln.severity,
                vuln.cve,
                serde_json::to_string(&vuln.fixed_versions).unwrap_or_default(),
            ],
        )?;
        Ok(())
    }

    pub async fn update_all(&self) -> Result<()> {
        // Placeholder: in a real implementation, fetch OSV feeds and registry mirrors
        println!(
            "{}",
            "Cache update would fetch OSV database and registry data here.".yellow()
        );
        Ok(())
    }

    pub fn print_stats(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM registry_versions", [], |row| {
            row.get(0)
        })?;
        let vuln_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| row.get(0))?;
        println!("Cache statistics:");
        println!("  Registry entries: {}", count);
        println!("  Vulnerability records: {}", vuln_count);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct VulnerabilityRecord {
    pub id: String,
    pub ecosystem: String,
    pub package: String,
    pub affected: String,
    pub summary: String,
    pub severity: f32,
    pub cve: Option<String>,
    pub fixed_versions: Vec<String>,
}
