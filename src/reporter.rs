use super::dependency::ScanResult;
use colored::Colorize;
use std::collections::HashMap;

pub struct Reporter {
    fail_on_critical: bool,
    #[allow(dead_code)]
    min_severity: String,
}

impl Reporter {
    pub fn new(fail_on_critical: bool, min_severity: String) -> Self {
        Self {
            fail_on_critical,
            min_severity,
        }
    }

    pub fn print_report(&self, results: &[ScanResult]) -> crate::Result<()> {
        if results.is_empty() {
            println!("{}", "No dependencies scanned.".yellow());
            return Ok(());
        }

        let total = results.len();
        let mut count_by_severity = HashMap::new();
        count_by_severity.insert("critical", 0);
        count_by_severity.insert("high", 0);
        count_by_severity.insert("medium", 0);
        count_by_severity.insert("low", 0);
        count_by_severity.insert("vulnerable", 0);
        count_by_severity.insert("outdated", 0);

        let mut critical_found = false;

        // Summary header
        println!(
            "\n{}",
            "═══════════════════════════════════════".cyan().bold()
        );
        println!(
            "{}",
            "       DEPENDENCY HEALTH REPORT        ".cyan().bold()
        );
        println!(
            "{}",
            "═══════════════════════════════════════".cyan().bold()
        );
        println!();

        // Group results by severity
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();
        let mut ok = Vec::new();

        for result in results {
            let severity = self.classify_result(result);
            match severity {
                "critical" => {
                    critical_found = true;
                    critical.push(result);
                    *count_by_severity.get_mut("critical").unwrap() += 1;
                    *count_by_severity.get_mut("vulnerable").unwrap() += 1;
                }
                "high" => {
                    high.push(result);
                    *count_by_severity.get_mut("high").unwrap() += 1;
                    if !result.vulnerabilities.is_empty() {
                        *count_by_severity.get_mut("vulnerable").unwrap() += 1;
                    }
                    if result.outdated {
                        *count_by_severity.get_mut("outdated").unwrap() += 1;
                    }
                }
                "medium" => {
                    medium.push(result);
                    *count_by_severity.get_mut("medium").unwrap() += 1;
                    if result.outdated {
                        *count_by_severity.get_mut("outdated").unwrap() += 1;
                    }
                }
                "low" => {
                    low.push(result);
                    *count_by_severity.get_mut("low").unwrap() += 1;
                    if result.outdated {
                        *count_by_severity.get_mut("outdated").unwrap() += 1;
                    }
                }
                _ => {
                    ok.push(result);
                }
            }
        }

        // Print critical issues first
        if !critical.is_empty() {
            println!("{}", "CRITICAL ISSUES:".red().bold());
            println!();
            for result in &critical {
                self.print_dependency(result, "critical");
            }
            println!();
        }

        // Print high severity
        if !high.is_empty() {
            println!("{}", "HIGH SEVERITY:".red());
            println!();
            for result in &high {
                self.print_dependency(result, "high");
            }
            println!();
        }

        // Print medium severity
        if !medium.is_empty() {
            println!("{}", "MEDIUM SEVERITY:".yellow());
            println!();
            for result in &medium {
                self.print_dependency(result, "medium");
            }
            println!();
        }

        // Print low severity
        if !low.is_empty() {
            println!("{}", "LOW SEVERITY:".yellow());
            println!();
            for result in &low {
                self.print_dependency(result, "low");
            }
            println!();
        }

        // Print summary table
        println!("{}", "───────────────────────────────────────".cyan());
        println!("{}", "SUMMARY".cyan().bold());
        println!("{}", "───────────────────────────────────────".cyan());
        println!(
            "{:<20} {:>6}",
            "Total dependencies:".bold(),
            total.to_string().cyan()
        );
        println!(
            "{:<20} {:>6}",
            "Vulnerable:".bold(),
            count_by_severity["vulnerable"].to_string().red()
        );
        println!(
            "{:<20} {:>6}",
            "Outdated:".bold(),
            count_by_severity["outdated"].to_string().yellow()
        );
        println!(
            "{:<20} {:>6} / {:>6} / {:>6} / {:>6}",
            "By severity:".bold(),
            count_by_severity["critical"].to_string().red(),
            count_by_severity["high"].to_string().red(),
            count_by_severity["medium"].to_string().yellow(),
            count_by_severity["low"].to_string().green()
        );
        println!();

        if self.fail_on_critical && critical_found {
            std::process::exit(1);
        }

        Ok(())
    }

    fn print_dependency(&self, result: &ScanResult, severity: &str) {
        let icon = match severity {
            "critical" => "✖".red().bold(),
            "high" => "✖".red(),
            "medium" => "⚠".yellow(),
            "low" => "ℹ".blue(),
            _ => "✓".green(),
        };

        println!(
            "  {} {}@{} [{}]",
            icon,
            result.dependency.name.cyan(),
            result.dependency.version.dimmed(),
            result.dependency.ecosystem
        );

        if let Some(ref latest) = result.latest_version {
            println!(
                "       {} {} → {}",
                "latest:".dimmed(),
                result.dependency.version.dimmed(),
                latest.green()
            );
        }

        for vuln in &result.vulnerabilities {
            let sev = if vuln.severity >= 9.0 {
                "CRITICAL".red().bold()
            } else if vuln.severity >= 7.0 {
                "HIGH".red()
            } else if vuln.severity >= 4.0 {
                "MEDIUM".yellow()
            } else {
                "LOW".blue()
            };

            println!(
                "       {} {} ({}): {}",
                "vulnerability:".red().bold(),
                vuln.id.cyan(),
                sev,
                vuln.summary
            );

            if !vuln.fixed_versions.is_empty() {
                println!(
                    "              {} in {}",
                    "fixed:".green(),
                    vuln.fixed_versions.join(", ").green()
                );
            }
        }

        if let Some(score) = result.bus_factor_score {
            let score_str = if score < 30 {
                format!("{} (low)", score).red()
            } else if score < 60 {
                format!("{} (medium)", score).yellow()
            } else {
                format!("{} (good)", score).green()
            };
            println!("       {} {}", "bus factor:".dimmed(), score_str);
        }

        if !result.alternatives.is_empty() {
            println!("       {}:", "alternatives".dimmed());
            for alt in &result.alternatives {
                println!(
                    "         - {}@{} (stars: {}, downloads: {})",
                    alt.name.cyan(),
                    alt.version.dimmed(),
                    alt.stars,
                    alt.weekly_downloads
                );
            }
            println!(
                "         {}",
                "run `depscan suggest <package>` for details"
                    .italic()
                    .dimmed()
            );
        }

        println!();
    }

    fn classify_result(&self, result: &ScanResult) -> &'static str {
        if !result.vulnerabilities.is_empty() {
            for vuln in &result.vulnerabilities {
                if vuln.severity >= 9.0 {
                    return "critical";
                }
                if vuln.severity >= 7.0 {
                    return "high";
                }
            }
            return "medium";
        }

        if let Some(score) = result.bus_factor_score {
            if score < 30 {
                return "high";
            }
        }

        if result.outdated {
            return "low";
        }

        "ok"
    }
}
