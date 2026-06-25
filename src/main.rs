use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use dep_health_scanner::{
    cache::Cache, dependency::Ecosystem, lockfile::LockfileDetector, reporter::Reporter,
    scanner::Scanner,
};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "depscan")]
#[command(about = "Fast, opinionated dependency health scanner", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to scan (default: current directory)
    #[arg(short, long, global = true)]
    path: Option<PathBuf>,

    /// Output format (text, json)
    #[arg(short, long, global = true, default_value = "text")]
    format: String,

    /// Run quietly (no progress bars)
    #[arg(short, long, global = true)]
    quiet: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan dependencies for health issues (default)
    Scan {
        /// Check bus factor (requires GitHub API)
        #[arg(long)]
        bus_factor: bool,

        /// Suggest lightweight alternatives
        #[arg(long)]
        suggest: bool,

        /// Exit with non-zero code if critical issues found
        #[arg(long)]
        fail_on_critical: bool,

        /// Minimum severity to report (low, medium, high, critical)
        #[arg(long, default_value = "low")]
        min_severity: String,
    },
    /// Update local vulnerability and package caches
    Update,
    /// Show cached statistics
    Stats,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    let cli = Cli::parse();

    let cache = Cache::new_default()?;

    match cli.command {
        Commands::Scan {
            bus_factor,
            suggest,
            fail_on_critical,
            min_severity,
        } => {
            let scan_path = cli.path.unwrap_or_else(|| std::env::current_dir()?);
            let mut scanner = Scanner::new(cache, scan_path);
            scanner
                .configure(bus_factor, suggest, fail_on_critical, min_severity)
                .await?;
            scanner.run().await?;
        }
        Commands::Update => {
            println!("{}", "Updating caches...".cyan().bold());
            cache.update_all().await?;
            println!("{}", "Done!".green().bold());
        }
        Commands::Stats => {
            cache.print_stats()?;
        }
    }

    Ok(())
}
