use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

/// Static security analyzer for WordPress plugins and themes.
#[derive(Debug, Parser)]
#[command(
    name = "wpguard",
    version,
    about = "Static security analyzer for WordPress plugins and themes",
    long_about = "wpguard parses PHP source with a real grammar and reports WordPress specific \
                  security defects: missing authorization, SQL injection, unsafe deserialization, \
                  unescaped output and more.\n\n\
                  It never runs the code it inspects, needs no WordPress installation and never \
                  sends anything off the machine."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan files or directories for security issues.
    Scan(Box<ScanArgs>),
    /// List every rule that ships with wpguard.
    Rules,
    /// Explain a single rule in detail.
    Explain {
        /// The rule identifier, for example WP001.
        rule_id: String,
    },
}

/// Output formats understood by the scan command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human readable, coloured output for a terminal.
    Console,
    /// A Markdown report.
    Markdown,
    /// Machine readable JSON.
    Json,
    /// SARIF 2.1.0, for GitHub code scanning.
    Sarif,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Files or directories to scan.
    #[arg(required = true)]
    pub paths: Vec<PathBuf>,

    /// Output format.
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Console)]
    pub format: OutputFormat,

    /// Write the report to this file instead of standard output.
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Only report findings at or above this severity.
    #[arg(short, long, value_name = "LEVEL")]
    pub severity: Option<String>,

    /// Only run these rules. May be given more than once.
    #[arg(long, value_name = "RULE_ID")]
    pub rule: Vec<String>,

    /// Never run these rules. May be given more than once.
    #[arg(long, value_name = "RULE_ID")]
    pub exclude: Vec<String>,

    /// Configuration file to read.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Findings recorded in this baseline are not reported.
    #[arg(long, value_name = "FILE")]
    pub baseline: Option<PathBuf>,

    /// Write the current findings to this baseline file.
    #[arg(long, value_name = "FILE")]
    pub write_baseline: Option<PathBuf>,

    /// Always exit with status 0, even when findings were reported.
    #[arg(long)]
    pub exit_zero: bool,
}
