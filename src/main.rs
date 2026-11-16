use wpguard::analyze;
use wpguard::baseline::Baseline;
use wpguard::cli::{Cli, Command, OutputFormat, ScanArgs};
use wpguard::config::Config;
use wpguard::report::{self, ScanSummary};
use wpguard::rule::Rule;
use wpguard::rules;
use wpguard::severity::Severity;

use anyhow::{Context as _, Result};
use clap::Parser;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

fn main() -> ExitCode {
    let cli = Cli::parse();
    let outcome = match cli.command {
        Command::Scan(args) => run_scan(*args),
        Command::Rules => run_rules(),
        Command::Explain { rule_id } => run_explain(&rule_id),
    };
    match outcome {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_rules() -> Result<ExitCode> {
    let all = rules::all_rules();
    println!("{:<8} {:<9} {:<9} TITLE", "RULE", "SEVERITY", "CWE");
    for rule in &all {
        let meta = rule.meta();
        let cwe = meta
            .cwe
            .map(|c| format!("CWE-{c}"))
            .unwrap_or_else(|| "-".to_string());
        println!(
            "{:<8} {:<9} {:<9} {}",
            meta.id,
            meta.severity.label(),
            cwe,
            meta.title
        );
    }
    println!();
    println!(
        "{} rules. Run `wpguard explain WP001` for the details of one rule.",
        all.len()
    );
    Ok(ExitCode::SUCCESS)
}

fn run_explain(rule_id: &str) -> Result<ExitCode> {
    let all = rules::all_rules();
    let Some(rule) = all
        .iter()
        .find(|r| r.meta().id.eq_ignore_ascii_case(rule_id))
    else {
        anyhow::bail!("unknown rule `{rule_id}`; run `wpguard rules` to see the list");
    };
    let meta = rule.meta();
    println!("{}  {}", meta.id, meta.title);
    println!("severity:   {}", meta.severity.label());
    println!("confidence: {}", meta.confidence);
    if let Some(cwe) = meta.cwe {
        println!("cwe:        CWE-{cwe}");
    }
    println!();
    println!("{}", meta.description);
    println!();
    println!("how to fix");
    println!("{}", meta.remediation);
    if !meta.references.is_empty() {
        println!();
        println!("references");
        for reference in meta.references {
            println!("  {reference}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn run_scan(args: ScanArgs) -> Result<ExitCode> {
    let started = Instant::now();
    let config = load_config(&args)?;

    let extensions = if config.extensions.is_empty() {
        wpguard::walk::DEFAULT_EXTENSIONS
            .iter()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
    } else {
        config.extensions.clone()
    };
    let mut excludes: Vec<String> = wpguard::walk::DEFAULT_EXCLUDES
        .iter()
        .map(|e| e.to_string())
        .collect();
    excludes.extend(config.exclude_paths.clone());

    let targets = wpguard::walk::collect(&args.paths, &excludes, &extensions)?;

    let mut parsed = Vec::with_capacity(targets.len());
    let mut skipped = 0usize;
    for target in targets {
        let source = match std::fs::read_to_string(&target.file) {
            Ok(source) => source,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        let rel = wpguard::php::parser::relative_path(&target.root, &target.file);
        match wpguard::php::parse_source(source, rel) {
            Ok(file) => parsed.push(file),
            Err(_) => skipped += 1,
        }
    }

    let selected = select_rules(&config, &args);
    let mut findings = analyze::analyze(&parsed, &selected);

    if let Some(threshold) = threshold(&config, &args)? {
        findings.retain(|f| f.severity >= threshold);
    }

    let baseline_path = args.baseline.clone().or_else(|| config.baseline.clone());
    if let Some(path) = &baseline_path {
        let recorded = Baseline::load(path)?;
        findings = wpguard::baseline::filter(findings, &recorded);
    }

    if let Some(path) = &args.write_baseline {
        let recorded = Baseline::from_findings(&findings);
        recorded.save(path)?;
        eprintln!(
            "wrote {} finding(s) to {}",
            recorded.findings.len(),
            path.display()
        );
    }

    let root = args
        .paths
        .first()
        .map(|p| {
            if p.is_dir() {
                p.clone()
            } else {
                p.parent().unwrap_or(Path::new(".")).to_path_buf()
            }
        })
        .unwrap_or_else(|| PathBuf::from("."));

    let summary = ScanSummary {
        root,
        files_scanned: parsed.len(),
        files_skipped: skipped,
        findings,
        elapsed: started.elapsed(),
    };

    let mut buffer = Vec::new();
    match args.format {
        OutputFormat::Console => report::console::write(&mut buffer, &summary)?,
        OutputFormat::Markdown => report::markdown::write(&mut buffer, &summary)?,
        OutputFormat::Json => report::json::write(&mut buffer, &summary)?,
        OutputFormat::Sarif => report::sarif::write(&mut buffer, &summary, &selected)?,
    }

    match &args.output {
        Some(path) => {
            std::fs::write(path, &buffer)
                .with_context(|| format!("could not write {}", path.display()))?;
        }
        None => {
            std::io::stdout().write_all(&buffer)?;
            std::io::stdout().flush()?;
        }
    }

    if args.exit_zero || summary.findings.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Ok(ExitCode::from(1))
    }
}

fn load_config(args: &ScanArgs) -> Result<Config> {
    if let Some(path) = &args.config {
        return Config::load(path);
    }
    for path in &args.paths {
        let root = if path.is_dir() {
            path.clone()
        } else {
            path.parent().unwrap_or(Path::new(".")).to_path_buf()
        };
        if let Some(config) = Config::discover(&root) {
            return Ok(config);
        }
    }
    Ok(Config::default())
}

fn threshold(config: &Config, args: &ScanArgs) -> Result<Option<Severity>> {
    let raw = args.severity.as_deref().or(config.severity.as_deref());
    match raw {
        Some(value) => Ok(Some(
            value
                .parse::<Severity>()
                .map_err(|e| anyhow::anyhow!("{e}"))?,
        )),
        None => Ok(None),
    }
}

fn select_rules(config: &Config, args: &ScanArgs) -> Vec<Box<dyn Rule>> {
    let only_cli = uppercased(&args.rule);
    let only_config = uppercased(&config.rules);
    // An explicit selection on the command line replaces the configured one.
    let only = if only_cli.is_empty() {
        only_config
    } else {
        only_cli
    };
    let mut never = uppercased(&args.exclude);
    for id in uppercased(&config.exclude) {
        if !never.contains(&id) {
            never.push(id);
        }
    }
    rules::all_rules()
        .into_iter()
        .filter(|rule| {
            let id = rule.meta().id.to_uppercase();
            if never.contains(&id) {
                return false;
            }
            if !only.is_empty() {
                return only.contains(&id);
            }
            true
        })
        .collect()
}

fn uppercased(ids: &[String]) -> Vec<String> {
    ids.iter().map(|s| s.to_uppercase()).collect()
}
