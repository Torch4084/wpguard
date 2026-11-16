//! End to end tests that drive the `wpguard` binary the way a user would.

use assert_cmd::Command;
use predicates::prelude::*;
use predicates::str::contains;
use std::path::PathBuf;

fn binary() -> Command {
    Command::cargo_bin("wpguard").expect("the wpguard binary should be built")
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

#[test]
fn reports_findings_and_exits_with_one() {
    binary()
        .args(["scan", fixture("vulnerable-plugin").to_str().unwrap()])
        .assert()
        .code(1)
        .stdout(contains("WP001"))
        .stdout(contains("WP010"))
        .stdout(contains("Unauthenticated AJAX action"));
}

#[test]
fn stays_quiet_on_a_correct_plugin() {
    binary()
        .args(["scan", fixture("clean-plugin").to_str().unwrap()])
        .assert()
        .code(0)
        .stdout(contains("No issues found"));
}

#[test]
fn emits_valid_json() {
    let output = binary()
        .args([
            "scan",
            fixture("vulnerable-plugin").to_str().unwrap(),
            "--format",
            "json",
        ])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    let document: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    assert_eq!(document["tool"], "wpguard");
    assert!(document["finding_count"].as_u64().unwrap() > 0);
    let first = &document["findings"][0];
    assert!(first["rule_id"].is_string());
    assert!(first["fingerprint"].is_string());
    assert!(first["file"].is_string());
}

#[test]
fn emits_valid_sarif() {
    let output = binary()
        .args([
            "scan",
            fixture("vulnerable-plugin").to_str().unwrap(),
            "--format",
            "sarif",
        ])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let text = String::from_utf8(output).unwrap();
    let document: serde_json::Value = serde_json::from_str(&text).expect("valid SARIF");
    assert_eq!(document["version"], "2.1.0");
    assert_eq!(document["runs"][0]["tool"]["driver"]["name"], "wpguard");
    assert!(
        document["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .len()
            > 5
    );
    let result = &document["runs"][0]["results"][0];
    assert!(result["ruleId"].is_string());
    assert!(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].is_string());
}

#[test]
fn filters_by_severity() {
    binary()
        .args([
            "scan",
            fixture("vulnerable-plugin").to_str().unwrap(),
            "--severity",
            "high",
        ])
        .assert()
        .code(1)
        .stdout(contains("WP001"))
        .stdout(contains("WP010"))
        .stdout(contains("WP005").not());
}

#[test]
fn runs_only_the_requested_rules() {
    binary()
        .args([
            "scan",
            fixture("vulnerable-plugin").to_str().unwrap(),
            "--rule",
            "WP010",
        ])
        .assert()
        .code(1)
        .stdout(contains("WP010"))
        .stdout(contains("WP001").not());
}

#[test]
fn skips_the_excluded_rules() {
    binary()
        .args([
            "scan",
            fixture("vulnerable-plugin").to_str().unwrap(),
            "--exclude",
            "WP001",
            "--exclude",
            "WP002",
        ])
        .assert()
        .code(1)
        .stdout(contains("WP010"))
        .stdout(contains("WP001").not());
}

#[test]
fn exit_zero_keeps_the_status_code_success() {
    binary()
        .args([
            "scan",
            fixture("vulnerable-plugin").to_str().unwrap(),
            "--exit-zero",
        ])
        .assert()
        .code(0)
        .stdout(contains("WP001"));
}

#[test]
fn writes_a_report_to_a_file() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("report.md");
    binary()
        .args([
            "scan",
            fixture("vulnerable-plugin").to_str().unwrap(),
            "--format",
            "markdown",
            "--output",
            target.to_str().unwrap(),
        ])
        .assert()
        .code(1);
    let written = std::fs::read_to_string(&target).unwrap();
    assert!(written.contains("# wpguard report"));
    assert!(written.contains("WP001"));
}

#[test]
fn a_baseline_hides_findings_that_are_already_known() {
    let directory = tempfile::tempdir().unwrap();
    let baseline = directory.path().join("baseline.json");

    binary()
        .args([
            "scan",
            fixture("vulnerable-plugin").to_str().unwrap(),
            "--write-baseline",
            baseline.to_str().unwrap(),
        ])
        .assert()
        .code(1);

    assert!(baseline.exists());
    let recorded = std::fs::read_to_string(&baseline).unwrap();
    assert!(recorded.contains("WP001"));

    binary()
        .args([
            "scan",
            fixture("vulnerable-plugin").to_str().unwrap(),
            "--baseline",
            baseline.to_str().unwrap(),
        ])
        .assert()
        .code(0)
        .stdout(contains("No issues found"));
}

#[test]
fn lists_every_rule() {
    binary()
        .arg("rules")
        .assert()
        .code(0)
        .stdout(contains("WP001"))
        .stdout(contains("WP010"))
        .stdout(contains("PHP001"))
        .stdout(contains("CWE-352"));
}

#[test]
fn explains_a_single_rule() {
    binary()
        .args(["explain", "WP010"])
        .assert()
        .code(0)
        .stdout(contains("WP010"))
        .stdout(contains("prepared"))
        .stdout(contains("https://"));
}

#[test]
fn fails_on_an_unknown_rule() {
    binary()
        .args(["explain", "NOPE"])
        .assert()
        .code(1)
        .stderr(contains("unknown rule"));
}

#[test]
fn fails_when_the_path_does_not_exist() {
    binary()
        .args(["scan", "does/not/exist"])
        .assert()
        .code(1)
        .stderr(contains("does not exist"));
}
