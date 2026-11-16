//! wpguard — a static security analyzer for WordPress plugins and themes.
//!
//! The crate is split into a library and a thin binary so that the analysis
//! can be embedded in other tools and tested in isolation.

pub mod analyze;
pub mod baseline;
pub mod cli;
pub mod config;
pub mod finding;
pub mod php;
pub mod report;
pub mod rule;
pub mod rules;
pub mod severity;
pub mod taint;
pub mod walk;

/// The version of the tool.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
