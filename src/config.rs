use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

/// The name of the configuration file wpguard looks for.
pub const CONFIG_FILE: &str = "wpguard.toml";

/// Optional configuration, normally in `wpguard.toml` next to the plugin.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    /// Only report findings at or above this severity.
    #[serde(default)]
    pub severity: Option<String>,
    /// Only run these rules.
    #[serde(default)]
    pub rules: Vec<String>,
    /// Never run these rules.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Directories that are skipped while walking the tree.
    #[serde(default)]
    pub exclude_paths: Vec<String>,
    /// File extensions that are scanned.
    #[serde(default)]
    pub extensions: Vec<String>,
    /// A baseline file whose findings are treated as accepted.
    #[serde(default)]
    pub baseline: Option<PathBuf>,
}

impl Config {
    /// Read a configuration file.
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("could not read config {}", path.display()))?;
        let config: Config = toml::from_str(&text)
            .with_context(|| format!("could not parse config {}", path.display()))?;
        Ok(config)
    }

    /// Look for a configuration file in the given directory.
    pub fn discover(root: &Path) -> Option<Config> {
        let candidate = root.join(CONFIG_FILE);
        if candidate.is_file() {
            Config::load(&candidate).ok()
        } else {
            None
        }
    }
}
