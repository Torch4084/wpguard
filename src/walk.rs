use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Directories that are skipped by default. Third party code is not the
/// plugin author's code, and it produces noise.
pub const DEFAULT_EXCLUDES: &[&str] = &[
    "vendor",
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    ".idea",
    ".vscode",
    "build",
    "dist",
];

/// The file extensions that are scanned by default.
pub const DEFAULT_EXTENSIONS: &[&str] = &[".php", ".inc", ".phtml"];

/// A file that will be scanned, together with the root its path is relative to.
pub struct Target {
    pub root: PathBuf,
    pub file: PathBuf,
}

/// Collect every file to scan from the given paths.
pub fn collect(
    paths: &[PathBuf],
    exclude: &[String],
    extensions: &[String],
) -> Result<Vec<Target>> {
    let mut out = Vec::new();
    for path in paths {
        if path.is_file() {
            let root = path.parent().unwrap_or(Path::new(".")).to_path_buf();
            out.push(Target {
                root,
                file: path.clone(),
            });
        } else if path.is_dir() {
            walk(path, path, exclude, extensions, &mut out)?;
        } else {
            return Err(anyhow::anyhow!("{} does not exist", path.display()));
        }
    }
    out.sort_by(|a, b| a.file.cmp(&b.file));
    out.dedup_by(|a, b| a.file == b.file);
    Ok(out)
}

fn walk(
    root: &Path,
    dir: &Path,
    exclude: &[String],
    extensions: &[String],
    out: &mut Vec<Target>,
) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("could not read directory {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            if is_excluded(&name, &path, exclude) {
                continue;
            }
            walk(root, &path, exclude, extensions, out)?;
        } else if file_type.is_file() && has_wanted_extension(&path, extensions) {
            out.push(Target {
                root: root.to_path_buf(),
                file: path,
            });
        }
    }
    Ok(())
}

/// Is this directory skipped?
///
/// An entry matches when its name equals the exclude pattern, or when the
/// path relative to the root starts with it.
fn is_excluded(name: &str, path: &Path, exclude: &[String]) -> bool {
    exclude.iter().any(|pattern| {
        if pattern.is_empty() {
            return false;
        }
        if name == pattern {
            return true;
        }
        let normalized = pattern.replace('\\', "/").trim_end_matches('/').to_string();
        path.to_string_lossy()
            .replace('\\', "/")
            .contains(&normalized)
    })
}

fn has_wanted_extension(path: &Path, extensions: &[String]) -> bool {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();
    extensions.iter().any(|ext| {
        let ext = ext.trim().to_lowercase();
        if ext.is_empty() {
            return false;
        }
        if name.ends_with(&ext) {
            return true;
        }
        // A bare extension such as "php" should also match.
        let bare = ext.trim_start_matches('.');
        !bare.is_empty() && name.ends_with(&format!(".{bare}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_extensions_with_or_without_a_dot() {
        let extensions = vec!["php".to_string(), ".inc".to_string()];
        assert!(has_wanted_extension(
            Path::new("a/b/plugin.php"),
            &extensions
        ));
        assert!(has_wanted_extension(
            Path::new("a/b/plugin.inc"),
            &extensions
        ));
        assert!(!has_wanted_extension(
            Path::new("a/b/plugin.js"),
            &extensions
        ));
    }

    #[test]
    fn excludes_by_directory_name() {
        let exclude = vec!["vendor".to_string()];
        assert!(is_excluded("vendor", Path::new("/a/vendor"), &exclude));
        assert!(!is_excluded("src", Path::new("/a/src"), &exclude));
    }
}
