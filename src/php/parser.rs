use anyhow::{anyhow, Result};
use std::path::Path;
use tree_sitter::{Node, Parser, Tree};
/// A parsed PHP source file together with everything the analyzer needs to
/// reason about it.
pub struct PhpFile {
    /// Path relative to the scan root, always with forward slashes.
    pub rel: String,
    /// Full file contents.
    pub source: String,
    /// Parsed syntax tree.
    pub tree: Tree,
}

impl PhpFile {
    /// The source line (1-based) that `node` starts on.
    #[allow(dead_code)]
    pub fn line_of(&self, node: Node<'_>) -> usize {
        node.start_position().row + 1
    }
}

/// Parse PHP source text into a [`PhpFile`].
pub fn parse_source(source: String, rel: String) -> Result<PhpFile> {
    let language: tree_sitter::Language = tree_sitter_php::LANGUAGE_PHP.into();
    let mut parser = Parser::new();
    parser
        .set_language(&language)
        .map_err(|e| anyhow!("could not load the PHP grammar: {e}"))?;
    let tree = parser
        .parse(&source, None)
        .ok_or_else(|| anyhow!("could not parse {rel}"))?;
    Ok(PhpFile { rel, source, tree })
}

/// Build a path relative to `root`, using forward slashes so that output is
/// identical on every platform.
pub fn relative_path(root: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(root).unwrap_or(path);
    rel.components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}
