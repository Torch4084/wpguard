pub mod ast;
pub mod parser;
pub mod project;

pub use parser::{parse_source, PhpFile};
pub use project::{build_index, Callback, Permission, ProjectIndex};

/// A byte range inside a source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn of(node: tree_sitter::Node<'_>) -> Self {
        Span {
            start: node.start_byte(),
            end: node.end_byte(),
        }
    }
}
