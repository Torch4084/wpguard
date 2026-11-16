# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-16

The first release.

### Added

- A static analyzer for WordPress plugins and themes, written in Rust with no
  runtime dependencies.
- PHP parsing through the official tree-sitter grammar. The code under analysis
  is never executed.
- A project index that resolves every hook registration, REST route and admin
  page to the callback behind it, whether that callback is a named function, a
  class method or a closure.
- Nineteen rules covering broken access control, injection, unsafe
  deserialization, unescaped output, file handling, weak cryptography and
  generic PHP hazards. Each one maps to a CWE and carries a concrete fix.
- Four output formats: a coloured terminal report, Markdown, JSON and SARIF
  2.1.0 for GitHub code scanning.
- Baselines, so that an existing codebase can record the findings it already
  knows about and be warned only about new ones.
- A `wpguard.toml` configuration file, and command line flags that override it.
- A reusable GitHub Action that runs the analyzer and writes `wpguard.sarif`.

[0.1.0]: https://github.com/Torch4084/wpguard/releases/tag/v0.1.0
