# Configuration

wpguard reads an optional `wpguard.toml` from the directory it is pointed at.
Every setting can be overridden on the command line.

## File format

```toml
# Only report findings at or above this severity.
# One of: low, medium, high, critical.
severity = "medium"

# Only run these rules. Leave this out to run all of them.
rules = ["WP001", "WP003", "WP010"]

# Never run these rules.
exclude = ["WP031"]

# Directories that are skipped while walking the tree. These are matched
# against the directory name and against the path relative to the scan root.
exclude_paths = ["vendor", "node_modules", "build"]

# Which file extensions are scanned. A leading dot is optional.
extensions = [".php", ".inc", ".phtml"]

# A baseline file whose findings are treated as already accepted.
baseline = ".wpguard-baseline.json"
```

## Defaults

| Setting | Default |
|---|---|
| `severity` | every severity is reported |
| `rules` | every rule runs |
| `exclude` | nothing is excluded |
| `exclude_paths` | `vendor`, `node_modules`, `.git`, `.svn`, `.hg`, `.idea`, `.vscode`, `build`, `dist` |
| `extensions` | `.php`, `.inc`, `.phtml` |
| `baseline` | none |

## Command line

| Flag | Meaning |
|---|---|
| `--severity <LEVEL>` | Only report findings at or above this severity. |
| `--rule <RULE_ID>` | Only run this rule. May be given more than once. |
| `--exclude <RULE_ID>` | Never run this rule. May be given more than once. |
| `--config <FILE>` | Read this configuration file instead of discovering one. |
| `--baseline <FILE>` | Treat the findings in this file as accepted. |
| `--write-baseline <FILE>` | Write the current findings to this file. |
| `--format <FORMAT>` | `console`, `markdown`, `json` or `sarif`. |
| `--output <FILE>` | Write the report to a file instead of standard output. |
| `--exit-zero` | Always exit with status 0. |

## Precedence

1. An explicit `--rule` on the command line replaces the configured `rules`
   list entirely.
2. `--exclude` and the configured `exclude` are merged, so a rule can be
   excluded from either place.
3. `--severity` overrides the configured `severity`.
4. `--config` overrides configuration discovery.

## Baselines

A baseline is a JSON file that records the findings a project already knows
about:

```json
{
  "version": 1,
  "generated_at": "unix:1794796800",
  "findings": [
    {
      "fingerprint": "8f3c1a92b7e40d55",
      "rule_id": "WP001",
      "file": "includes/ajax.php",
      "line": 42
    }
  ]
}
```

The fingerprint is derived from the rule, the file, the enclosing function and
the offending code with its whitespace normalised. It does not contain the
line number, so inserting a line above a finding does not bring it back.

To record the current state:

```bash
wpguard scan . --write-baseline .wpguard-baseline.json
```

To report only what is new:

```bash
wpguard scan . --baseline .wpguard-baseline.json
```

Commit the baseline alongside the code. A pull request that fixes a finding
removes it from the report, and a pull request that introduces one shows up
even if it lands on a line that already had something else on it.
