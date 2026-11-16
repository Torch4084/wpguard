<h1 align="center">wpguard</h1>

<p align="center">
  <b>A static security analyzer for WordPress plugins and themes.</b><br>
  Point it at a plugin. It tells you whether a logged out visitor can make it do
  something they should not be allowed to do.
</p>

<p align="center">
  <a href="#install"><img alt="install" src="https://img.shields.io/badge/install-cargo%20install%20wpguard-ff7700?style=flat-square"></a>
  <a href="#rules"><img alt="rules" src="https://img.shields.io/badge/rules-19-ff7700?style=flat-square"></a>
  <a href="#github-action"><img alt="action" src="https://img.shields.io/badge/GitHub%20Action-ready-ff7700?style=flat-square"></a>
  <img alt="license" src="https://img.shields.io/badge/license-MIT-ff7700?style=flat-square">
  <img alt="ci" src="https://github.com/Torch4084/wpguard/actions/workflows/ci.yml/badge.svg">
</p>

---

## The problem

The WordPress plugin ecosystem is enormous, and almost none of it gets reviewed.
A plugin is a PHP file that a stranger uploaded, which then runs inside the
admin panel of the site you care about. When a plugin gets reviewed, it is
usually by hand, and usually only after something has already gone wrong.

The tools that exist today fall into two groups. The first is `PHP_CodeSniffer`
with the WordPress standard, which enforces *style*. The second is scanners that
match regular expressions against the file looking for `eval(` or `unserialize(`.
Both miss the defect that matters most in WordPress, which is not a dangerous
function call but a **missing check**: an AJAX handler that never verifies who
is calling it, a REST route registered with `__return_true`, an `admin_post`
action with no capability check.

wpguard parses PHP with a real grammar and reasons about the *relationships*
between a hook, the callback behind it, and what that callback does.

```
$ wpguard scan acme-forms/

acme-forms.php
  17:3  HIGH  WP001  Unauthenticated AJAX action without a nonce check
    add_action( 'wp_ajax_nopriv_acme_import', array( $this, 'handle_import' ) );
    `acme_import` is registered for unauthenticated visitors and its handler does
    not verify a nonce, so any third party site can trigger it.
    in Acme_Forms::register
    CWE-352 · confidence medium
    fix: Call `check_ajax_referer( 'my-action', 'nonce' )` at the top of the handler,
    and require a capability with `current_user_can()` if the action should only be
    available to logged in users.
```

## What it looks for

| Rule | Severity | CWE | What it catches |
|---|---|---|---|
| `WP001` | high | CWE-352 | `wp_ajax_nopriv_*` action with no nonce check |
| `WP002` | medium | CWE-352 | `wp_ajax_*` action with no nonce check |
| `WP003` | high | CWE-862 | REST route with `permission_callback => '__return_true'` |
| `WP004` | medium | CWE-862 | REST route with no `permission_callback` at all |
| `WP005` | low | CWE-862 | Admin menu page registered with `read` or no capability |
| `WP006` | high | CWE-862 | `admin_post` handler with no capability check |
| `WP007` | medium | CWE-862 | REST permission callback that checks no capability |
| `WP010` | high | CWE-89 | `$wpdb` query built without `prepare()` |
| `WP011` | high | CWE-502 | `unserialize()` on request data |
| `WP012` | high | CWE-95 | `eval()`, `assert()`, `create_function()` |
| `WP013` | high | CWE-98 | `include` / `require` with a runtime path |
| `WP014` | medium | CWE-79 | Request data echoed without escaping |
| `WP015` | medium | CWE-601 | `wp_redirect()` to a request controlled URL |
| `WP020` | high | CWE-434 | `move_uploaded_file()` with no file type check |
| `WP021` | medium | CWE-918 | Server side request to a request controlled URL |
| `WP030` | medium | CWE-328 | `md5()` / `sha1()` used on a password |
| `WP031` | medium | CWE-338 | `rand()` used to build a secret |
| `PHP001` | high | CWE-78 | Shell command built at runtime |
| `PHP002` | high | CWE-295 | `CURLOPT_SSL_VERIFYPEER` switched off |

Run `wpguard rules` for the list, `wpguard explain WP001` for the full detail
of one rule including how to fix it and where to read more.

## Install

```bash
cargo install --locked wpguard
```

Or grab a prebuilt binary for Linux, macOS and Windows from the
[releases page](https://github.com/Torch4084/wpguard/releases).

There is no runtime dependency: no PHP, no WordPress, no Node. The analyzer is a
single static binary and it never executes the code it inspects.

## Use

```bash
# Scan a plugin directory
wpguard scan ~/plugins/acme-forms/

# Scan a single file
wpguard scan includes/ajax.php

# Only the serious stuff
wpguard scan . --severity high

# Only one rule
wpguard scan . --rule WP010 --rule WP011

# Machine readable output
wpguard scan . --format json
wpguard scan . --format sarif --output results.sarif
wpguard scan . --format markdown --output report.md
```

`wpguard` exits with status `1` when it reports a finding, so it drops straight
into a CI pipeline. Pass `--exit-zero` if you would rather not fail the build.

## GitHub Action

The SARIF output uploads straight to GitHub code scanning, so findings show up
as annotations on the pull request that introduced them.

```yaml
name: wpguard
on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  wpguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Torch4084/wpguard@v1
        with:
          path: .
          severity: medium
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: wpguard.sarif
```

The action writes `wpguard.sarif` into the workspace.

## Configuration

Drop a `wpguard.toml` next to your plugin:

```toml
# Only report findings at or above this severity.
severity = "medium"

# Never run these rules.
exclude = ["WP031"]

# Skip these directories while walking the tree.
exclude_paths = ["vendor", "build"]

# Which file extensions to scan.
extensions = [".php", ".inc"]
```

Command line flags always win over the configuration file. See
[docs/configuration.md](docs/configuration.md) for the full reference.

## Baselines

Legacy plugins are not going to be clean on day one. Record what you already
know about, and let the tool report only what is new:

```bash
wpguard scan . --write-baseline .wpguard-baseline.json
wpguard scan . --baseline .wpguard-baseline.json
```

The baseline is keyed by a fingerprint of the rule, the file, the enclosing
function and the code itself, so it survives refactoring and unrelated edits
shifting line numbers around.

## How it works

1. **Parse.** PHP is parsed with [tree-sitter](https://tree-sitter.github.io/)
   using the official PHP grammar. No PHP runtime, no `eval`, and a parse error
   in one file never stops the scan.
2. **Index.** Before any rule runs, wpguard builds a map of the project: every
   global function, every method, every hook registration, every REST route and
   every admin page, with the callback behind each one.
3. **Analyse.** Rules query that index. When a rule asks whether a handler is
   protected, wpguard resolves the callback, whether that is a named function, a
   method, or a closure, and looks for an authorization or nonce check inside
   it, following one level of delegation into helper functions.
4. **Report.** Findings carry a severity, a confidence, a CWE, the enclosing
   symbol and a concrete fix. They can be rendered as a terminal report,
   Markdown, JSON or SARIF.

More detail in [docs/architecture.md](docs/architecture.md).

## Design principles

- **Never execute the code.** wpguard parses PHP, it does not run it. A
  malicious plugin cannot attack the analyzer.
- **Never phone home.** There is no telemetry, no update check and no network
  access at all. Everything happens on your machine.
- **False positives are worse than false negatives.** A linter people turn off is
  worthless. Where wpguard is not sure, it lowers the confidence rather than
  guessing, and it says so in the report.
- **Every finding is actionable.** A report that says "this is bad" without
  saying what to do instead is not finished.

## Contributing

Contributions are welcome, especially new rules. See
[CONTRIBUTING.md](CONTRIBUTING.md) for how to add a rule, and
[docs/rules.md](docs/rules.md) for the conventions the existing ones follow.

## Security

Found a vulnerability in wpguard itself? Please report it privately rather than
opening a public issue. See [SECURITY.md](SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
