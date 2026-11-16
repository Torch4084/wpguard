# Architecture

wpguard is a library with a thin binary on top. The library lives in `src/`
and the binary only parses arguments, calls the library and writes the result.

```
src/
  lib.rs        the library root
  main.rs       the command line interface
  cli.rs        argument definitions
  analyze.rs    the analysis driver and the context rules query
  finding.rs    the Finding type and the fingerprint function
  rule.rs       the Rule trait and RuleMeta
  severity.rs   severity and confidence
  taint.rs      taint tracking, the heart of the data flow rules
  baseline.rs   reading and writing baselines
  config.rs     wpguard.toml
  walk.rs       finding the files to scan
  php/
    parser.rs   parsing a file into a PhpFile
    ast.rs      helpers over the tree-sitter nodes
    project.rs  the project index
  rules/
    mod.rs      the rule registry
    access_control.rs
    injection.rs
    files.rs
    crypto.rs
    php_generic.rs
  report/
    mod.rs      the ScanSummary
    console.rs
    markdown.rs
    json.rs
    sarif.rs
```

## The three phases

### 1. Parse

`php::parse_source` hands the file to a tree-sitter parser configured with the
official PHP grammar. The result is a `PhpFile`, which owns the source text
and the syntax tree.

Nothing is executed. A file with a syntax error still produces a tree; the
parts that parsed are still analysed, and the file is only skipped if it cannot
be read at all.

### 2. Index

Before any rule runs, `php::build_index` walks every file once and records:

- every global function, keyed by name, with the span of its body,
- every method, keyed by `(class, method)`,
- every `add_action` and `add_filter` registration, with the hook name and the
  callback behind it,
- every `register_rest_route` call, with its namespace, its route and the
  permission model it declared,
- every admin page registration, with the capability it asked for.

The callback behind a hook can be a named function, a method on the current
class, a method on a named class, or a closure. All four are resolved into the
same `Callback` type, so a rule does not care which form was used.

This is why the analyzer can say "the handler for `wp_ajax_nopriv_import` does
not check anything" rather than "there is a call near line 17". The rule asks
the index for the handler, and the index knows where it lives.

### 3. Analyse

Each rule receives a `Context`, which gives it the parsed files, the index, and
a few conveniences such as resolving a byte span back into a node and finding
the enclosing function.

Rules are deliberately simple. A typical rule walks the calls in a file, asks
the index a question, and turns the answer into findings.

## Taint tracking

`taint.rs` holds the small amount of data flow analysis wpguard does.

- `tainted_variables` collects the variables in a scope that were assigned
  straight from a superglobal. It is one assignment hop deep on purpose:
  `$raw = $_POST['x']; unserialize( $raw );` is caught, and nothing pretends
  to be a full data flow engine.
- `is_tainted` decides whether an expression carries attacker controlled data,
  either directly from a superglobal or through one of those variables.
- `is_escaped` checks whether the tainted part of an expression was routed
  through an escaping function. It looks at the arguments of the escaping call
  rather than the expression as a whole, so `esc_html( $_GET['a'] ) .
  $_GET['b']` is still reported.

## Call resolution

`analyze::handler_is_protected` and `analyze::handler_has_nonce` answer the
question the access control rules ask.

1. Resolve the callback through the index.
2. Walk the calls in the handler body, ignoring calls that belong to a nested
   named function, because those are a separate scope.
3. If a call matches an authorization or nonce marker, the handler is
   protected.
4. Otherwise, follow the global functions the handler calls, one level deep,
   and repeat.

The markers are the WordPress functions that actually mean something:
`current_user_can`, `is_user_logged_in`, `check_ajax_referer`,
`wp_verify_nonce`, `check_admin_referer` and a handful more. The list lives in
`analyze.rs` next to the code that uses it.

## Fingerprints

A finding is identified by a fingerprint built from the rule, the file, the
enclosing symbol and the offending code with whitespace normalised. The line
number is deliberately not part of it, so a baseline survives edits that shift
code around.

The hash is FNV-1a, implemented in `finding.rs`. It is small, stable across
runs and platforms, and needs no dependency. It is not a cryptographic hash
and is not meant to be one; it only has to be reproducible.

## Adding a format

A reporter is a function that takes the `ScanSummary` and writes to an
implementor of `Write`. `report/sarif.rs` additionally takes the selected
rules so that it can describe them. Add the format to the `OutputFormat` enum
in `cli.rs` and to the match in `main.rs`.
