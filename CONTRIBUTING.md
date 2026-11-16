# Contributing to wpguard

Thank you for taking the time. New rules are the most useful contribution, and
the bar for accepting one is deliberately specific.

## Getting set up

You need a stable Rust toolchain. Nothing else, not even PHP.

```bash
git clone https://github.com/Torch4084/wpguard
cd wpguard
cargo build
cargo test
```

The test suite has a positive case and a negative case for every rule. Both
have to exist before a rule is merged.

## Adding a rule

1. **Pick the identifier.** WordPress specific rules use `WP0NN`, generic PHP
   rules use `PHP0NN`. The number is permanent once it is published.
2. **Write the rule** in the matching module under `src/rules/`. A rule is a
   struct that implements the `Rule` trait:

   ```rust
   pub struct MyRule;

   static META: RuleMeta = RuleMeta {
       id: "WP030",
       title: "Short, specific title",
       severity: Severity::Medium,
       confidence: Confidence::High,
       cwe: Some(328),
       description: "What the defect is and why it matters.",
       remediation: "What to do instead, concretely.",
       references: &["https://developer.wordpress.org/..."],
   };

   impl Rule for MyRule {
       fn meta(&self) -> &RuleMeta {
           &META
       }

       fn check(&self, ctx: &Context<'_>) -> Vec<Finding> {
           // ...
       }
   }
   ```

3. **Register it** in `src/rules/mod.rs`.
4. **Test it** in `tests/rules.rs`. Write both cases:

   ```rust
   #[test]
   fn flags_the_defect() {
       assert_fires("WP030", r#"<?php ... vulnerable code ..."#);
   }

   #[test]
   fn accepts_the_correct_code() {
       assert_quiet(&["WP030"], r#"<?php ... correct code ..."#);
   }
   ```

5. **Document it** in `docs/rules.md`.

## Conventions

- **Severity is about impact, not about how easy the code is to write.**
  A missing nonce on a public endpoint is `medium`; a missing capability check
  on an `admin_post_nopriv_` handler is `high`.
- **Confidence is about certainty.** `high` means the rule can see the defect
  directly. `medium` means it inferred something. `low` means it is guessing
  and the reader should check.
- **A rule that can produce false positives must lower its confidence rather
  than stay silent.** A rule that fires on every plugin gets switched off.
- **Fix advice has to be actionable.** "Sanitise the input" is not advice.
  "`wp_check_filetype_and_ext()` before moving the file" is.
- **Reference the official documentation.** Every rule links to at least one
  page under `developer.wordpress.org` or `php.net`.

## Style

Run the formatter and the linter before you push:

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
cargo test
```

## Reporting a false positive

If wpguard reports something that is not a real defect, open an issue with the
rule identifier and a small snippet. False positives are treated as bugs, and
the fixture you provide becomes a regression test.

## Reporting a vulnerability in wpguard

Please do not open a public issue. See [SECURITY.md](SECURITY.md).
