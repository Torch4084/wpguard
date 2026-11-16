# Rules

Every rule has an identifier that never changes, a severity that reflects the
impact of the defect, a confidence that reflects how sure the analyzer is, and
a CWE that says what kind of defect it is.

## How severity is chosen

Severity answers "what happens if this is exploited". It does not answer "how
hard is it to reach".

| Severity | Meaning |
|---|---|
| `critical` | Remote code execution or full compromise with no precondition. |
| `high` | Privilege escalation, arbitrary file write, or an unauthenticated attacker reaching an action that should be restricted. |
| `medium` | Cross-site scripting, information disclosure, or a forged request that a logged in user can be tricked into sending. |
| `low` | A hardening gap. Worth fixing, not worth an emergency. |

## How confidence is chosen

Confidence answers "how sure is the analyzer". Where a rule has to infer
something, it lowers its confidence rather than staying quiet.

| Confidence | Meaning |
|---|---|
| `high` | The defect is visible directly in the code the rule is looking at. |
| `medium` | The rule inferred the relationship, for example that a callback is unprotected. |
| `low` | The rule is matching on a name or a keyword and could easily be wrong. |

## The rules

### WP001 — Unauthenticated AJAX action without a nonce check

*High, confidence medium, CWE-352*

An action registered under `wp_ajax_nopriv_` can be triggered by a visitor who
is not logged in. When the handler does not verify a nonce, the request is not
tied to a legitimate visit to the site, so another website can trigger it from
the visitor's browser.

wpguard resolves the callback, looks inside it, and follows one level of
delegation into helper functions before deciding.

**Fix:** call `check_ajax_referer( 'my-action', 'nonce' )` at the top of the
handler, and require a capability with `current_user_can()` if the action is
not meant to be public.

### WP002 — Authenticated AJAX action without a nonce check

*Medium, confidence medium, CWE-352*

The same problem for `wp_ajax_*`. A capability check stops unprivileged users
but it does not stop a third party site from replaying the request with the
victim's cookies, so the two checks are not interchangeable.

**Fix:** verify a nonce in addition to the capability check.

### WP003 — REST route is open to everyone

*High, confidence medium, CWE-862*

`permission_callback` is set to `__return_true`, which tells WordPress that
anybody may call the route.

**Fix:** replace it with a callback that checks a capability.

### WP004 — REST route registered without a permission callback

*Medium, confidence high, CWE-862*

`register_rest_route()` was called with no `permission_callback`. Recent
WordPress versions reject the registration outright and older ones fall back
to allowing the request.

**Fix:** add a `permission_callback` to the route arguments.

### WP005 — Admin page registered with a weak capability

*Low, confidence high, CWE-862*

The page is registered with `read`, or with no capability at all, so every
logged in subscriber can open it.

**Fix:** register the page with a capability that matches what the page does.

### WP006 — admin_post handler without a capability check

*High for `admin_post_nopriv_`, medium for `admin_post_`, confidence medium,
CWE-862*

`admin_post` handlers are reached by ordinary page requests. Without a
capability check the action runs for anyone who can trigger a request, which
for the `nopriv` variant means any visitor at all.

**Fix:** check `current_user_can()` inside the handler and abort with
`wp_die()`.

### WP007 — REST route permission callback does not check a capability

*Medium, confidence low, CWE-862*

The route has a permission callback, but the callback contains no capability
check. A callback that always returns true behaves exactly like no callback,
and one that only inspects the request may still let unprivileged callers
through.

**Fix:** check a capability inside the callback and return a `WP_Error` when
the caller is not allowed.

### WP010 — Database query built without prepared statements

*High, confidence high, CWE-89*

A value is concatenated into a SQL statement instead of being bound as a
parameter. When the value comes from the request, this is SQL injection.

wpguard reports the query as `medium` with `medium` confidence when it cannot
prove the value is attacker controlled.

**Fix:** use `$wpdb->prepare()`.

### WP011 — unserialize() applied to request data

*High, confidence high, CWE-502*

`unserialize()` turns a string back into a PHP object. When the string came
from the request, the attacker chooses the class that gets instantiated.

wpguard follows one assignment hop, so `$raw = $_POST['x']; unserialize(
$raw );` is caught as well.

**Fix:** use `json_decode()`, or `unserialize( $value, [ 'allowed_classes' =>
false ] )`.

### WP012 — Dynamic code evaluation

*High, confidence high, CWE-95*

`eval()`, `assert()` and `create_function()` execute PHP built at runtime.

**Fix:** use an explicit dispatch table.

### WP013 — File inclusion with a dynamic path

*High, confidence medium, CWE-98*

The path handed to `include` or `require` is only known at runtime.

**Fix:** build the path from a fixed set of known files and check it with
`realpath()` against a directory you control.

### WP014 — Request data echoed without escaping

*Medium, confidence high, CWE-79*

A value from the request is written into the response without going through an
escaping function. wpguard only reports the value when it is not routed
through `esc_*`, `wp_kses_*` or `sanitize_*`, and it looks at the arguments of
the escaping call so that `esc_html( $_GET['a'] ) . $_GET['b']` is still
reported.

**Fix:** use `esc_html()`, `esc_attr()`, `esc_url()` or `wp_kses()`.

### WP015 — Redirect to a request controlled URL

*Medium, confidence high, CWE-601*

The redirect target comes from the request, so an attacker can send a visitor
somewhere else using a link that looks like it belongs to the site.

**Fix:** use `wp_safe_redirect()`.

### WP020 — Uploaded file stored without a type check

*High, confidence medium, CWE-434*

The file is moved into place without confirming that it is an allowed type.

**Fix:** check the type with `wp_check_filetype_and_ext()` before moving it.

### WP021 — Server side request to a request controlled URL

*Medium, confidence medium, CWE-918*

The URL the server fetches is taken from the request, so the server can be
pointed at internal addresses.

**Fix:** validate the host against an allow list and reject private and link
local addresses.

### WP030 — Password hashed with a fast, unsalted algorithm

*Medium, confidence medium, CWE-328*

`md5()` and `sha1()` are designed to be fast, which is exactly wrong for
passwords.

**Fix:** use `wp_hash_password()` and `wp_check_password()`.

### WP031 — Security sensitive value generated with a weak random source

*Medium, confidence low, CWE-338*

`rand()` and `mt_rand()` are a linear congruential generator, and the sequence
is predictable.

**Fix:** use `random_bytes()`, `wp_generate_password()` or
`wp_generate_uuid4()`.

### PHP001 — Shell command built at runtime

*High, confidence medium, CWE-78*

The command is built at runtime and passed to a shell.

**Fix:** use `escapeshellarg()` on every value, and prefer a library function
over shelling out.

### PHP002 — TLS certificate verification disabled

*High, confidence high, CWE-295*

`CURLOPT_SSL_VERIFYPEER` is `false`, or `CURLOPT_SSL_VERIFYHOST` is `0`.

**Fix:** leave both at their defaults.
