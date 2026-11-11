# Target authentication with session refresh

ONIOPS probes a target's access-control boundaries by replaying the same request as
different identities: anonymous, a low-privilege user (A), a peer user (B) and an
admin. Each identity is carried by one HTTP header
(`auth_header` / `low_priv_header` / `peer_auth_header`, mapping to the roles
`primary` / `low_priv` / `peer`).

A fixed header string breaks on two real targets:

- **Short-lived tokens.** VAmPI issues JWTs that expire in about 60 seconds. A
  token minted before a scan is dead by the time the per-endpoint access-control
  probe runs, so the low-priv/peer differential silently collapses into
  anonymous requests.
- **Form logins.** Apps like DVWA need a login round-trip (fetch a CSRF token,
  POST credentials, capture a session cookie) that a static header cannot do.

The `target_auth` config block adds per-role **login recipes** and a session that
can re-mint a role's header. Every request a login makes is issued as a `curl`
argv through the same runner as the rest of ONIOPS, so it is scope-checked,
rate-limited and run from the attack host. There is no browser and no new
dependency here; this is the browser-free first increment. (The separate
`oniops crawl` Playwright crawler forwards one static header and does not log in or
refresh; a crawl can take a header from a session you refreshed first, but the
crawler itself does not mint one.)

## Recipe types

Three recipe types are supported per role:

- `static` — a literal header. This is today's behaviour and stays the default
  when no recipe is configured.
- `json_login` — POST a JSON body (credentials) to a login URL, read a token from
  a configurable dotted JSON path, and format it into a header.
- `form_login` — GET a login page, extract a CSRF/nonce token with a regex, POST
  form-urlencoded credentials plus that token while preserving cookies, capture
  the resulting session cookie(s), and build a `Cookie:` header. An optional
  follow-up GET and optional extra cookies are supported.

## Where credentials live

Target credentials are secrets. A recipe never stores a credential value: fields
that carry one are written as `${ENV_VAR}` and resolved from the environment only
at login time, used to build the ephemeral login `curl` argv, and then dropped.
Only the resulting auth **header** is retained. A header that ends up in a
finding's stored replay command is masked on display by the existing
`mask_command`; the login request and its credentials never reach a finding, log
line, raw-output section, report or manifest.

Non-secret values (for example a username like `admin`) may be written inline
instead of via `${ENV_VAR}` if you prefer.

## Refresh on expiry

When a request that was expected to be authenticated comes back `401` (or `403`
where a `200` was expected), the role's session is re-logged-in once and the
request is retried once with the fresh header. This is wired into the OpenAPI
access-control probe's per-endpoint loop (the point where the ~60s expiry bites)
for the low-priv, peer and admin requests, and each configured role's header is
also minted once at the start of an assessment. The retried response is the one
evaluated, and the stored replay command carries the current (fresh) header, not
a dead token.

## Config schema

```yaml
target_auth:
  <role>:                 # primary | low_priv | peer
    type: static | json_login | form_login
    # --- static ---
    header: "..."         # literal header or ${ENV_VAR}

    # --- json_login ---
    login_url: "http://HOST:PORT/path"
    json_body: { field: value | ${ENV_VAR}, ... }
    token_path: "a.b.c"   # dotted path into the JSON response
    header_template: "Authorization: Bearer {token}"
    method: POST          # optional, default POST
    extra_headers: { Name: value, ... }   # optional

    # --- form_login ---
    login_url: "http://HOST:PORT/login"
    csrf_regex: "..."     # must capture the token in group 1
    csrf_field: user_token
    form_fields: { username: ${ENV}, password: ${ENV}, ... }
    header_template: "Cookie: {cookies}"  # optional, this is the default
    follow_up_url: "http://HOST:PORT/..." # optional GET after login
    extra_cookies: { security: low }      # optional, merged into the cookie jar
    method: POST          # optional, default POST
```

### Example: VAmPI (`json_login`, short-lived JWT)

```yaml
target_auth:
  low_priv:
    type: json_login
    login_url: "http://172.17.0.3:5000/users/v1/login"
    json_body:
      username: "${ONIOPS_TARGET_LOW_USER}"
      password: "${ONIOPS_TARGET_LOW_PASS}"
    token_path: "auth_token"
    header_template: "Authorization: Bearer {token}"
  peer:
    type: json_login
    login_url: "http://172.17.0.3:5000/users/v1/login"
    json_body:
      username: "${ONIOPS_TARGET_PEER_USER}"
      password: "${ONIOPS_TARGET_PEER_PASS}"
    token_path: "auth_token"
    header_template: "Authorization: Bearer {token}"
```

```bash
export ONIOPS_TARGET_LOW_USER=name1  ONIOPS_TARGET_LOW_PASS=pass1
export ONIOPS_TARGET_PEER_USER=name2 ONIOPS_TARGET_PEER_PASS=pass2
```

### Example: OWASP Juice Shop (`json_login`, nested token path)

```yaml
target_auth:
  primary:
    type: json_login
    login_url: "http://172.17.0.2:3000/rest/user/login"
    json_body:
      email: "${ONIOPS_TARGET_JUICE_USER}"
      password: "${ONIOPS_TARGET_JUICE_PASS}"
    token_path: "authentication.token"
    header_template: "Authorization: Bearer {token}"
```

### Example: DVWA (`form_login`, CSRF + session cookie)

```yaml
target_auth:
  primary:
    type: form_login
    login_url: "http://172.17.0.4/login.php"
    csrf_regex: "name=['\"]user_token['\"]\\s+value=['\"]([^'\"]+)['\"]"
    csrf_field: user_token
    form_fields:
      username: "${ONIOPS_TARGET_DVWA_USER}"
      password: "${ONIOPS_TARGET_DVWA_PASS}"
      Login: "Login"
    follow_up_url: "http://172.17.0.4/security.php"
    extra_cookies:
      security: low
```

```bash
export ONIOPS_TARGET_DVWA_USER=admin ONIOPS_TARGET_DVWA_PASS=password
```

DVWA rotates `PHPSESSID` on a successful login; the recipe captures the rotated
cookie from the POST response. The `security: low` cookie pins the practice level
so later probes exercise the low-security code path; the follow-up GET to
`/security.php` carries the authenticated session.
