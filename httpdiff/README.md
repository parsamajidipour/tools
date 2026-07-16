# HTTPDiff

HTTPDiff is a semantic HTTP response comparison tool built for security researchers, penetration testers, bug bounty hunters, developers, and system administrators.

Traditional tools such as `diff` compare lines and characters.

HTTPDiff does not merely compare response text. It compares **HTTP behavior**.

It understands the structure of HTTP responses and explains changes in status codes, headers, cookies, caching behavior, redirects, structured response bodies, reflected input, authentication state, and authorization-related data.

Instead of only showing that two values changed, HTTPDiff attempts to explain why the change may matter from a security perspective.

> HTTPDiff does not automatically prove that a vulnerability exists. Its findings are evidence-based heuristics intended to guide manual security testing.

---

## Why HTTPDiff Exists

A traditional text comparison might produce this result:

```diff
-Set-Cookie: session=abc; Secure; HttpOnly
+Set-Cookie: session=xyz; HttpOnly

-Cache-Control: private
+Cache-Control: public

-{"role":"user"}
+{"role":"admin"}
```

This output is technically correct, but it does not explain the meaning of the changes.

HTTPDiff interprets the same responses like this:

```text
Comparison Summary
------------------
Status: unchanged, 200 OK
Content-Type: unchanged, application/json
Body similarity: 94%

Cookie Changes
--------------
[MEDIUM] Secure was removed from the session cookie.
[INFO] Session cookie value changed and was redacted.

Cache Changes
-------------
[MEDIUM] Cache-Control changed from private to public.

JSON Changes
------------
[CHANGE] $.role changed from "user" to "admin".

Security Observations
---------------------
[MEDIUM, confidence: medium]
Possible authorization-related behavior change.

Evidence:
- The response remained successful.
- The returned role changed from user to admin.
- The response became publicly cacheable.

Manual verification is required.
```

The goal is not to replace `diff`.

The goal is to answer a different question:

> What does this HTTP difference mean?

---

## Features

HTTPDiff can analyze and compare:

- HTTP status codes and protocol versions
- Added, removed, and modified headers
- Security headers
- Cache headers and CDN behavior
- CORS headers
- Cookies and security attributes
- Redirect targets and redirect chains
- JSON structures and JSON paths
- HTML forms, links, scripts, and visible text
- XML elements and attributes
- Plain-text responses
- Reflected input
- Authentication-related behavior
- Authorization-related behavior
- Dynamic response noise
- Potentially sensitive values

HTTPDiff separates results into:

1. Raw differences
2. Structural differences
3. Semantic HTTP changes
4. Security observations
5. Suppressed dynamic noise

---

## Supported Inputs

HTTPDiff supports several comparison modes.

### Raw HTTP response files

```bash
httpdiff compare response-a.txt response-b.txt
```

### Explicit baseline and candidate files

```bash
httpdiff compare \
  --baseline response-a.txt \
  --candidate response-b.txt
```

### Remote URLs

```bash
httpdiff url \
  --baseline "https://example.com/account" \
  --candidate "https://example.com/admin"
```

### Raw HTTP request files

```bash
httpdiff request \
  --baseline-request request-a.txt \
  --candidate-request request-b.txt
```

### Standard input

```bash
cat response-a.txt | httpdiff compare --stdin-baseline response-b.txt
```

---

## Installation

HTTPDiff requires Python 3.11 or newer.

### Install from source

```bash
git clone https://github.com/parsamajidipour/tools.git
cd tools/web/httpdiff

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install .
```

Verify the installation:

```bash
httpdiff --version
```

### Development installation

```bash
python -m pip install -e ".[dev]"
```

---

## Quick Start

Create two raw HTTP response files.

### `baseline.txt`

```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=abc; Secure; HttpOnly; SameSite=Lax
Cache-Control: private

{
  "user": {
    "id": 10,
    "role": "user"
  }
}
```

### `candidate.txt`

```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=xyz; HttpOnly; SameSite=Lax
Cache-Control: public

{
  "user": {
    "id": 10,
    "role": "admin"
  }
}
```

Run the comparison:

```bash
httpdiff compare baseline.txt candidate.txt
```

Example output:

```text
HTTPDiff Comparison Report
==========================

Summary
-------
Baseline status : 200 OK
Candidate status: 200 OK
Content type    : application/json
Body similarity : 94%

Headers
-------
[CHANGE] Cache-Control
  Baseline : private
  Candidate: public

Cookies
-------
[MEDIUM] Secure attribute removed from cookie "session"
[INFO] Cookie value changed: sha256:ba7816... -> sha256:cb8379...

JSON Body
---------
[CHANGE] $.user.role
  Baseline : "user"
  Candidate: "admin"

Security Findings
-----------------
[MEDIUM] Possible authorization-related behavior change
Confidence: medium

Evidence:
- The response remained successful.
- The user role changed from "user" to "admin".
- The response became publicly cacheable.

Recommendation:
Verify whether the candidate response exposes data or privileges that
should not be available under the same authentication context.

Manual verification is required.
```

---

## Command Overview

```text
httpdiff [GLOBAL OPTIONS] COMMAND [COMMAND OPTIONS]
```

Available commands:

```text
compare    Compare saved HTTP responses
url        Request and compare two URLs
request    Send and compare two raw HTTP requests
```

Global options:

```text
--help
--version
--verbose
--quiet
--no-color
--config PATH
--output PATH
--format terminal|json|markdown
--fail-on none|info|low|medium|high
--timeout SECONDS
--insecure
--proxy URL
--user-agent VALUE
```

Comparison options:

```text
--ignore-header NAME
--include-header NAME
--ignore-cookie NAME
--ignore-json-path PATH
--ignore-regex REGEX
--normalize
--no-normalize
--show-raw-diff
--show-unchanged
--reflection-value VALUE
--similarity-threshold FLOAT
--show-secrets
```

Options such as `--ignore-header` and `--ignore-json-path` may be repeated.

Example:

```bash
httpdiff compare baseline.txt candidate.txt \
  --ignore-header Date \
  --ignore-header X-Request-ID \
  --ignore-json-path '$.metadata.timestamp'
```

---

## Raw HTTP Response Format

HTTPDiff accepts responses in standard raw HTTP format:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=abc; Secure; HttpOnly
Cache-Control: private

{"role":"user"}
```

The parser supports:

- CRLF and LF line endings
- Duplicate headers
- Multiple `Set-Cookie` headers
- Empty response bodies
- Header-only responses
- Recoverable malformed responses
- Chunked transfer encoding
- gzip and deflate compression
- Brotli compression when supported
- Text and binary response bodies
- Character-set detection with safe fallbacks

Duplicate headers are preserved and are not collapsed into a normal dictionary.

---

## Header Analysis

HTTPDiff compares headers based on their HTTP meaning rather than only their raw text.

It identifies:

- Added headers
- Removed headers
- Modified headers
- Duplicate-header changes
- Security-relevant changes
- Cache-policy changes
- CORS-policy changes
- Redirect changes
- Content-type changes

### Security headers

HTTPDiff recognizes headers such as:

```text
Content-Security-Policy
Content-Security-Policy-Report-Only
Strict-Transport-Security
X-Content-Type-Options
X-Frame-Options
Referrer-Policy
Permissions-Policy
Cross-Origin-Opener-Policy
Cross-Origin-Embedder-Policy
Cross-Origin-Resource-Policy
```

Example finding:

```text
[MEDIUM] Strict-Transport-Security was removed.
```

The removal of a security header is reported as a security-relevant change, not automatically as an exploitable vulnerability.

---

## Cookie Analysis

Each `Set-Cookie` header is parsed independently.

HTTPDiff compares:

- Cookie values
- Domain
- Path
- Expiration
- Max-Age
- Secure
- HttpOnly
- SameSite
- Partitioned
- Priority
- `__Host-` prefix requirements
- `__Secure-` prefix requirements

Example:

```text
Cookie: session

[INFO] Value changed
  Baseline : sha256:8f3a...
  Candidate: sha256:91bc...

[MEDIUM] Secure attribute was removed
[LOW] SameSite changed from Strict to Lax
```

Cookie values are redacted by default.

To display raw values explicitly:

```bash
httpdiff compare a.txt b.txt --show-secrets
```

Using `--show-secrets` may expose credentials, tokens, session identifiers, or personal information in terminal output and generated reports.

---

## JSON Semantic Comparison

When both response bodies contain JSON, HTTPDiff parses and compares the structures recursively.

Formatting and key order are ignored.

Example:

```json
{
  "user": {
    "id": 10,
    "role": "user",
    "authenticated": true
  }
}
```

Compared with:

```json
{
  "user": {
    "id": 10,
    "role": "admin",
    "authenticated": true,
    "permissions": ["read", "write", "delete"]
  }
}
```

HTTPDiff reports:

```text
[CHANGE] $.user.role
  "user" -> "admin"

[ADDED] $.user.permissions
  ["read", "write", "delete"]
```

It can detect:

- Added keys
- Removed keys
- Changed values
- Type changes
- Array changes
- `null` versus missing values
- Boolean state changes
- Identity-related fields
- Role and permission fields
- Potentially sensitive fields

Sensitive values such as passwords, tokens, session identifiers, API keys, and private keys are redacted by default.

Ignored JSON paths can be configured:

```bash
httpdiff compare a.txt b.txt \
  --ignore-json-path '$.metadata.timestamp' \
  --ignore-json-path '$.request_id'
```

A changed role or permission field does not automatically prove an authorization vulnerability. HTTPDiff reports such changes as evidence requiring manual verification.

---

## HTML Semantic Comparison

When both responses contain HTML, HTTPDiff compares meaningful document structures.

It can analyze:

- Page titles
- Forms
- Form actions
- Input fields
- Links
- Script sources
- iframe sources
- Meta elements
- Visible text
- Administrative controls
- Login and logout indicators
- Error messages
- Debug information
- Stack traces

Example:

```text
[CHANGE] Page title
  "Login" -> "Administration"

[ADDED] Form
  Action: /admin/users/delete

[ADDED] Script source
  https://cdn.example.net/admin.js
```

HTTPDiff does not execute JavaScript and does not use a browser in its initial implementation.

---

## Reflection Detection

HTTPDiff can search for explicit test values inside a response.

```bash
httpdiff compare baseline.txt candidate.txt \
  --reflection-value "HTTPDIFF123"
```

It searches for:

- Exact reflection
- URL-encoded reflection
- HTML-encoded reflection
- JSON-escaped reflection
- Unicode-escaped reflection
- Base64-encoded reflection
- Case-transformed reflection
- Partial reflection

Example:

```text
Reflection Detected
-------------------
Value   : HTTPDIFF123
Location: HTML attribute
Encoding: none
Context : value="HTTPDIFF123"

Security note:
Unencoded reflection inside an HTML attribute may require manual XSS testing.
```

HTTPDiff does not automatically classify every reflection as XSS.

Reflection context, encoding, browser behavior, and surrounding syntax must be verified manually.

---

## Redirect Analysis

HTTPDiff compares:

- Redirect status codes
- `Location` headers
- Relative and absolute redirects
- Schemes
- Hosts
- Ports
- Paths
- Query strings
- Cross-origin changes
- HTTPS-to-HTTP downgrades
- Redirect chains
- Redirect loops

Example:

```text
[CHANGE] Redirect target became cross-origin

Baseline:
  /dashboard

Candidate:
  https://external.example/login
```

An external redirect is not automatically reported as an open redirect.

An open redirect finding requires stronger evidence, such as attacker-controlled input being reflected into an external redirect destination.

---

## Cache Behavior Analysis

Cache analysis is one of HTTPDiff's primary features.

HTTPDiff compares:

- `Cache-Control`
- `Pragma`
- `Expires`
- `Age`
- `ETag`
- `Last-Modified`
- `Vary`
- `Surrogate-Control`
- `CDN-Cache-Control`
- `Cloudflare-CDN-Cache-Control`
- `X-Cache`
- `X-Cache-Hits`
- `CF-Cache-Status`
- `X-Served-By`
- `Via`

It understands directives such as:

```text
public
private
no-store
no-cache
max-age
s-maxage
stale-while-revalidate
stale-if-error
immutable
must-revalidate
proxy-revalidate
```

Example:

```text
Potential Cache Risk
--------------------
Severity  : medium
Confidence: medium

Evidence:
- Cache-Control changed from private to public.
- The response contains user-specific JSON fields.
- Vary does not include Cookie or Authorization.

Recommendation:
Verify whether authenticated responses are shared across users or cache keys.
```

HTTPDiff does not claim to automatically discover the complete cache key.

It compares visible cache behavior and highlights combinations that deserve manual testing.

---

## Authentication and Authorization Heuristics

HTTPDiff combines multiple signals when analyzing authentication and authorization behavior.

Authentication signals may include:

- `401`, `403`, and `200` transitions
- Login and logout indicators
- Session-cookie changes
- `WWW-Authenticate` changes
- Token fields
- Redirects to login pages
- Authentication booleans
- Account identity fields
- CSRF-token changes

Authorization signals may include:

- Role changes
- Permission changes
- Additional private fields
- Administrative controls
- Object identifiers
- Account ownership changes
- Forbidden content becoming available

Example:

```text
Possible Access-Control Difference
----------------------------------
Severity  : medium
Confidence: medium

Evidence:
- Baseline status was 403.
- Candidate status was 200.
- Candidate returned an account object.
- Authentication cookie fingerprint remained unchanged.
- Candidate included additional permission fields.

Manual verification is required.
```

Confidence describes the strength of the available evidence.

It does not represent the final severity of a confirmed vulnerability.

---

## Response Normalization

HTTP responses commonly include values that change on every request.

Examples include:

```text
Date
X-Request-ID
X-Correlation-ID
X-Trace-ID
Traceparent
CF-Ray
X-Amzn-Trace-Id
Server-Timing
```

Without normalization, these values create large amounts of meaningless output.

HTTPDiff can normalize:

- Header-name casing
- Optional whitespace
- Line endings
- JSON formatting
- Cookie attribute ordering
- UUID-like values
- Request identifiers
- Timestamps
- Timing values
- Random nonce-like values
- Insignificant HTML whitespace

Example:

```text
Suppressed Dynamic Differences
------------------------------
[NOISE] Date changed
  Reason: dynamic timestamp header

[NOISE] X-Request-ID changed
  Reason: UUID-like request identifier
```

Normalization never removes the original evidence internally.

Every suppressed difference preserves:

- Original value
- Normalized value
- Normalization reason

Normalization can be disabled:

```bash
httpdiff compare a.txt b.txt --no-normalize
```

---

## Ignoring Known Noise

Ignore specific headers:

```bash
httpdiff compare a.txt b.txt \
  --ignore-header Date \
  --ignore-header X-Request-ID
```

Ignore cookies:

```bash
httpdiff compare a.txt b.txt \
  --ignore-cookie analytics_id
```

Ignore matching values:

```bash
httpdiff compare a.txt b.txt \
  --ignore-regex 'request-id=[a-f0-9-]+'
```

Ignore JSON paths:

```bash
httpdiff compare a.txt b.txt \
  --ignore-json-path '$.timestamp'
```

---

## Output Formats

HTTPDiff supports three output formats.

### Terminal

```bash
httpdiff compare a.txt b.txt
```

Designed for interactive use.

### JSON

```bash
httpdiff compare a.txt b.txt --format json
```

JSON reports use a versioned schema:

```json
{
  "schema_version": "1.0",
  "tool_version": "1.0.0",
  "baseline": {},
  "candidate": {},
  "summary": {},
  "differences": [],
  "findings": [],
  "suppressed": []
}
```

### Markdown

```bash
httpdiff compare a.txt b.txt \
  --format markdown \
  --output report.md
```

Markdown reports are designed for:

- GitHub issues
- Pentest notes
- Security reports
- Bug bounty reports
- CI artifacts

---

## CI Usage

HTTPDiff supports severity-based exit thresholds.

```bash
httpdiff compare baseline.txt candidate.txt \
  --format json \
  --output httpdiff-report.json \
  --fail-on medium
```

Exit codes:

```text
0    Comparison completed and no finding reached the failure threshold
1    One or more findings reached the configured failure threshold
2    Invalid arguments or malformed input
3    Request or network failure
4    Internal tool error
```

Example GitHub Actions step:

```yaml
- name: Compare HTTP responses
  run: |
    httpdiff compare \
      tests/baseline-response.txt \
      tests/current-response.txt \
      --format markdown \
      --output httpdiff-report.md \
      --fail-on high
```

---

## Configuration

HTTPDiff supports TOML configuration files.

Default locations:

```text
./httpdiff.toml
~/.config/httpdiff/config.toml
```

Example:

```toml
[comparison]
similarity_threshold = 0.92
max_body_size = 5242880
normalize = true

[ignore]
headers = [
  "Date",
  "X-Request-ID",
  "CF-Ray"
]

cookies = [
  "analytics_id"
]

json_paths = [
  "$.metadata.timestamp",
  "$.request_id"
]

regexes = [
  "request-id=[a-f0-9-]+"
]

[report]
format = "terminal"
show_secrets = false

[rules]
minimum_severity = "info"
```

CLI options override configuration values.

Use a custom configuration file:

```bash
httpdiff --config ./configs/bug-bounty.toml compare a.txt b.txt
```

---

## Secret Redaction

HTTP responses may contain:

- Session cookies
- Authorization headers
- API keys
- Access tokens
- Refresh tokens
- CSRF tokens
- Passwords
- Private keys
- Personal information

HTTPDiff redacts sensitive values by default.

Example:

```text
Authorization: Bearer [REDACTED]

Cookie: session=sha256:91bc...

$.access_token: [REDACTED]
```

HTTPDiff does not:

- Upload response data
- Send telemetry
- Contact external services
- Store credentials remotely
- Make requests other than those explicitly requested by the user

Use `--show-secrets` only in a trusted environment.

---

## Security Model

HTTPDiff is a defensive analysis and testing utility.

It only sends requests to targets explicitly supplied by the user.

HTTPDiff does not include:

- Automated crawling
- Mass scanning
- Distributed scanning
- Stealth or evasion features
- Automatic exploitation
- Credential attacks
- Destructive testing

Only use HTTPDiff against systems you own or have explicit permission to test.

---

## Limitations

HTTPDiff does not:

- Prove that a vulnerability exists
- Replace manual security testing
- Execute JavaScript
- Use a browser engine
- Parse raw binary HTTP/2 frames
- Automatically discover complete cache keys
- Crawl websites
- Exploit security findings
- Understand every application-specific role model
- Infer user intent from response text
- Eliminate all false positives
- Detect every meaningful behavioral difference

HTTPDiff may produce false positives or miss application-specific security behavior.

Every security observation should be manually verified.

---

## Project Structure

```text
httpdiff/
├── pyproject.toml
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── SECURITY.md
├── httpdiff/
│   ├── cli.py
│   ├── config.py
│   ├── models.py
│   ├── parser.py
│   ├── client.py
│   ├── normalization.py
│   ├── comparison.py
│   ├── redaction.py
│   ├── analyzers/
│   ├── rules/
│   └── reporters/
├── tests/
└── examples/
```

The codebase separates:

- Parsing
- Normalization
- Comparison
- Analysis
- Rule evaluation
- Reporting

---

## Development

Clone the repository:

```bash
git clone https://github.com/parsamajidipour/tools.git
cd tools/web/httpdiff
```

Create an environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

Run linting:

```bash
ruff check .
```

Run type checking:

```bash
mypy httpdiff
```

Run the complete validation suite:

```bash
pytest --cov=httpdiff
ruff check .
mypy httpdiff
python -m build
```

---

## Contributing

Contributions are welcome.

Useful contribution areas include:

- New semantic comparison rules
- Improved normalization
- Additional response-body analyzers
- Better false-positive handling
- New cache-behavior heuristics
- Additional report formats
- Performance improvements
- Documentation and examples
- Parser test cases

Before submitting a pull request:

1. Add or update tests.
2. Run the test suite.
3. Run linting and type checking.
4. Document user-visible changes.
5. Avoid presenting heuristic observations as confirmed vulnerabilities.

See `CONTRIBUTING.md` for more information.

---

## Roadmap

Planned improvements include:

- Advanced response clustering
- Multiple-response comparison
- Baseline stability analysis
- Repeated-request noise detection
- Cache-key behavior experiments
- Request mutation support
- Burp Suite integration
- HAR import
- SARIF output
- Custom user-defined rules
- Plugin support
- WebSocket handshake comparison
- GraphQL response analysis
- OAuth flow comparison
- HTTP/2 metadata support
- Machine-readable rule documentation

---

## Reporting Security Issues

Do not report vulnerabilities in HTTPDiff through public GitHub issues.

Follow the instructions in `SECURITY.md`.

When reporting an issue, include:

- A clear description
- Affected version
- Reproduction steps
- Expected behavior
- Actual behavior
- Potential impact
- Suggested remediation, when available

Do not include real credentials, tokens, or private response data.

---

## License

HTTPDiff is released under the MIT License.

See `LICENSE` for details.

---

## Final Note

`diff` tells you which text changed.

HTTPDiff helps you understand what changed in the HTTP response, why it may matter, and where manual security investigation should continue.

HTTPDiff does not merely compare response text.

It compares HTTP behavior.
