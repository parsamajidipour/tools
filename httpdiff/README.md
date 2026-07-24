# HTTPDiff

HTTPDiff compares two HTTP responses and tells you what actually changed —
not just which bytes are different, but what it *means*: a session cookie
got weaker, a response that used to require login now doesn't, a redirect
now points somewhere else, caching behavior changed in a way that could leak
private data.

It's built for security testing (bug bounty, pentesting, API review), but
it's just as useful for backend/API developers who want to know exactly what
changed between two deploys, two environments, or two versions of an
endpoint.

Think of it as `diff`, but it actually understands HTTP.

```
$ diff response-a.txt response-b.txt
< session=abc; Secure
> session=xyz
< "role": "user"
> "role": "admin"
```

That tells you the bytes changed. It doesn't tell you it matters. HTTPDiff:

```
$ httpdiff compare response-a.txt response-b.txt

[MEDIUM] Secure attribute was removed from cookie session
[CHANGE] $.user.role: 'user' -> 'admin'
[MEDIUM] Possible authorization-related behavior change (confidence: medium)
         Manual verification is required.
```

**Important:** HTTPDiff does not prove a vulnerability exists. It surfaces
evidence and points you at what to check by hand. Every finding it produces
comes with a severity, a confidence level, and a note on when it's likely a
false positive. Treat it as a very good first pass, not a final verdict.

---

## Table of contents

- [What it actually does](#what-it-actually-does)
- [Installation](#installation)
- [Basic usage](#basic-usage)
  - [Comparing two saved response files](#comparing-two-saved-response-files)
  - [Comparing two live URLs](#comparing-two-live-urls)
  - [Replaying two raw request files](#replaying-two-raw-request-files)
  - [Reading from stdin](#reading-from-stdin)
- [Reading the output](#reading-the-output)
- [What HTTPDiff checks for](#what-httpdiff-checks-for)
- [Cutting down noise](#cutting-down-noise)
- [Checking for reflected input](#checking-for-reflected-input)
- [Output formats](#output-formats)
- [Using it in CI](#using-it-in-ci)
- [Secrets and redaction](#secrets-and-redaction)
- [Config file](#config-file)
- [Full CLI reference](#full-cli-reference)
- [How it's put together](#how-its-put-together-for-contributors)
- [What it won't do](#what-it-wont-do)
- [Running the tests](#running-the-tests)
- [License](#license)

---

## What it actually does

You give HTTPDiff two HTTP responses — call them **baseline** (the "before"
or the "expected" one) and **candidate** (the "after" or the one you're
checking). It parses both, and instead of a line-by-line text diff, it
walks through everything that makes up an HTTP response and reports on it
separately:

- Status code and protocol version
- Every header, categorized (general / security / caching / CORS / auth)
- Every cookie and its security attributes
- The body — as JSON, HTML, XML, or plain text, whichever it detects
- Redirect targets, if either response is a redirect
- Caching behavior (`Cache-Control`, `Vary`, ETags, CDN headers)
- Whether a value you supply shows up reflected somewhere in the response

For each thing it finds, it decides whether it's just noise (a `Date`
header, a request ID — things that are *always* going to differ) or an
actual difference worth your attention. Noise gets suppressed by default,
but never thrown away — you can always see what was filtered out and why.

On top of the plain differences, a small rule engine looks for
*combinations* of changes that are worth flagging: a cookie losing its
`Secure` flag, a response that used to return 403 now returning 200 with
extra data in it, a redirect that now points to a different domain over
plain HTTP. Each of these becomes a **finding** with a severity
(info/low/medium/high), a confidence level, the actual evidence, and a
plain-language recommendation.

## Installation

Requires Python 3.11 or newer.

```bash
git clone <your-repo-url>
cd httpdiff
pip install -e .
```

That installs the `httpdiff` command. Check it worked:

```bash
httpdiff --version
```

If you want Brotli-compressed response support (some CDNs use it):

```bash
pip install -e ".[brotli]"
```

If you're setting this up to develop/test HTTPDiff itself, see
[Running the tests](#running-the-tests).

## Basic usage

There are three ways to feed HTTPDiff a pair of responses.

### Comparing two saved response files

This is the most common case: you've already captured two raw HTTP
responses (Burp, curl -i, browser dev tools export, whatever) and saved
them as text files.

```bash
httpdiff compare response-a.txt response-b.txt
```

or, more explicitly:

```bash
httpdiff compare --baseline response-a.txt --candidate response-b.txt
```

A response file just needs to look like a real HTTP response:

```
HTTP/1.1 200 OK
Content-Type: application/json
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Lax
Cache-Control: private

{"user":{"id":10,"role":"user"}}
```

You don't need to clean it up first — HTTPDiff handles CRLF or LF line
endings, duplicate headers, multiple `Set-Cookie` lines, chunked encoding,
gzip/deflate (and optionally Brotli) compressed bodies, and even responses
missing a proper status line. If something can't be parsed cleanly, it
degrades gracefully and tells you what it had to guess at instead of just
crashing.

### Comparing two live URLs

If you'd rather have HTTPDiff make the requests itself:

```bash
httpdiff url --baseline "https://example.com/account" \
             --candidate "https://example.com/admin"
```

Both requests are sent as `GET` by default (`--method` to change that).
Redirects are **not** followed automatically — you'll see the 3xx and its
`Location` header as-is unless you pass `--follow-redirects`. This is
deliberate: if you're comparing auth behavior, following a redirect to a
login page silently would hide the exact thing you're trying to catch.

### Replaying two raw request files

For a more precise comparison — same headers, same cookies, same body —
save two raw requests (a Burp "Copy as request" export works fine) and let
HTTPDiff send them and compare the responses:

```bash
httpdiff request --baseline-request request-a.txt \
                  --candidate-request request-b.txt
```

A request file looks like:

```
GET /account HTTP/1.1
Host: example.com
Cookie: session=abc123
User-Agent: HTTPDiff
```

If the request has no scheme information, HTTPDiff assumes `https` — pass
`--scheme http` if you need plain HTTP.

### Reading from stdin

Useful for piping straight from another tool:

```bash
cat response-a.txt | httpdiff compare --stdin-baseline response-b.txt
```

## Reading the output

By default you get a terminal report, grouped into sections:

```
Comparison Summary
  Status: unchanged, 200 -> 200
  Body similarity: 86.6%
  Differences: 8 (suppressed: 0)
  Findings: 3 (highest severity: medium)

Differences
-----------
  [CHANGE] Cache-Control changed from private to public
  [CHANGE] Secure attribute was removed from cookie session
  [CHANGE] $.user.role: 'user' -> 'admin'

Security Findings
------------------
  [MEDIUM] (HTTPDIFF-COOKIE-001, confidence: high) Secure attribute was
           removed from cookie session
      Recommendation: Restore the stronger cookie attribute unless this
      change was intentional and reviewed for session-hijacking / CSRF impact.

Suppressed Dynamic Differences
-------------------------------
  [NOISE] Date changed and was normalized (dynamic header normalized to an
          equal value)
```

Three things to pay attention to:

- **`Differences`** is everything that changed, in plain language, after
  noise has been filtered out.
- **`Security Findings`** is the smaller, curated list — only things the
  rule engine thinks are worth a second look, each with its own confidence
  level. This is what you should actually act on.
- **`Suppressed Dynamic Differences`** shows you what got filtered as noise
  and why, so nothing is ever silently hidden from you — if you don't trust
  the filtering for a given comparison, check this section.

Every finding also comes with **false-positive notes** — a short note on
when that specific finding is expected to be benign. Read those before you
report anything as a bug; a lot of "findings" are completely normal
application behavior (e.g. a session cookie disappearing on logout).

## What HTTPDiff checks for

Roughly, in the order it runs:

| Area | Examples of what gets flagged |
|---|---|
| **Status & protocol** | Status code changed, HTTP version changed, response became empty |
| **Headers** | Security header (`CSP`, `HSTS`, `X-Frame-Options`, ...) removed; `Access-Control-Allow-Origin` widened to `*` |
| **Cookies** | `Secure`/`HttpOnly` removed, `SameSite` weakened, domain/path broadened, `__Host-`/`__Secure-` prefix rules violated |
| **JSON body** | Any key added/removed/changed by JSONPath, with role/permission/identity-looking fields flagged specifically |
| **HTML body** | New password input, new external `<script src>`, CSP `<meta>` tag disappeared, page title changed |
| **XML body** | Any element/attribute/text change (external entities are never resolved, even if the XML tries to define one) |
| **Redirects** | Target became cross-origin, HTTPS downgraded to HTTP, redirect chain length changed |
| **Caching** | Response went from `private` to `public`, `no-store` removed, `Vary` no longer includes `Cookie`, personalized data showing up in a publicly-cacheable response |
| **Reflection** | A value you supply (`--reflection-value`) shows up in the response, in what context, and in what encoding |
| **Auth behavior** | Multiple signals changing together (status code + cookie + `WWW-Authenticate`), or access that was denied now succeeding *and* returning more data |

Full detail on each rule and its rule ID (e.g. `HTTPDIFF-COOKIE-001`) is in
the code under `httpdiff/rules/` — every rule is a small, readable class
with its evidence logic right there, nothing hidden in config.

## Cutting down noise

Some differences are always going to show up and aren't worth your time —
timestamps, request IDs, trace headers. HTTPDiff filters a sensible default
set of these automatically (`Date`, `X-Request-ID`, `CF-Ray`, UUID-looking
values, ISO timestamps, and similar). If you're still seeing noise:

```bash
# Ignore a specific header entirely
httpdiff compare a.txt b.txt --ignore-header X-Server-Timing

# Ignore a specific cookie
httpdiff compare a.txt b.txt --ignore-cookie ab_test_bucket

# Ignore a specific JSON field (supports glob-style patterns)
httpdiff compare a.txt b.txt --ignore-json-path '$.metadata.timestamp'

# Ignore anything matching a regex, wherever it shows up
httpdiff compare a.txt b.txt --ignore-regex 'req-[a-f0-9]{16}'

# Turn off automatic noise filtering entirely
httpdiff compare a.txt b.txt --no-normalize
```

All of these can be repeated (`--ignore-header X --ignore-header Y`), and
all of them can live in a config file instead — see [Config file](#config-file).

## Checking for reflected input

If you're testing for injection issues, give HTTPDiff the marker value you
put in your request and it'll check the response for it — in plain text, in
an HTML attribute, inside a `<script>` block, URL-encoded, HTML-encoded,
JSON-escaped, Unicode-escaped, Base64, or case-flipped:

```bash
httpdiff compare a.txt b.txt --reflection-value "HTTPDIFF123"
```

It tells you exactly where and in what form the value showed up, so you can
judge for yourself whether it's exploitable — it does **not** claim
"XSS found." An unencoded reflection inside an HTML attribute is worth
checking by hand; a JSON-escaped reflection inside a JSON string body
usually isn't dangerous on its own.

## Output formats

```bash
httpdiff compare a.txt b.txt --format terminal    # default, human-readable
httpdiff compare a.txt b.txt --format json        # machine-readable, stable schema
httpdiff compare a.txt b.txt --format markdown     # for GitHub issues / pentest notes
```

Write straight to a file instead of stdout:

```bash
httpdiff compare a.txt b.txt --format markdown --output report.md
```

The JSON output has a `schema_version` field (currently `"1.0"`) so you can
build tooling on top of it without worrying about the shape changing
silently underneath you.

## Using it in CI

`--fail-on` sets the severity threshold that turns a comparison into a
failed build:

```bash
httpdiff compare baseline.txt candidate.txt --format json --fail-on medium
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Ran fine, nothing hit the `--fail-on` threshold |
| `1` | Something hit the `--fail-on` threshold |
| `2` | Bad arguments or input that couldn't be read at all |
| `3` | Network/request failure (`url`/`request` modes only) |
| `4` | Internal error (please file a bug if you hit this) |

`--fail-on` defaults to `none`, meaning HTTPDiff always exits `0` unless you
explicitly ask it to fail the build on findings.

## Secrets and redaction

Cookie values, `Authorization`/`Cookie`/`Set-Cookie`/`Proxy-Authorization`
header values, and JSON fields that look sensitive (`password`, `token`,
`api_key`, `session`, `private_key`, and similar) are redacted **by
default**, everywhere — terminal, JSON, and Markdown output. You'll see a
short fingerprint instead of the real value:

```
Session cookie value changed and was redacted: session
  Baseline: sha256:6ca13d52...
  Candidate: sha256:5a4640c1...
```

If you need to see the actual values (e.g. debugging why two cookies you
expect to be identical aren't):

```bash
httpdiff compare a.txt b.txt --show-secrets
```

Nothing is ever written to disk or printed unredacted unless you pass this
flag explicitly.

## Config file

If you're running the same set of ignore rules over and over, put them in a
config file instead of retyping flags. HTTPDiff looks for `./httpdiff.toml`
or `~/.config/httpdiff/config.toml` automatically, or you can point at one
with `--config path/to/file.toml`. CLI flags always win over the config
file if both set the same thing.

```toml
[comparison]
similarity_threshold = 0.92
max_body_size = 5242880      # bytes; larger bodies get truncated (and it tells you)
normalize = true

[ignore]
headers = ["Date", "X-Request-ID", "CF-Ray"]
cookies = ["analytics_id"]
json_paths = ["$.metadata.timestamp"]
regexes = ["request-id=[a-f0-9-]+"]

[report]
format = "terminal"
show_secrets = false

[rules]
minimum_severity = "info"
```

## Full CLI reference

```
httpdiff compare BASELINE CANDIDATE          Compare two response files
httpdiff compare --baseline A --candidate B  Same, explicit flags
httpdiff compare --stdin-baseline B          Read baseline from stdin, candidate from file B
httpdiff compare --stdin-candidate A         Read candidate from stdin, baseline from file A

httpdiff url --baseline URL --candidate URL [--method METHOD]
httpdiff request --baseline-request FILE --candidate-request FILE [--scheme http|https]

Global options (work before or after the subcommand):
  --format terminal|json|markdown   Output format (default: terminal)
  --output PATH                     Write report to a file instead of stdout
  --fail-on none|info|low|medium|high   Exit 1 if a finding reaches this severity
  --no-color                        Disable ANSI colors in terminal output
  --show-unchanged                  Include unchanged items in the report
  --show-secrets                    Show real cookie/header/JSON secret values
  --config PATH                     Explicit config file path
  --verbose / --quiet                More or less console noise

  --ignore-header NAME              Repeatable
  --include-header NAME             Repeatable; if set, ONLY these headers are compared
  --ignore-cookie NAME              Repeatable
  --ignore-json-path PATH           Repeatable, glob-style JSONPath
  --ignore-regex REGEX              Repeatable
  --normalize / --no-normalize      Toggle automatic noise suppression

  --reflection-value VALUE          Marker to search for in the candidate response
  --similarity-threshold FLOAT      Body-similarity ratio (0.0-1.0) used for reporting
  --max-body-size BYTES             Truncate bodies larger than this
  --max-diff-lines N                Cap on raw text-diff output lines
  --max-json-depth N                Cap on JSON recursion depth

  --timeout SECONDS                 Request timeout (url/request modes)
  --insecure                        Skip TLS certificate verification
  --proxy URL                       Route requests through an HTTP(S) proxy
  --user-agent VALUE                Override the User-Agent header
  --follow-redirects                Follow redirects instead of showing the 3xx as-is
  --scheme http|https                Scheme to assume for raw request files without one
```

`httpdiff --help` and `httpdiff <command> --help` always have the
authoritative, up-to-date list.

## How it's put together (for contributors)

```
httpdiff/
├── parser.py         raw HTTP/1.x -> HTTPResponse
├── client.py          makes the actual requests for `url` / `request` modes
├── normalization.py    decides what's "dynamic noise" vs. a real difference
├── analyzers/          one file per aspect (headers, cookies, json_body, ...)
│                        -> each one just returns a list of Difference objects,
│                           no severity judgment happens here
├── rules/               the security rule engine -> consumes Differences,
│                        outputs Findings (severity + confidence + evidence)
├── comparison.py        wires parser -> analyzers -> rules together
├── reporters/            terminal / json / markdown renderers
└── cli.py                argument parsing, dispatch, exit codes
```

If you want to add a check that isn't there yet, it's almost always one of:

- A new **analyzer** function if you're detecting a new kind of raw
  difference (add it under `analyzers/`, wire it into `comparison.py`).
- A new **rule** if you're combining existing differences into a security
  judgment (add it under `rules/`, register it in `rules/__init__.py`).

See `CONTRIBUTING.md` for more detail, and `tests/` for how existing
analyzers/rules are tested — copy the closest existing test file as a
starting point.

## What it won't do

Being upfront about this matters more for a security tool than most:

- It does **not** prove a vulnerability exists. Every finding is a
  heuristic pointing at something worth checking by hand.
- It does **not** execute JavaScript or use a real browser — HTML is parsed
  statically, so JS-rendered differences won't show up.
- It does **not** parse raw HTTP/2 frames (only through the built-in HTTP
  client, which negotiates HTTP/1.1).
- It does **not** discover CDN/cache keys — the caching findings tell you
  something *might* be cached publicly that shouldn't be, not what the
  actual cache key is.
- It does **not** crawl, scan, or touch anything beyond the exact URLs/files
  you give it. It sends requests only to targets you explicitly name.
- It does **not** exploit anything it finds. It's a comparison tool, not an
  attack tool.
- It **will** occasionally produce false positives — read the
  "false-positive considerations" on each finding before acting on it.

Only test targets you're authorized to test.

## Running the tests

```bash
pip install -e ".[dev]"
python -m pytest              # or: python -m unittest discover -s tests
python -m pytest --cov=httpdiff --cov-report=term-missing
ruff check .
mypy httpdiff
```

## License

MIT — see `LICENSE`.
