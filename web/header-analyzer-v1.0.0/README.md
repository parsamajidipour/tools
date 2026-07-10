# Header Analyzer

A practical command-line tool for auditing HTTP response security headers.

Header Analyzer does more than check whether a header exists. It performs lightweight validation of important values, follows redirects, assigns a transparent score, highlights information disclosure and cookie issues, and supports both human-readable and JSON output.

> Use this tool only against systems you own or are explicitly authorized to test.

## Features

- Context-aware analysis of common response security headers
- Basic CSP weakness detection
- HSTS validation, including `max-age` and `includeSubDomains`
- Clickjacking protection checks using CSP `frame-ancestors` or `X-Frame-Options`
- Referrer-Policy and Permissions-Policy validation
- Redirect-chain visualization
- Cookie, CORS, legacy-header, and server-disclosure observations
- Single-target and file-based batch scanning
- Text and JSON reports
- Optional raw response-header output
- No external scanning engine or browser required

## Headers analyzed

The current release evaluates:

- `Content-Security-Policy`
- `Strict-Transport-Security`
- `X-Content-Type-Options`
- `Referrer-Policy`
- CSP `frame-ancestors` / `X-Frame-Options`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`

The tool also records additional observations for response headers such as `Server`, `X-Powered-By`, CORS headers, `Set-Cookie`, and the legacy `X-XSS-Protection` header.

## Requirements

- Python 3.10 or newer
- Internet access to the target
- Authorization to test the target

## Installation

### Option 1: Run from the repository

```bash
git clone https://github.com/parsamajidipour/tools.git
cd tools/web/header-analyzer

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
```

Run the tool:

```bash
python header_analyzer.py https://example.com
```

### Option 2: Install the CLI locally

From inside this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .
```

You can then call it directly:

```bash
header-analyzer https://example.com
```

## Usage

```text
usage: header-analyzer [-h] [-i INPUT] [-o OUTPUT]
                       [--format {text,json}] [--timeout TIMEOUT]
                       [--insecure] [--no-color] [--show-headers]
                       [--user-agent USER_AGENT] [--version]
                       [target]
```

### Scan one target

```bash
python header_analyzer.py https://example.com
```

A scheme is optional. HTTPS is assumed:

```bash
python header_analyzer.py example.com
```

### Show all received response headers

```bash
python header_analyzer.py https://example.com --show-headers
```

### Save a JSON report

```bash
python header_analyzer.py https://example.com \
  --format json \
  --output report.json
```

### Scan multiple targets

Create a file containing one URL per line:

```text
https://example.com
https://example.org
```

Then run:

```bash
python header_analyzer.py --input targets.txt
```

### Change the timeout

```bash
python header_analyzer.py https://example.com --timeout 20
```

### Test a host with an untrusted certificate

```bash
python header_analyzer.py https://test.internal --insecure
```

`--insecure` disables TLS certificate verification and should only be used intentionally in a controlled environment.

## Example output

```text
Header Analyzer
Target:    https://example.com
Final URL: https://example.com/
Status:    200
Time:      184 ms

Redirect chain
  200 https://example.com/

Security header findings
  [FAIL] Content-Security-Policy (0/25)
         CSP is missing.
         Fix: Deploy a restrictive CSP; prefer nonces or hashes and avoid broad sources.

  [PASS] X-Content-Type-Options (10/10)
         MIME sniffing protection is enabled.
         Value: nosniff

Summary
  Score: 46/100
  Grade: F
```

## Scoring model

The score is based on weighted checks. It is designed to make findings easy to prioritize, not to certify that an application is secure.

A high score does not prove that a site is free of vulnerabilities. A low score does not necessarily mean every missing header is relevant to every response type. For example, some document-oriented headers provide little value on a machine-to-machine JSON API.

Grades:

| Score | Grade |
|---:|:---:|
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 60–69 | D |
| 0–59 | F |

## Testing

The test suite includes rule-level unit tests and a local HTTP-server integration test.

```bash
python -m unittest discover -s tests -v
```

## Project structure

```text
header-analyzer/
├── header_analyzer.py
├── pyproject.toml
├── requirements.txt
├── README.md
├── LICENSE
├── examples/
│   └── targets.txt
└── tests/
    └── test_header_analyzer.py
```

## Limitations

- Analysis is heuristic and intentionally conservative.
- CSP parsing is not a full browser-grade policy evaluator.
- Header relevance depends on the response type and application architecture.
- The scanner evaluates the final response and reports the redirect chain, but it does not independently grade every redirect response.
- It does not replace manual review, browser testing, or a full security assessment.

## References

The checks were designed around current guidance from the OWASP HTTP Security Response Headers Cheat Sheet and MDN documentation for the relevant HTTP headers.

## License

Released under the MIT License.
