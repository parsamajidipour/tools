# Security Policy

## Reporting a Vulnerability in HTTPDiff itself

HTTPDiff processes sensitive data — cookies, tokens, authorization headers,
and private response bodies — so we take security issues in the tool itself
seriously.

If you find a vulnerability (for example: a redaction bypass, an XXE/SSRF
issue, a way to leak secrets into logs/reports, or a crash triggerable by
untrusted response data), please report it responsibly:

- **Do not** open a public GitHub issue for security vulnerabilities.
- Email the maintainers (see the repository's contact information) with:
  - A description of the issue and its impact
  - Steps to reproduce, including a minimal example if possible
  - The HTTPDiff version and Python version you tested against

We aim to acknowledge reports within 5 business days and to provide a fix or
mitigation timeline shortly after confirming the issue.

## Security Design Principles HTTPDiff Follows

- Secrets (cookie values, Authorization/Cookie header values, sensitive JSON
  fields) are redacted by default in every report format. `--show-secrets`
  is required to opt out, and its use is intentional and explicit.
- No telemetry, no analytics, no "phone home" behavior of any kind.
- HTTPDiff only ever contacts hosts the user explicitly names as a baseline
  or candidate target. It does not crawl, scan, or discover targets on its
  own.
- XML parsing never resolves external entities or fetches external DTDs/
  schemas (XXE is disabled unconditionally).
- Redirects are not followed automatically unless `--follow-redirects` is
  passed, and `Authorization`/`Cookie` headers are stripped when a redirect
  crosses origins.
- Error messages are scrubbed of `Authorization:` and `Cookie:` header
  values before being printed.

## Known Limitations (Not Vulnerabilities)

HTTPDiff's security *findings* (the heuristics about the target application)
are best-effort and may have false positives or false negatives. These are
tracked as feature/quality issues, not HTTPDiff security vulnerabilities,
unless the false result stems from a redaction or data-handling bug in the
tool itself.
