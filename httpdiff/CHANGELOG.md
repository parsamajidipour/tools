# Changelog

All notable changes to this project are documented in this file.

## [1.0.0] - 2026-07-24

### Added

- Initial stable release.
- Raw HTTP/1.x response parser with duplicate-header preservation, chunked
  transfer-encoding decoding, gzip/deflate/(optional) brotli decompression,
  charset detection, and lenient recovery from malformed input.
- Normalization pipeline for dynamic values (UUIDs, timestamps, request IDs,
  dynamic headers) that preserves original values alongside normalized ones.
- Analyzers for status/protocol, headers (general/security/caching/CORS/
  auth categories), cookies (including `__Host-`/`__Secure-` prefix rules),
  generic body metadata, JSON semantic diff (JSONPath-style), HTML semantic
  diff, XML diff (XXE-safe), reflection detection (multiple encodings),
  redirect target analysis, and cache-behavior analysis.
- Conservative security rule engine (`httpdiff/rules/`) covering security
  headers, cookie hardening, CORS, cache-risk combinations, redirect risk,
  authentication-behavior signals, and a multi-signal
  "possible access-control difference" heuristic.
- Three report formats: terminal (color + text labels), versioned JSON
  (`schema_version: "1.0"`), and Markdown.
- `compare`, `url`, and `request` subcommands; TOML configuration file
  support; secret redaction by default with `--show-secrets` opt-out.
- Test suite (unit + CLI integration tests).

### Known limitations

See the "Limitations" section of `README.md`.
