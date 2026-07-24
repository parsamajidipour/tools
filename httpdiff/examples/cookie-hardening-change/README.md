# Example: cookie-hardening-change

Demonstrates HTTPDIFF-COOKIE-001: the candidate response removes `Secure`
and `HttpOnly`, widens `SameSite` from `Strict` to `None`, and broadens the
cookie `Domain` from a fixed host to a wildcard-style domain cookie.

Run:

    httpdiff compare baseline.txt candidate.txt
