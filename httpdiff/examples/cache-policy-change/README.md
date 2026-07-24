# Example: cache-policy-change

Demonstrates HTTPDIFF-CACHE-001: a personalized JSON response (contains an
email address) becomes publicly cacheable, and `Vary` no longer includes
`Cookie`.

Run:

    httpdiff compare baseline.txt candidate.txt
