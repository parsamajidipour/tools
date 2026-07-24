# Example: reflection

Demonstrates HTTPDIFF-REFLECT-001: an attacker-supplied marker value is
reflected unencoded inside an HTML attribute.

Run:

    httpdiff compare baseline.txt candidate.txt --reflection-value HTTPDIFF123
