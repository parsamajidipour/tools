# Contributing to HTTPDiff

Thanks for considering a contribution! HTTPDiff is used by security
researchers to make real decisions, so correctness and conservative wording
matter more than raw feature count.

## Development setup

```bash
git clone <repo-url>
cd httpdiff
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running checks locally

```bash
python -m pytest                 # test suite
python -m pytest --cov=httpdiff  # with coverage
ruff check .                     # lint
mypy httpdiff                    # type check
```

## Project layout

- `httpdiff/parser.py` — raw HTTP/1.x response parsing
- `httpdiff/normalization.py` — dynamic-value suppression rules
- `httpdiff/analyzers/` — one module per aspect (headers, cookies, body,
  JSON/HTML/XML, reflection, redirect, caching). Analyzers only produce
  `Difference` objects; they never decide severity.
- `httpdiff/rules/` — the security rule engine. Rules consume `Difference`
  objects (plus the original responses) and produce `Finding` objects with
  severity/confidence/evidence/recommendation.
- `httpdiff/reporters/` — terminal, JSON, and Markdown renderers.
- `httpdiff/cli.py` — argument parsing and command dispatch.

## Adding a new rule

1. Add a `Rule` subclass in the appropriate `httpdiff/rules/*.py` file.
2. Register it in `httpdiff/rules/__init__.py`'s `default_rules()`.
3. Give it a stable `rule_id` following the `HTTPDIFF-<CATEGORY>-<NNN>`
   convention (see existing rules for examples).
4. Write the finding conservatively: state the evidence you actually have,
   not the conclusion you suspect. Every finding should include
   `false_positive_notes` describing when the finding is expected to be
   benign.
5. Add unit tests in `tests/unit/test_rules.py` covering both the case where
   the rule *should* fire and at least one case where it should *not*.

## Adding a new analyzer

Analyzers live in `httpdiff/analyzers/`. They take parsed data (headers,
cookies, bodies) and return a `list[Difference]`. Keep analyzers pure functions
where possible — no I/O, no global state — so they stay easy to test in
isolation.

## Style

- Full type hints on all public functions.
- No bare `except:` — catch specific exceptions, or `Exception` with a
  comment explaining why the boundary needs to be broad (e.g. the rule
  engine isolating a single misbehaving rule).
- Prefer clarity over cleverness; this is a security tool people will read
  the source of to decide whether to trust a finding.

## Reporting bugs / requesting features

Open a GitHub issue. For anything that could be a security issue in
HTTPDiff itself (not a finding accuracy issue), see `SECURITY.md` instead.
