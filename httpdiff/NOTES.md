# Dev notes

Some notes on decisions that aren't obvious from the code, mostly for future me.

## No httpx

Originally used `httpx` for the `url`/`request` client but ended up dropping
it in favor of plain `urllib`. It's a bit more code (had to write my own
redirect loop) but it means `pip install httpdiff` doesn't pull in any
network dependency at all - just `beautifulsoup4`, `lxml`, and `chardet`,
which are only used for HTML parsing and charset sniffing. `rich` got
dropped too; the terminal output uses raw ANSI codes instead, it's like 15
lines.

Brotli is behind an optional extra (`pip install "httpdiff[brotli]"`) since
gzip/deflate cover the vast majority of real traffic and brotli pulls in a
compiled dependency.

## Rule engine swallows exceptions on purpose

`RuleEngine.run()` catches per-rule exceptions so one broken rule can't take
down the whole comparison. Set `HTTPDIFF_DEBUG=1` (or pass `--verbose`) to
have it print what actually broke instead of silently skipping - this bit
me once already (see below) so don't remove it.

## Things that were broken and got fixed

- `CookieRemovedRule` was matching on "one colon in the path", which also
  matched `cookie:session.secure` (attribute change), not just
  `cookie:session` (actual removal). Now checks `ChangeType.REMOVED` and no
  `.` in the path.
- Redirect analysis wasn't flagging the most common open-redirect pattern
  (relative path -> absolute cross-origin URL) because it required *both*
  sides to have a netloc. Fixed to trigger whenever the candidate side has
  one that differs.
- `DifferenceCategory` was missing `AUTHENTICATION` / `AUTHORIZATION`
  members entirely, so the two auth-related rules threw `AttributeError` on
  every single run and - because of the exception-swallowing above - just
  silently produced zero findings. This one was annoying to catch precisely
  because it failed silently; that's why the debug flag exists now.
- `Set-Cookie` header diffs weren't redacted even though the dedicated
  cookie analyzer redacts cookie values separately - so the raw header diff
  was leaking full cookie strings. Headers analyzer now redacts
  `Set-Cookie`/`Cookie`/`Authorization`/`Proxy-Authorization` by default.

## Environment note

Built and tested in a sandboxed environment with no network access, so
`pytest`/`ruff`/`mypy`/`coverage` couldn't actually be installed or run here
- the test suite is `unittest`-based (which `pytest` can run natively) and
everything was validated with `python -m unittest discover`, plus manual
CLI smoke tests and a clean wheel install/reinstall cycle. If you're
reading this after cloning normally, `pip install -e ".[dev]"` should give
you the full toolchain and `python -m pytest` should just work.

## Not done yet

- `--show-raw-diff` is defined as a CLI flag but not actually wired into the
  terminal reporter yet (`analyzers/body.py::unified_text_diff` exists and
  is ready to use).
- No coverage numbers - `coverage.py`/`pytest-cov` weren't available to run
  here. Test list is fairly thorough (see `tests/`) but I haven't measured
  the actual percentage.
- Rules are hardcoded in `rules/__init__.py`; would be nice to let people
  add their own via config at some point.
