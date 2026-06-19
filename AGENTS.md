# Engineering Principles

Guidelines for human and AI contributors working on the Tet framework.

## Design philosophy

Tet is a **batteries-included Pyramid framework**. We add value by
providing well-integrated defaults, not by inventing new paradigms.
When Pyramid already has a mechanism, wrap or configure it — don't
replace it.

### Extend, don't fork

Every Tet module should be usable by a vanilla Pyramid app via
`config.include()`. If using Tet requires abandoning standard Pyramid
patterns, the design is wrong.

### One way to do it

Prefer a single well-documented way over multiple options. If a
feature can be a `config.include()`, don't also make it a decorator,
a class mixin, and a settings key. Convenience re-exports are fine;
duplicate mechanisms are not.

### Explicit over implicit

- Services are registered explicitly via `config.include()` and
  `config.register_service_factory()`, not auto-discovered.
- Configuration is passed via `set_token_authentication()` or
  similar directives — not read from magic settings keys.
- Imports come from `tet.security`, `tet.services`, etc. — not from
  a top-level `tet` namespace that re-exports everything.

### Dependencies are a liability

Core `tet` depends only on Pyramid, SQLAlchemy, passlib, and
pyramid_di. Everything else belongs in extras (`[security]`, etc.).
A module that adds a dependency must justify it. Never add a
dependency for a single use that stdlib can handle.

## Code standards

### Python version

Minimum supported: **Python 3.10**. Use modern syntax freely:
`int | str`, `match`/`case`, `dict[str, Any]`, `list[int]`.
No `from __future__ import annotations`.

### Formatting and linting

**ruff** for both linting and formatting (no Black). Configuration
lives in `pyproject.toml`. Run `ruff check --fix . && ruff format .`
before committing. Pre-commit hooks enforce this automatically.

### Type annotations

Annotate public APIs. Use `typing` imports (`tp.Optional`, `tp.Any`)
for complex types; use built-in syntax for simple ones (`dict`, `list`,
`int | None`). Don't annotate private helpers unless it aids readability.

### Docstrings

Public classes and functions get docstrings. Use imperative mood
("Create a token", not "Creates a token" or "This method creates...").
Keep Args/Returns sections short. Skip docstrings on `includeme()`,
test functions, and obvious one-liners.

### No comments explaining what

Comments explain *why*, never *what*. If you need a comment to explain
what code does, rename the variables or extract a function instead.

## Architecture patterns

### Service layer (`pyramid_di`)

Services are the primary abstraction for business logic:

- **Request-scoped** (`RequestScopedBaseService`) for anything that
  touches the current request, session, or database.
- **Application-scoped** (`ApplicationScopedBaseService`) for
  singletons that live for the app's lifetime.
- Inject dependencies with `autowired()`:
  `db_session: Session = autowired(Session)`.
- Register in `includeme()` via `config.register_service_factory()`.

### Model mixins

Reusable database schemas are provided as **SQLAlchemy mixins**, not
base classes. The consuming app adds foreign keys, constraints, and
table args. Mixins define columns and helper methods only.

Examples: `TokenMixin`, `MultiFactorAuthenticationMethodMixin`,
`UserPasswordMixin`.

### Configuration directives

Complex setup (like `set_token_authentication()`) is done via Pyramid
**config directives** registered in `includeme()`. Directives store
configuration on `config.registry` and use Pyramid's conflict
detection (`config.action()`).

### Events

Use Pyramid's event system for cross-cutting concerns (logging,
auditing, notifications). Define events as **dataclasses** inheriting
from a base event class. Fire with `config.registry.notify()`.
Subscribe with `config.add_subscriber()`.

### Compatibility imports

When Pyramid moves symbols between releases (e.g., `pyramid.security`
to `pyramid.authorization`), create a `compat.py` that does the
try/except import dance. All other modules import from `compat.py`,
never directly from the Pyramid module that might move.

## Security principles

### Secrets at rest

- Tokens are stored **hashed** (SHA-256). The plaintext is returned
  once at creation and never stored.
- Passwords are hashed via passlib (currently sha256_crypt).
- TOTP secrets in the database are a known gap — application-level
  encryption is planned.

### Secrets in transit

- Refresh tokens go in `HttpOnly; Secure; SameSite` cookies.
- Access tokens (JWTs) are short-lived (default 15 minutes).
- Signing keys are provided by the application via a callback, never
  hardcoded or stored in settings.

### Fail closed

- Missing or invalid tokens → 401.  No silent fallbacks.
- Rate limiting records are written on a separate DB connection so
  they survive transaction rollbacks (a failed login still counts).
- TOTP replay protection is opt-in but recommended.

### Don't roll your own crypto

Use `secrets` for token generation, `hashlib`/`hmac` for hashing,
`PyJWT` for JWT encoding/verification, `pyotp` for TOTP. No custom
cryptographic primitives.

## Testing

### Test layout

- Tests live in `tests/` at the repo root (not inside `src/`).
- Test files mirror the source structure:
  `tests/services/security/test_authentication.py` tests
  `src/tet/security/authentication.py`.

### Test types

- **Unit tests**: mock external dependencies, fast, no database.
- **Integration tests**: use a real PostgreSQL database
  (`test_tet` on localhost). Fixtures handle setup/teardown.
- **Public API contract tests** (`test_public_api.py`): import every
  public symbol from every public module. If anything is removed or
  renamed, this test breaks. This is the API stability guarantee.

### Fixtures

- `pyramid_app` — fully configured WSGI app with all security
  services registered.
- `pyramid_request` — a request context bound to the app.
- `db_session` — a transactional database session (rolled back after
  each test).

### Coverage

Aim for >95% on new code. Don't test framework internals (Pyramid's
job) or trivial property accessors. Do test error paths, edge cases,
and security-sensitive logic.

## Packaging

### Source layout

The package lives under `src/tet/` (PEP 621 src layout).
`pyproject.toml` is the single source of truth for metadata,
dependencies, and tool configuration. There is no `setup.py` or
`setup.cfg`.

### Extras

- `[security]` — JWT auth, TOTP MFA, rate limiting dependencies.
- `[dev]` — everything needed to develop and test (includes
  `[security]`).
- `[test]` — CI test dependencies (includes `[security]`).

### Versioning

Follow PEP 440. Use alpha/beta/rc suffixes for pre-releases
(`0.6a1`, `0.6b1`, `0.6rc1`). Bump the version in `pyproject.toml`
and add a `CHANGES.md` entry in the same commit.

## Git workflow

### Branches

- `master` is the release branch. It should always be in a
  releasable state.
- Feature branches are rebased onto master before merging.
- Use descriptive branch names: `jwt-token-auth`, not `feature-1`.

### Commits

- Write imperative commit messages: "Add rate limiting", not "Added"
  or "Adds".
- One logical change per commit. Separate formatting from logic.
- Reference issues/PRs in the commit body, not the subject line.

### Pull requests

- PRs go against `master` on `tetframework/tet`.
- Development happens on forks (`interjektio/tet`).
- Squash-merge is acceptable for single-feature branches. Rebase
  merge for branches with meaningful intermediate history.

## Documentation

### Where things live

- `CLAUDE.md` — AI agent instructions (codebase overview, patterns).
- `AGENTS.md` — this file (engineering principles).
- `docs/narr/` — narrative documentation (Sphinx/RST).
- `docs/api/` — auto-generated API reference (Sphinx autodoc).
- `docs/tutorials/` — step-by-step tutorials.
- `CHANGES.md` — release changelog.
- `SECURITY.md` — vulnerability reporting policy.

### Docs build

Sphinx with `myst_parser` (Markdown support) and `sphinx_rtd_theme`.
Build with: `python -m sphinx docs docs/_build`. The
`autodoc-process-signature` hook in `conf.py` handles `pyramid_di`
`reify_attr` descriptors so they render as typed attributes instead
of raising warnings.
