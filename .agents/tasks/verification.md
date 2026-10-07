# Verification — Finding 1 (idp-2026-10-06)

All commands run inside the worktree
`/Users/topazb/repos/identity-provider/.worktrees/sec-f1-restore-integrity`
with the venv activated (`source /Users/topazb/python/py314/bin/activate`,
Python 3.14 at `/Users/topazb/python/py314/`).

## ruff check identity_provider_server/

```
All checks passed!
EXIT=0
```

Also ran ruff on every touched production + primary-test file
(`identity_provider_server/{admin,backup,backup_cli}.py`,
`tests/test_backup.py`, `tests/test_backup_cli.py`,
`tests/test_backup_portal.py`): **All checks passed!**

Note: the broader `ruff check identity_provider_server tests` reports ~110
pre-existing baseline findings in files this task did NOT touch
(`tests/integration/*`, `tests/test_admin_full.py`,
`tests/test_remaining_coverage.py`, etc.: unsorted imports, unused
`pytest`/`json`, E501). My edits to `test_admin_full.py` and
`test_remaining_coverage.py` changed only archive-name string literals
(`.tar.gz` → `.tar.gz.enc`) and introduced zero new ruff findings. The
task's enforced gate command `ruff check identity_provider_server/` is clean.

## bandit -r identity_provider_server/ (medium+)

```
bandit -q -ll -r identity_provider_server
```

No `>> Issue` lines and no Medium/High severity findings — clean at medium+.
The `# nosec B202` previously on `backup.py` `tar.extract` was removed: with
`filter="data"` added, bandit does not flag B202 and stays clean without the
suppression. (Baseline `nosec encountered` INFO lines for other modules'
B105/B404/B603 markers are unrelated to Finding 1.)

## pytest -q (full suite, with coverage)

```
python3 -m pytest -q --cov=identity_provider_server --cov-report=term-missing
```

```
TOTAL                                         3698      0   100%
Required test coverage of 100.0% reached. Total coverage: 100.00%
663 passed, 28 skipped, 2 warnings in 60.69s (0:01:00)
EXIT=0
```

(The 28 skips are the `tests/integration/*` live-IdP/browser tests, skipped
without credentials — same as baseline. Coverage gate `fail_under = 100` holds.)

## pytest -m smoke -q

```
28 passed, 663 deselected in 29.32s
EXIT=0
```

Includes the newly `@pytest.mark.smoke`-marked happy path
`tests/test_backup_cli.py::test_do_restore_encrypted_archive`.

## New / updated tests (fail without the fix, pass with it)

- `tests/test_backup_portal.py`
  - `test_restore_rejects_plaintext_archive_name` — portal rejects `.tar.gz`.
  - `test_restore_accepts_encrypted_archive_name` — portal accepts `.tar.gz.enc`.
  - `test_restore_with_valid_mfa_triggers_unit` / `test_restore_requires_confirmation`
    updated to encrypted names; asserts unit
    `idp-restore@idp-20260101-000000.tar.gz.enc.service`.
- `tests/test_backup_cli.py`
  - `test_do_restore_refuses_plaintext_archive` — fail-closed: rc==2, no mount.
  - `test_do_restore_encrypted_archive` — kept as encrypted happy path, now
    `@pytest.mark.smoke`.
- `tests/test_backup.py`
  - `test_validate_archive_rejects_setuid_member` (0o4755).
  - `test_validate_archive_rejects_world_writable_member` (0o666).
  - `test_validate_archive_accepts_benign_modes` (0o644 / 0o600, no over-reject).
  - `test_restore_archive_uses_data_filter` — asserts `filter="data"` kwarg.
- `tests/test_admin_full.py`, `tests/test_remaining_coverage.py` — archive-name
  literals updated to `.tar.gz.enc` so pre-existing mount-failure /
  not-found / oserror / trigger-failure paths still execute under the new guard.

## Pre-work

Copied git-ignored local test secrets into the worktree data dir
(`data/idp.key`, `data/users.json`) so `tests/test_backup_portal.py` fixtures
resolve. Confirmed they remain git-ignored (not staged/committed).
