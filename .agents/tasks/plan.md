# Implementation Plan — Finding 1 (Insecure Deserialization / unverified restore)

Security review **idp-2026-10-06**, Finding 1 (High). Harden the backup-restore
path so the admin portal can only ever select integrity-protected encrypted
archives, the privileged CLI fails closed on anything it cannot authenticate, and
tar extraction cannot apply attacker-controlled modes (setuid-root) or
world/group-writable permissions.

ALL work happens in the worktree:
`/Users/topazb/repos/identity-provider/.worktrees/sec-f1-restore-integrity`
(NOT the main checkout). Every python/pytest/ruff/bandit command must be run
after `source /Users/topazb/python/py314/bin/activate`.

## Design decisions (made during exploration, grounded in the code)

1. **backup_cli fail-closed vs. gated flag — CHOSEN: fail closed, remove the
   plaintext fallback entirely.** Rationale: `backup.py` already ships
   `create_encrypted_archive` as the only writer (daily backups are named
   `…​.tar.gz.enc`, see `backup.py` ~line 438), so no first-party plaintext
   archive is ever produced. The only source of a plaintext `.tar.gz` on the
   SMB share is a human dropping a pre-encryption legacy file or an attacker
   forging one — and the two are indistinguishable to the code because a
   plaintext archive carries no digest and no Fernet tag to authenticate. A
   gated `--allow-unverified-plaintext` flag would still leave an
   unauthenticated extraction path reachable as root; given there is no
   first-party plaintext producer, keeping that path is pure attack surface.
   We therefore delete the `else: bk.restore_archive(...)` branch in
   `do_restore` and make a non-`.enc` name return a clear error. The admin
   portal guard (part 1) already prevents the portal from ever selecting a
   non-`.enc` name, so defense is layered: the portal cannot pick it, and the
   CLI refuses it even if invoked directly. `restore_archive`'s signature is
   kept intact (still used by `restore_encrypted_archive`, which extracts the
   decrypted inner tarball, and by the backup tests).

2. **validate_archive mode-bit policy — CHOSEN: reject an enumerated set of
   dangerous bits (group/other-write `0o022`, setuid `0o4000`, setgid `0o2000`,
   sticky `0o1000`, other-execute `0o0001`), NOT "only 0600/0700".** Rationale:
   `create_archive` uses `tar.add(src, arcname=…)` (`backup.py` ~line 341),
   which captures each file's real on-disk mode. Verified empirically that a
   file created with `write_text` lands in the tar as `0o644`, and
   `tarfile.TarInfo`'s default mode is also `0o644`. A strict "members must be
   0600/0700 only" check would reject every legitimately produced archive and
   break the real round-trip (`tests/test_backup.py::test_backup_restore_round_trip`)
   and encrypted-restore tests. The enumerated forbidden-bit set blocks the
   actual attack described in the finding — a planted **setuid-root** file and
   **world/group-writable** files — while allowing the benign `0o644`/`0o600`
   modes that real backups contain. This is the security-equivalent, non-breaking
   reading of the finding's intent. Reject expression:
   `member.mode & (0o4000 | 0o2000 | 0o1000 | 0o0022 | 0o0001)` being non-zero.
   (Owner-read/write/execute `0o700` and group/other-read remain allowed.)

3. **`filter="data"` on extract.** `tar.extract(member, path=data_dir)` gains
   `filter="data"` (Python 3.12+ tarfile data filter; project targets 3.10+ but
   runs on 3.14 per the venv — the `data` filter is available). This neutralises
   absolute paths, traversal, links, device nodes, and setuid/setgid bits at
   extraction time as a second layer beneath `validate_archive`.

## Pre-work: unblock the worktree test environment

The fresh worktree is missing two git-ignored local secrets that
`tests/test_backup_portal.py` copies as fixtures (`data/idp.key`,
`data/users.json`). Without them, 10 portal tests error with
`FileNotFoundError: …/data/idp.key` — this is a worktree-setup artifact, NOT a
code defect, and is required for the full suite (and the 100% coverage gate) to
run. Verified: copying both files in makes those 10 tests pass.

- [ ] 0. Stage the local test secrets into the worktree data dir (git-ignored,
      never committed).
      Files: (copies into) `data/idp.key`, `data/users.json`
      Command: `cp /Users/topazb/repos/identity-provider/data/idp.key /Users/topazb/repos/identity-provider/.worktrees/sec-f1-restore-integrity/data/idp.key && cp /Users/topazb/repos/identity-provider/data/users.json /Users/topazb/repos/identity-provider/.worktrees/sec-f1-restore-integrity/data/users.json`
      Verify: `source /Users/topazb/python/py314/bin/activate && python3 -m pytest tests/test_backup_portal.py -q` — 10 passed. Confirm `git status` does not list `data/idp.key` or `data/users.json` (they are git-ignored).

## Source changes

- [ ] 1. **Harden the admin portal restore guard** so it can ONLY select
      encrypted archives. In `identity_provider_server/admin.py`, in the
      `restore_backup` action handler (~line 1932), change the guard
      `if "/" in archive or ".." in archive or not archive.endswith(".tar.gz"):`
      to require the encrypted suffix while KEEPING the `/` and `..` rejection.
      Use the backup module's constants rather than hardcoding: the required
      suffix is `_ARCHIVE_SUFFIX + ENCRYPTED_SUFFIX` (i.e. `.tar.gz` + `.enc`).
      Check how `admin.py` already imports the backup module (it uses `bk.`),
      and reference `bk.ENCRYPTED_SUFFIX` (`= ".enc"`); confirm/add
      `_ARCHIVE_SUFFIX` or compose with the literal `".tar.gz"` as the module
      already does elsewhere. Keep the user-facing error exactly
      `"Invalid archive name."`. The downstream unit name becomes
      `idp-restore@<name>.tar.gz.enc.service`.
      Files: `identity_provider_server/admin.py`
      Verify: `python3 -m pytest tests/test_backup_portal.py -q` passes after the
      test updates in item 5.

- [ ] 2. **Make `do_restore` fail closed** in
      `identity_provider_server/backup_cli.py` (~lines 183-220). (a) In the
      archive-name guard (~line 185-189) require the encrypted suffix only:
      replace `valid_suffix = archive.endswith(".tar.gz") or archive.endswith(".tar.gz.enc")`
      and the subsequent `not valid_suffix` with a check that rejects anything
      not ending in `bk.ENCRYPTED_SUFFIX` (keep the `/` and `..` checks and the
      `return 2`). (b) In the restore dispatch (~lines 211-215) delete the
      `else: bk.restore_archive(src, data_dir)` legacy-plaintext branch; keep
      only the encrypted path (`bk.restore_encrypted_archive(src, data_dir, key)`).
      With the suffix guard rejecting non-`.enc` names up front, the `else`
      branch becomes dead code; remove it so the file does not carry an
      unreachable unverified-extract call. Update the two code comments that
      currently say "Accept encrypted archives … and legacy plaintext" and
      "Legacy plaintext archive (pre-encryption)" to reflect encrypted-only.
      Keep `restore_archive` imported/available in `backup.py` (unchanged here).
      Files: `identity_provider_server/backup_cli.py`
      Verify: `python3 -m pytest tests/test_backup_cli.py -q` passes after the
      test updates in item 6.

- [ ] 3. **Harden `validate_archive` mode bits** in
      `identity_provider_server/backup.py` (~lines 554-577). After the existing
      regular-file and absolute-path/traversal checks, add a mode-bit check per
      design decision 2: reject any member whose
      `member.mode & (0o4000 | 0o2000 | 0o1000 | 0o0022 | 0o0001)` is non-zero,
      raising `ValueError(f"Unsafe archive member mode …: {member.name}")`.
      Add a one-line Google-style note in the docstring's existing "Rejects …"
      sentence covering setuid/setgid/sticky, group/other-write, and
      other-execute. Keep the existing checks and the return of member names.
      Files: `identity_provider_server/backup.py`
      Verify: `python3 -m pytest tests/test_backup.py -q` passes after the test
      additions in item 7.

- [ ] 4. **Add the `data` extraction filter** in
      `identity_provider_server/backup.py` `restore_archive` (~line 605). Change
      `tar.extract(member, path=data_dir)  # nosec B202` to
      `tar.extract(member, path=data_dir, filter="data")`. Attempt to drop the
      `# nosec B202` comment: baseline bandit already reports "nosec encountered
      (B202), but no failed test" for this line, so B202 does not fire — removing
      the nosec should keep bandit clean. If, after removal, bandit at medium+
      flags B202, restore the comment with an accurate justification referencing
      `validate_archive` + `_is_within` + `filter="data"`. Update the adjacent
      explanatory comment to mention the data filter.
      Files: `identity_provider_server/backup.py`
      Verify: `bandit -q -ll -r identity_provider_server/backup.py` reports no
      issues; `python3 -m pytest tests/test_backup.py -q` still passes.

## Test changes

- [ ] 5. **Update + extend the admin portal restore tests** in
      `tests/test_backup_portal.py` for the new encrypted-only guard, following
      the existing `_make_app` / `_client_with_session` / `_get_csrf` pattern and
      the `mock.patch("…admin.subprocess.run")` + `mock.patch("…admin.verify_code", return_value=True)`
      pattern already used by `test_restore_with_valid_mfa_triggers_unit`.
      (a) UPDATE `test_restore_with_valid_mfa_triggers_unit`: the archive and
      listing become `idp-20260101-000000.tar.gz.enc`, and assert the started
      unit is `idp-restore@idp-20260101-000000.tar.gz.enc.service`. (b) ADD a
      test that a plaintext `.tar.gz` name is rejected with "Invalid archive name"
      and `subprocess.run` is NOT called (mirror `test_restore_rejects_bad_archive_name`,
      using `idp-20260101-000000.tar.gz`). (c) ADD a test that a `.tar.gz.enc`
      name is ACCEPTED (reaches `_trigger_unit`), covering the positive branch
      of the new guard. (`test_restore_requires_confirmation` already fails on
      the MFA check before the guard, so it needs no change, but update its
      archive literal to `.tar.gz.enc` for realism.)
      Files: `tests/test_backup_portal.py`
      Verify: `python3 -m pytest tests/test_backup_portal.py -q` — all pass.

- [ ] 6. **Update + extend the backup_cli restore tests** in
      `tests/test_backup_cli.py` for fail-closed behaviour, following the
      `fake_mount` / `mock.patch.object(backup_cli, "_mount_smb"|"_umount")`
      pattern. (a) REPLACE `test_do_restore_happy_path` (currently builds a
      plaintext `.tar.gz` with `create_archive` and expects rc==0) with a test
      asserting that a plaintext `.tar.gz` name now fails closed: `do_restore`
      returns 2 (rejected by the suffix guard before mount) and NO extraction
      occurs. Name it e.g. `test_do_restore_refuses_plaintext_archive`. (b) KEEP
      `test_do_restore_encrypted_archive` as the encrypted happy path (it already
      uses `.tar.gz.enc` + `create_encrypted_archive`); mark it
      `@pytest.mark.smoke` if the touched area lacks a smoke test for the primary
      happy path. (c) `test_main_restore_dispatch` passes `a.tar.gz` to a mocked
      `do_restore` — unaffected (mock), leave as is or update the literal to
      `.enc` for consistency.
      Files: `tests/test_backup_cli.py`
      Verify: `python3 -m pytest tests/test_backup_cli.py -q` — all pass.

- [ ] 7. **Add `validate_archive` / `restore_archive` mode-bit tests** in
      `tests/test_backup.py`, following the existing
      `test_validate_archive_rejects_*` pattern (build a tar with a crafted
      `tarfile.TarInfo`, set `info.mode`, `tar.addfile(info)`, assert
      `pytest.raises(ValueError)`). (a) ADD a test that a member with the setuid
      bit (`info.mode = 0o4755` or `0o4700`) is rejected by `validate_archive`.
      (b) ADD a test that a world/group-writable member (`info.mode = 0o666`) is
      rejected. (c) ADD a test that a benign `0o644`/`0o600` member is ACCEPTED
      (guards against over-rejection breaking real archives). (d) ADD a test that
      `restore_archive` uses the data filter — e.g. build a valid archive, patch
      `tarfile.TarFile.extract` (or assert via a crafted link member that
      extraction is filtered) to confirm `filter="data"` is passed; simplest:
      `mock.patch.object(tarfile.TarFile, "extract")` and assert the call kwargs
      include `filter="data"`. Keep an existing smoke test (`test_backup_restore_round_trip`
      is already `@pytest.mark.smoke`) green.
      Files: `tests/test_backup.py`
      Verify: `python3 -m pytest tests/test_backup.py -q` — all pass.

## Docs

- [ ] 8. **Add a CHANGELOG entry** under `## [Unreleased]` → `### Security`
      in `CHANGELOG.md`. The current `[Unreleased]` Security section is headed
      `### Security (code review idp-20261003)`; add a NEW, separate
      `### Security (code review idp-2026-10-06)` subsection above or below it (do
      not merge into the 20261003 list), with a bullet describing the Finding 1
      fix: portal restore now accepts only integrity-protected `.tar.gz.enc`
      archives; the privileged restore CLI fails closed on any archive it cannot
      authenticate (digest + Fernet tag), the legacy plaintext fallback removed;
      `validate_archive` rejects setuid/setgid/sticky/world-or-group-writable/
      other-executable members; and `restore_archive` extracts with the tarfile
      `data` filter. Reference "review idp-2026-10-06, Finding 1". Do NOT create
      the full security-review response doc.
      Files: `CHANGELOG.md`
      Verify: `rg "idp-2026-10-06" CHANGELOG.md` shows the new entry (manual read
      to confirm wording).

## Final verification (run all, in the venv, from the worktree root)

- [ ] 9. Run the full gate and confirm green.
      Commands (after `source /Users/topazb/python/py314/bin/activate`):
      - `ruff check identity_provider_server tests` → "All checks passed!"
      - `bandit -q -ll -r identity_provider_server` → no issues of medium+ severity
      - `python3 -m pytest -q` → full suite passes (baseline: 657 passed,
        28 skipped) with the new tests added, and the coverage gate holds.
        NOTE: `pyproject.toml` sets `fail_under = 100` (the real enforced gate is
        100%, stricter than the 80% floor in the brief) and `run_tests.sh` runs
        `--cov=identity_provider_server --cov-report=term-missing`. New lines in
        `admin.py`, `backup_cli.py`, and `backup.py` must be covered by items 5-7;
        if coverage drops below 100%, add targeted tests for the uncovered
        branches (e.g. the new ValueError path, the new guard rejection path)
        rather than lowering the threshold.
      - `python3 -m pytest -m smoke -q` → smoke subset passes.
      Expected outcome: ruff clean, bandit clean at medium+, full suite + coverage
      gate pass.

## Notes / assumptions

- Line-length: `pyproject.toml` sets ruff `line-length = 100` (admin/app/totp are
  additionally E501-exempt). The brief says 88-col; follow the project's enforced
  ruff config (100) so `ruff check` passes, and match surrounding style.
- Scope is strictly Finding 1. Do NOT touch session epoch, token-in-URL,
  trust_proxy, or audit-log findings.
- `restore_archive` keeps its public signature; it is still invoked by
  `restore_encrypted_archive` (decrypted inner tarball) and by the backup tests.
- The loop stop contract is unchanged: the reviewer writes
  `.agents/tasks/review.json` last with `verdict: "APPROVED"`.
