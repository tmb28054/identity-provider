"""Coverage for CLI entry points and project initialization.

Covers __main__.main, run_gunicorn.main, and init_project.run_init, including
the --init branch, ADFS config path, and cert-exists vs generate paths. The
Flask/gunicorn run calls are mocked so nothing binds a socket.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from identity_provider_server import __main__, init_project, run_gunicorn

DATA_DIR = str(Path(__file__).parent.parent / "data")


# --- __main__.main ----------------------------------------------------------

def test_main_runs_app(monkeypatch):
    fake_app = mock.Mock()
    monkeypatch.setattr(__main__, "create_app", mock.Mock(return_value=fake_app))
    monkeypatch.setattr("sys.argv", ["idp", "--data-dir", DATA_DIR, "--port", "5999"])
    __main__.main()
    fake_app.run.assert_called_once()


def test_main_init_branch(monkeypatch, tmp_path):
    called = {}
    monkeypatch.setattr(
        "identity_provider_server.init_project.run_init",
        lambda d: called.setdefault("dir", d),
    )
    monkeypatch.setattr("sys.argv", ["idp", "--init", "--data-dir", str(tmp_path)])
    with pytest.raises(SystemExit) as exc:
        __main__.main()
    assert exc.value.code == 0
    assert called["dir"] == str(tmp_path)


def test_main_init_uses_default_init_dir(monkeypatch):
    """--init with the default data-dir switches to ./data (line 108)."""
    captured = {}
    monkeypatch.setattr(
        "identity_provider_server.init_project.run_init",
        lambda d: captured.setdefault("dir", d),
    )
    monkeypatch.setattr("sys.argv", ["idp", "--init"])
    with pytest.raises(SystemExit):
        __main__.main()
    assert captured["dir"] == str(__main__.INIT_DATA_DIR)


def test_run_gunicorn_init_uses_default_init_dir(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "identity_provider_server.init_project.run_init",
        lambda d: captured.setdefault("dir", d),
    )
    monkeypatch.setattr("sys.argv", ["run-idp", "--init"])
    with pytest.raises(SystemExit):
        run_gunicorn.main()
    assert captured["dir"] == str(run_gunicorn.INIT_DATA_DIR)


def test_main_adfs_config_path(monkeypatch, tmp_path):
    fake_app = mock.Mock()
    monkeypatch.setattr(__main__, "create_app", mock.Mock(return_value=fake_app))
    monkeypatch.setattr(
        "identity_provider_server.adfs.load_adfs_config",
        lambda p: {"host": "ldaps://x", "skip_ssl_verify": True},
    )
    monkeypatch.setattr(
        "identity_provider_server.adfs.load_group_role_map", lambda d: {}
    )
    adfs_file = tmp_path / "adfs.yaml"
    adfs_file.write_text("host: ldaps://x\n")
    monkeypatch.setattr(
        "sys.argv",
        ["idp", "--data-dir", DATA_DIR, "--adfs-config", str(adfs_file), "-vv"],
    )
    __main__.main()
    fake_app.run.assert_called_once()


def test_main_all_cli_overrides(monkeypatch):
    """Exercise every 'if args.X is not None' override branch."""
    fake_app = mock.Mock()
    monkeypatch.setattr(__main__, "create_app", mock.Mock(return_value=fake_app))
    monkeypatch.setattr(
        "sys.argv",
        ["idp", "--data-dir", DATA_DIR, "--host", "0.0.0.0", "--port", "5002",
         "--debug", "--provider-name", "p", "--session-duration", "6"],
    )
    __main__.main()
    fake_app.run.assert_called_once()


def test_configure_logging_levels():
    __main__._configure_logging("INFO", 0)
    __main__._configure_logging("WARNING", 1)
    __main__._configure_logging("DEBUG", 2)


# --- _version._read_version fallbacks ---------------------------------------

def test_version_metadata_fallback(monkeypatch, tmp_path):
    from identity_provider_server import _version

    # Point at a dir with no CHANGELOG so it falls back to package metadata.
    monkeypatch.setattr(_version, "_PACKAGE_DIR", tmp_path / "pkg")
    (tmp_path / "pkg").mkdir()
    monkeypatch.setattr(
        "importlib.metadata.version", lambda name: "9.9.9"
    )
    assert _version._read_version() == "9.9.9"


def test_version_raises_when_unavailable(monkeypatch, tmp_path):
    from identity_provider_server import _version

    monkeypatch.setattr(_version, "_PACKAGE_DIR", tmp_path / "pkg")
    (tmp_path / "pkg").mkdir()

    def _boom(_name):
        raise RuntimeError("no metadata")

    monkeypatch.setattr("importlib.metadata.version", _boom)
    with pytest.raises(RuntimeError):
        _version._read_version()


# --- run_gunicorn.main ------------------------------------------------------

def test_run_gunicorn_main(monkeypatch):
    fake_app = mock.Mock()
    monkeypatch.setattr(
        "identity_provider_server.app.create_app", mock.Mock(return_value=fake_app)
    )
    # Instead of binding a socket, invoke load() so the app-loading path runs.
    monkeypatch.setattr(
        "gunicorn.app.base.BaseApplication.run", lambda self: self.load()
    )
    monkeypatch.setattr(
        "sys.argv", ["run-idp", "--data-dir", DATA_DIR, "--workers", "1"]
    )
    run_gunicorn.main()


def test_run_gunicorn_init_branch(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "identity_provider_server.init_project.run_init", lambda d: None
    )
    monkeypatch.setattr("sys.argv", ["run-idp", "--init", "--data-dir", str(tmp_path)])
    with pytest.raises(SystemExit) as exc:
        run_gunicorn.main()
    assert exc.value.code == 0


def test_run_gunicorn_adfs(monkeypatch, tmp_path):
    fake_app = mock.Mock()
    monkeypatch.setattr(
        "identity_provider_server.app.create_app", mock.Mock(return_value=fake_app)
    )
    monkeypatch.setattr(
        "gunicorn.app.base.BaseApplication.run", lambda self: None
    )
    monkeypatch.setattr(
        "identity_provider_server.adfs.load_adfs_config",
        lambda p: {"host": "ldaps://x", "skip_ssl_verify": True},
    )
    monkeypatch.setattr(
        "identity_provider_server.adfs.load_group_role_map", lambda d: {}
    )
    adfs_file = tmp_path / "adfs.yaml"
    adfs_file.write_text("host: ldaps://x\n")
    monkeypatch.setattr(
        "sys.argv",
        ["run-idp", "--data-dir", DATA_DIR, "--adfs-config", str(adfs_file),
         "--host", "0.0.0.0", "--port", "5001", "--provider-name", "p",
         "--session-duration", "4", "-v"],
    )
    run_gunicorn.main()


# --- init_project.run_init --------------------------------------------------

def test_run_init_generates_everything(monkeypatch, tmp_path):
    """Fresh dir: prompts for CN, generates cert + config + services + users."""
    monkeypatch.setattr("builtins.input", lambda _prompt="": "test-idp")
    init_project.run_init(str(tmp_path))
    for name in ("idp.crt", "idp.key", "config.yaml", "services.yaml", "users.json"):
        assert (tmp_path / name).is_file(), name
    users = json.loads((tmp_path / "users.json").read_text())
    assert users[0]["must_set_password"] is True


def test_run_init_default_cn_when_blank(monkeypatch, tmp_path):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "")
    init_project.run_init(str(tmp_path))
    assert (tmp_path / "idp.crt").is_file()


def test_run_init_existing_files_are_kept(monkeypatch, tmp_path):
    """Second run over an existing dir hits the 'already exists' branches."""
    monkeypatch.setattr("builtins.input", lambda _prompt="": "keep-idp")
    init_project.run_init(str(tmp_path))
    marker = (tmp_path / "users.json").read_text()
    # Re-run: existing cert triggers _extract_cn_from_cert + kept-file branches.
    init_project.run_init(str(tmp_path))
    assert (tmp_path / "users.json").read_text() == marker


def test_run_init_openssl_failure(monkeypatch, tmp_path):
    monkeypatch.setattr("builtins.input", lambda _prompt="": "x")
    fake = mock.Mock(returncode=1, stderr="boom", stdout="")
    monkeypatch.setattr(init_project.subprocess, "run", mock.Mock(return_value=fake))
    with pytest.raises(SystemExit) as exc:
        init_project.run_init(str(tmp_path))
    assert exc.value.code == 1


def test_extract_cn_variants(monkeypatch, tmp_path):
    cert = tmp_path / "c.crt"
    cert.write_text("dummy")
    # "CN = value" format
    monkeypatch.setattr(
        init_project.subprocess, "run",
        mock.Mock(return_value=mock.Mock(returncode=0, stdout="subject=CN = my-idp")),
    )
    assert init_project._extract_cn_from_cert(cert) == "my-idp"
    # "CN=value/O=org" format
    monkeypatch.setattr(
        init_project.subprocess, "run",
        mock.Mock(return_value=mock.Mock(returncode=0, stdout="subject=CN=a/O=org")),
    )
    assert init_project._extract_cn_from_cert(cert) == "a"
    # openssl error -> fallback
    monkeypatch.setattr(
        init_project.subprocess, "run", mock.Mock(side_effect=OSError())
    )
    assert init_project._extract_cn_from_cert(cert) == "local-idp"
