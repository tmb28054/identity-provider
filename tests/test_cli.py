from unittest.mock import MagicMock, patch

from identity_provider_server.__main__ import main

_PATCH_CREATE = "identity_provider_server.__main__.create_app"


def test_default_args_start_server():
    mock_app = MagicMock()
    with (
        patch(_PATCH_CREATE, return_value=mock_app) as mock_create,
        patch("sys.argv", ["identity-provider-server"]),
    ):
        main()
    mock_create.assert_called_once()
    call_kwargs = mock_create.call_args
    assert call_kwargs.kwargs["host"] == "127.0.0.1"
    assert call_kwargs.kwargs["port"] == 5000
    assert call_kwargs.kwargs["provider_name"] == "local-idp"
    assert call_kwargs.kwargs["session_duration_hours"] == 1
    mock_app.run.assert_called_once_with(host="127.0.0.1", port=5000, debug=False)


def test_custom_host_port_debug():
    mock_app = MagicMock()
    with (
        patch(_PATCH_CREATE, return_value=mock_app),
        patch("sys.argv", [
            "identity-provider-server",
            "--host", "0.0.0.0",
            "--port", "8080",
            "--debug",
        ]),
    ):
        main()
    mock_app.run.assert_called_once_with(host="0.0.0.0", port=8080, debug=True)


def test_custom_data_dir_passed_to_create_app(tmp_path):
    import json
    import shutil
    from pathlib import Path

    data = Path(__file__).parent.parent / "data"
    shutil.copy(data / "idp.crt", tmp_path / "idp.crt")
    shutil.copy(data / "idp.key", tmp_path / "idp.key")
    (tmp_path / "users.json").write_text(json.dumps([]))

    mock_app = MagicMock()
    with (
        patch(_PATCH_CREATE, return_value=mock_app) as mock_create,
        patch("sys.argv", ["identity-provider-server", "--data-dir", str(tmp_path)]),
    ):
        main()
    assert mock_create.call_args[0][0] == str(tmp_path)


def test_provider_name_and_session_duration():
    mock_app = MagicMock()
    with (
        patch(_PATCH_CREATE, return_value=mock_app) as mock_create,
        patch("sys.argv", [
            "identity-provider-server",
            "--provider-name", "my-idp",
            "--session-duration", "4",
        ]),
    ):
        main()
    assert mock_create.call_args.kwargs["provider_name"] == "my-idp"
    assert mock_create.call_args.kwargs["session_duration_hours"] == 4
