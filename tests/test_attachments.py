import base64
from unittest.mock import MagicMock, patch

import pytest

from odoo_mcp import server
from odoo_mcp.attachments import MAX_ATTACHMENT_BYTES, attachment_values


def values(**overrides):
    args = dict(
        name="screen.png", content_base64="aGVsbG8=", mimetype=None, res_model=None, res_id=None, description=None
    )
    args.update(overrides)
    return attachment_values(**args)


def test_binary_and_record_metadata():
    result = values(res_model="website.page", res_id=42, description="After redesign")
    assert base64.b64decode(result["datas"]) == b"hello"
    assert result["public"] is False
    assert result["mimetype"] == "image/png"
    assert (result["res_model"], result["res_id"]) == ("website.page", 42)


@pytest.mark.parametrize(
    "overrides",
    [
        {"name": "../secret"},
        {"name": "bad\nname"},
        {"content_base64": "data:image/png;base64,AA=="},
        {"content_base64": ""},
        {"content_base64": "!!!!"},
        {"res_model": "website.page"},
        {"res_id": 1},
        {"res_model": "website.page", "res_id": 0},
        {"res_model": "website.page", "res_id": True},
        {"mimetype": "image/png\r\n"},
        {"content_base64": "A" * (4 * ((MAX_ATTACHMENT_BYTES + 2) // 3) + 4)},
    ],
)
def test_invalid_upload(overrides):
    with pytest.raises(ValueError):
        values(**overrides)


def test_upload_gate_binds_bytes_and_reuses_create(monkeypatch):
    monkeypatch.setenv("MCP_SAFETY_MODE", "strict")
    monkeypatch.delenv("MCP_READ_ONLY", raising=False)
    monkeypatch.delenv("MCP_WRITE_ALLOWLIST", raising=False)
    monkeypatch.delenv("MCP_VALIDATE_PAYLOADS", raising=False)
    client = MagicMock()
    client.execute_method.return_value = [17]
    args = dict(ctx=MagicMock(), name="screen.png", content_base64="aGVsbG8=")
    with (
        patch.object(server, "get_odoo_client", return_value=client),
        patch.object(server, "_fields_loader", return_value=lambda model: {"public": {"type": "boolean"}}),
        patch.object(server, "_reject_private_method", return_value=None),
    ):
        first = server.upload_attachment(**args)
        assert first.pending_confirmation
        client.execute_method.assert_not_called()
        token = first.hint.split("confirmation_token='")[1].split("'")[0]
        wrong = server.upload_attachment(
            **{**args, "content_base64": "d29ybGQ="}, confirmed=True, confirmation_token=token
        )
        assert not wrong.success
        client.execute_method.assert_not_called()
        first = server.upload_attachment(**args)
        token = first.hint.split("confirmation_token='")[1].split("'")[0]
        result = server.upload_attachment(**args, confirmed=True, confirmation_token=token)
        assert result.success and result.result == [17]
        call = client.execute_method.call_args
        assert call.args == ("ir.attachment", "create")
        assert call.kwargs["vals_list"][0]["public"] is False
        assert "image_no_postprocess" not in (call.kwargs.get("context") or {})


def test_upload_readonly_never_resolves_client(monkeypatch):
    monkeypatch.setenv("MCP_READ_ONLY", "true")
    with patch.object(server, "get_odoo_client") as client:
        result = server.upload_attachment(ctx=MagicMock(), name="file.txt", content_base64="aGk=")
    assert not result.success
    client.assert_not_called()
