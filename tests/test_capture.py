import base64
import io
import json
import socket
from dataclasses import replace
from unittest.mock import MagicMock, patch

import pytest

from odoo_mcp import server
from odoo_mcp.capture import CaptureRequest
from odoo_mcp.capture_policy import CaptureError, CapturePolicy, safe_url
from odoo_mcp.capture_proxy import connect_checked


def policy(**kwargs):
    return CapturePolicy(hosts=("*.leonix.cc",), private_hosts=(), **kwargs)


def addresses(ip):
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "data:text/html,test",
        "chrome://settings",
        "http://127.0.0.1",
        "http://169.254.169.254/latest/meta-data",
        "https://example.com",
        "https://evil.leonix.cc.attacker.com",
        "https://leonix.cc",
        "https://user:secret@test.leonix.cc",
        "https://test.leonix.cc:8000",
        "https://test.leonix.cc\\@evil.com",
        "https://test.leonix.cc\r\nHost: localhost",
    ],
)
def test_invalid_targets(url):
    with pytest.raises(CaptureError):
        policy().validate_url(url)


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "169.254.169.254",
        "10.1.2.3",
        "172.16.0.1",
        "192.168.1.1",
        "0.0.0.0",
        "100.100.100.200",
        "224.0.0.1",
    ],
)
def test_dns_must_not_resolve_to_forbidden_networks(ip):
    with patch("socket.getaddrinfo", return_value=addresses(ip)), pytest.raises(CaptureError):
        connect_checked(policy(), "https://test.leonix.cc")


def test_private_network_opt_in_and_metadata_remains_blocked():
    private = replace(policy(), private_hosts=("test.leonix.cc",))
    with patch("socket.getaddrinfo", return_value=addresses("10.1.2.3")), patch("socket.socket") as sock:
        connect_checked(private, "https://test.leonix.cc")
        sock.return_value.connect.assert_called_once_with(("10.1.2.3", 443))
    with patch("socket.getaddrinfo", return_value=addresses("169.254.169.254")), pytest.raises(CaptureError):
        connect_checked(private, "https://test.leonix.cc")


def test_rebinding_connects_to_validated_ip_and_checks_next_connection():
    with patch("socket.getaddrinfo", side_effect=[addresses("93.184.216.34"), addresses("127.0.0.1")]) as dns:
        with patch("socket.socket") as sock:
            connect_checked(policy(), "https://test.leonix.cc")
            sock.return_value.connect.assert_called_once_with(("93.184.216.34", 443))
            assert dns.call_count == 1
            with pytest.raises(CaptureError):
                connect_checked(policy(), "https://test.leonix.cc")
            assert sock.return_value.connect.call_count == 1


def test_redirect_target_has_independent_dns_validation():
    with patch("socket.getaddrinfo", side_effect=[addresses("93.184.216.34"), addresses("10.0.0.1")]):
        with patch("socket.socket") as sock:
            connect_checked(policy(), "https://source.leonix.cc")
            with pytest.raises(CaptureError):
                connect_checked(policy(), "https://redirect.leonix.cc")
            assert sock.return_value.connect.call_count == 1


def test_url_redaction_and_secret_repr():
    assert safe_url("https://user:pass@test.leonix.cc/path?token=SECRET#fragment") == "https://test.leonix.cc/path"
    request = CaptureRequest(url="https://test.leonix.cc", headers={"Authorization": "SECRET"})
    assert "SECRET" not in repr(request)
    assert "SECRET" not in str(request.model_dump())
    assert request.worker_payload()["headers"]["Authorization"] == "SECRET"
    assert request.digest() != CaptureRequest(url=request.url).digest()


@pytest.fixture
def stub(monkeypatch):
    monkeypatch.setenv("MCP_SAFETY_MODE", "strict")
    for key in ("MCP_READ_ONLY", "MCP_WRITE_ALLOWLIST", "MCP_VALIDATE_PAYLOADS", "MCP_CAPTURE_ALLOWED_HOSTS"):
        monkeypatch.delenv(key, raising=False)
    client = MagicMock(url="https://test.leonix.cc", username="agent")
    client.execute_method.return_value = [17]
    monkeypatch.setattr(server, "get_odoo_client", lambda: client)
    monkeypatch.setattr(server, "_reject_private_method", lambda *args: None)
    monkeypatch.setattr(server, "_fields_loader", lambda *args: lambda model: {"public": {"type": "boolean"}})
    return client


def captured():
    return dict(
        success=True,
        content_base64="aGVsbG8=",
        mimetype="image/png",
        size=5,
        url_final="https://test.leonix.cc/page",
        title="Page",
        http_status=200,
        captured_at="2026-11-04T00:00:00+00:00",
        blocked_subrequests=False,
    )


def token(response):
    assert response.pending_confirmation, response
    return response.hint.split("confirmation_token='")[1].split("'")[0]


def test_capture_gated_before_render_and_returns_metadata_only(stub):
    stub.execute_method.side_effect = lambda model, method, **kwargs: (
        [17] if method == "create" else [{"name": "after.png", "mimetype": "image/png", "file_size": 3}]
    )
    args = dict(ctx=MagicMock(), url="https://test.leonix.cc/page?token=SECRET", name="after.png")
    with patch.object(server, "run_capture", return_value=captured()) as worker:
        first = server.capture_page(**args)
        worker.assert_not_called()
        stub.execute_method.assert_not_called()
        result = server.capture_page(**args, confirmed=True, confirmation_token=token(first))
    assert result.success and result.result["attachment_id"] == 17
    assert "content_base64" not in result.result and "datas" not in result.model_dump_json()
    create = stub.execute_method.call_args_list[0]
    vals = create.kwargs["vals_list"][0]
    assert "image_no_postprocess" not in (create.kwargs.get("context") or {})
    assert result.result["size"] == 3  # Odoo's stored size after normal postprocessing.
    assert "datas" not in stub.execute_method.call_args.kwargs["fields"]
    assert vals["public"] is False and vals["datas"] == "aGVsbG8="
    assert "SECRET" not in vals["description"]
    assert vals["name"] == "after.png"


def test_capture_token_rejects_changed_url_or_storage_target(stub):
    args = dict(ctx=MagicMock(), url="https://test.leonix.cc/page")
    with patch.object(server, "run_capture") as worker:
        first = server.capture_page(**args)
        result = server.capture_page(**args, name="different.png", confirmed=True, confirmation_token=token(first))
        assert not result.success
        worker.assert_not_called()
        stub.execute_method.assert_not_called()


@pytest.mark.parametrize("setting,value", [("MCP_READ_ONLY", "true"), ("MCP_WRITE_ALLOWLIST", "res.partner.create")])
def test_capture_obeys_write_guards(stub, monkeypatch, setting, value):
    monkeypatch.setenv(setting, value)
    with patch.object(server, "run_capture") as worker:
        result = server.capture_page(ctx=MagicMock(), url="https://test.leonix.cc/page")
    assert not result.success
    worker.assert_not_called()
    stub.execute_method.assert_not_called()


def test_capture_readonly_role_cannot_render(stub):
    with patch.object(server, "current_role", return_value="readonly"), patch.object(server, "run_capture") as worker:
        result = server.capture_page(ctx=MagicMock(), url="https://test.leonix.cc/page")
    assert not result.success
    worker.assert_not_called()


def test_list_attachment_query_only_requests_metadata(stub):
    result = server.list_attachments(ctx=MagicMock(), res_model="website.page", res_id=7, name_contains="after")
    assert result.success
    kwargs = stub.execute_method.call_args.kwargs
    assert "datas" not in kwargs["fields"]
    assert ["res_id", "=", 7] in kwargs["domain"]
    assert kwargs["limit"] == 20


def metadata(mimetype="text/plain", size=5):
    return dict(id=17, name="capture", mimetype=mimetype, file_size=size, type="binary")


def test_read_text_fetches_bytes_only_after_metadata_and_paginates(stub):
    stub.execute_method.side_effect = [[metadata()], [{"datas": "aGVsbG8="}]]
    result = server.read_attachment(ctx=MagicMock(), attachment_id=17, max_chars=3)
    payload = json.loads(result.content[0].text)
    assert payload["text"].startswith("hel") and payload["next_offset"] == 3
    assert payload["truncated"] and "UNTRUSTED" in payload["content_notice"]
    assert stub.execute_method.call_args.kwargs["context"]["bin_size"] is False


def test_read_acl_failure_does_not_fetch_bytes_or_leak_error(stub):
    stub.execute_method.side_effect = PermissionError("SECRET")
    result = server.read_attachment(ctx=MagicMock(), attachment_id=17)
    assert result.is_error and "SECRET" not in result.content[0].text
    assert stub.execute_method.call_count == 1


def test_read_oversized_or_unsupported_file_never_fetches_bytes(stub):
    stub.execute_method.return_value = [metadata(size=30 * 1024 * 1024)]
    assert server.read_attachment(ctx=MagicMock(), attachment_id=17).is_error
    assert stub.execute_method.call_count == 1
    stub.execute_method.reset_mock()
    stub.execute_method.return_value = [metadata(mimetype="application/zip")]
    result = server.read_attachment(ctx=MagicMock(), attachment_id=17)
    assert not result.is_error and not json.loads(result.content[0].text)["supported"]
    assert stub.execute_method.call_count == 1


def test_tall_image_is_tiled_and_original_preserved(stub):
    Image = pytest.importorskip("PIL.Image")
    from odoo_mcp.attachment_content import image_preview

    stream = io.BytesIO()
    Image.new("RGB", (1000, 6000), "blue").save(stream, format="PNG")
    data = stream.getvalue()
    image, details = image_preview(data, tile=2)
    assert image.type == "image" and details["tile_count"] == 4
    assert details["width"] == 1000 and details["height"] == 1568
    stub.execute_method.side_effect = [[metadata("image/png", len(data))], [{"datas": base64.b64encode(data).decode()}]]
    result = server.read_attachment(ctx=MagicMock(), attachment_id=17)
    assert [content.type for content in result.content] == ["text", "image"]


def test_pdf_text_and_optional_rendered_page():
    pymupdf = pytest.importorskip("pymupdf")
    pytest.importorskip("PIL")
    from odoo_mcp.attachment_content import preview_content

    with pymupdf.open() as document:
        document.new_page().insert_text((40, 40), "Review this design")
        data = document.tobytes()
    result, images = preview_content(metadata("application/pdf", len(data)), data, render_pages=[1])
    assert "Review this design" in result["text"] and result["page_count"] == 1
    assert len(images) == 1 and images[0].type == "image"


@pytest.mark.parametrize("mime", ["text/html", "text/markdown", "text/plain", "text/csv", "application/json"])
def test_text_like_files_preview_as_untrusted_text(mime):
    from odoo_mcp.attachment_content import preview_content

    result, images = preview_content(metadata(mime), b"hello", max_chars=3)
    assert result["text"].startswith("hel") and result["next_offset"] == 3
    assert not images


@pytest.mark.parametrize(
    "field,value",
    [("x", -1), ("y", -1), ("width", 0), ("height", 0), ("x", float("nan")), ("height", float("inf")), ("width", 4097)],
)
def test_invalid_clip(field, value):
    clip = dict(x=0, y=800, width=1440, height=600)
    clip[field] = value
    with pytest.raises(ValueError):
        CaptureRequest(url="https://test.leonix.cc", clip=clip)


@pytest.mark.parametrize("fmt", ["pdf", "html", "text", "md"])
def test_clip_rejects_non_image_formats(fmt):
    with pytest.raises(ValueError, match="PNG and JPEG"):
        CaptureRequest(url="https://test.leonix.cc", format=fmt, clip=dict(x=0, y=0, width=100, height=100))


def test_selector_cropping_removed():
    with pytest.raises(ValueError):
        CaptureRequest(url="https://test.leonix.cc", selector="section")


def test_clip_is_bound_to_confirmation(stub):
    from odoo_mcp.capture import CaptureClip

    args = dict(
        ctx=MagicMock(), url="https://test.leonix.cc/page", clip=CaptureClip(x=0, y=800, width=1440, height=600)
    )
    with patch.object(server, "run_capture") as worker:
        first = server.capture_page(**args)
        args["clip"] = CaptureClip(x=0, y=900, width=1440, height=600)
        result = server.capture_page(**args, confirmed=True, confirmation_token=token(first))
        assert not result.success
        worker.assert_not_called()


@pytest.mark.parametrize("fmt", ["png", "jpeg"])
@pytest.mark.parametrize(
    "clip,error",
    [
        (dict(x=20, y=1800, width=600, height=400), None),
        (dict(x=20, y=2800, width=600, height=400), "fit within"),
        (dict(x=1400, y=0, width=600, height=400), "fit within"),
        (dict(x=0, y=0, width=600, height=50000), "dimensions"),
    ],
)
def test_worker_uses_page_relative_clip(fmt, clip, error):
    import asyncio
    from contextlib import nullcontext
    from unittest.mock import AsyncMock

    from odoo_mcp.capture_worker import render

    request = CaptureRequest(url="https://test.leonix.cc", format=fmt, clip=clip).worker_payload()
    page = MagicMock(url=request["url"])
    page.goto = AsyncMock(return_value=MagicMock(status=200))
    page.evaluate = AsyncMock(return_value=dict(width=1440, height=3000))
    page.screenshot = AsyncMock(return_value=b"image")
    page.title = AsyncMock(return_value="Test")
    context = MagicMock()
    context.new_page = AsyncMock(return_value=page)
    context.route = AsyncMock()
    context.route_web_socket = AsyncMock()
    browser = MagicMock()
    browser.new_context = AsyncMock(return_value=context)
    browser.close = AsyncMock()
    playwright = MagicMock()
    playwright.chromium.launch = AsyncMock(return_value=browser)
    manager = MagicMock()
    manager.__aenter__ = AsyncMock(return_value=playwright)
    manager.__aexit__ = AsyncMock(return_value=False)
    proxy = MagicMock(server_address=("127.0.0.1", 1234), blocked=False)
    with (
        patch("playwright.async_api.async_playwright", return_value=manager),
        patch("odoo_mcp.capture_worker.capture_proxy", return_value=nullcontext(proxy)),
    ):
        if error:
            with pytest.raises(CaptureError, match=error):
                asyncio.run(render(request, policy()))
            page.screenshot.assert_not_called()
            return
        result = asyncio.run(render(request, policy()))
    assert result["success"]
    options = page.screenshot.call_args.kwargs
    assert options["clip"] == clip and options["full_page"] is False
