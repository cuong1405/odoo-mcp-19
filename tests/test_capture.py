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


@pytest.mark.parametrize("fmt", ["pdf", "html", "text", "md"])
def test_section_rejects_non_image_formats(fmt):
    with pytest.raises(ValueError, match="PNG and JPEG"):
        CaptureRequest(url="https://test.leonix.cc", format=fmt, selectors=["#target"])


@pytest.mark.parametrize(
    "extra",
    [
        {"clip": dict(x=-1, y=800, width=1440, height=600)},
        {"selectors": [" "]},
        {"expected_text": "Heading"},
        {"selectors": ["#target"], "expected_text": " "},
    ],
)
def test_section_rejects_unverified_coordinate_inputs(extra):
    with pytest.raises(ValueError):
        CaptureRequest(url="https://test.leonix.cc", **extra)


@pytest.fixture
def browser_stubs():
    from unittest.mock import AsyncMock

    page = MagicMock(url="https://test.leonix.cc")
    page.goto = AsyncMock(return_value=MagicMock(status=200))
    page.evaluate = AsyncMock(return_value=dict(width=1440, height=3000))
    page.add_style_tag = AsyncMock()
    page.screenshot = AsyncMock(return_value=b"image")
    page.title = AsyncMock(return_value="Test")
    target = MagicMock()
    target.count = AsyncMock(return_value=1)
    target.wait_for = AsyncMock()
    target.scroll_into_view_if_needed = AsyncMock()
    target.inner_text = AsyncMock(return_value="Ghi nhận một lần.")
    target.evaluate = AsyncMock(return_value=dict(x=20, y=1800, width=600, height=400))
    page.locator.return_value = target
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
    return page, target, manager


@pytest.mark.parametrize("count", [0, 2])
def test_measure_section_rejects_missing_or_ambiguous_target(browser_stubs, count):
    import asyncio

    from odoo_mcp.capture_worker import measure_region

    page, target, _ = browser_stubs
    target.count.return_value = count
    with pytest.raises(CaptureError, match="exactly one"):
        asyncio.run(measure_region(page, ["section"], None, dict(top=0, right=0, bottom=0, left=0)))
    target.evaluate.assert_not_called()
    page.screenshot.assert_not_called()


def test_measure_section_checks_content_before_measuring(browser_stubs):
    import asyncio

    from odoo_mcp.capture_worker import measure_region

    page, target, _ = browser_stubs
    with pytest.raises(CaptureError, match="expected_text"):
        asyncio.run(measure_region(page, ["#target"], "Wrong heading", dict(top=0, right=0, bottom=0, left=0)))
    page.screenshot.assert_not_called()


def test_measure_section_refuses_moving_layout(browser_stubs):
    import asyncio

    from odoo_mcp.capture_worker import measure_region

    page, target, _ = browser_stubs
    target.evaluate.side_effect = [None] + [dict(x=0, y=y, width=600, height=400) for y in range(12)]
    with pytest.raises(CaptureError, match="moving"):
        asyncio.run(measure_region(page, ["#target"], None, dict(top=0, right=0, bottom=0, left=0)))
    page.screenshot.assert_not_called()


@pytest.mark.parametrize("fmt", ["png", "jpeg"])
def test_capture_uses_agent_chosen_coordinates_without_remeasurement(browser_stubs, fmt):
    import asyncio
    from contextlib import nullcontext

    from odoo_mcp.capture_worker import render

    page, target, manager = browser_stubs
    clip = dict(x=0, y=1500, width=1400, height=1000)
    request = CaptureRequest(url=page.url, format=fmt, clip=clip)
    proxy = MagicMock(server_address=("127.0.0.1", 1234), blocked=False)
    with patch("playwright.async_api.async_playwright", return_value=manager), patch(
        "odoo_mcp.capture_worker.capture_proxy", return_value=nullcontext(proxy)
    ):
        result = asyncio.run(render(request.worker_payload(), policy()))
    assert result["clip"] == clip
    assert page.screenshot.call_args.kwargs["clip"] == clip
    assert page.screenshot.call_args.kwargs["full_page"] is True
    target.evaluate.assert_not_awaited()


@pytest.mark.parametrize("scale", [1, 2])
@pytest.mark.parametrize("selectors", [["#target"], ["#first", "#last"]])
@pytest.mark.parametrize("margin", [0, 10, -10])
def test_real_browser_measures_section_below_viewport(scale, selectors, margin):
    """Exercise actual layout measurement and screenshot together, without remote requests."""
    import asyncio
    from contextlib import nullcontext
    from pathlib import Path

    playwright_api = pytest.importorskip("playwright.async_api")
    Route, async_playwright = playwright_api.Route, playwright_api.async_playwright
    Image = pytest.importorskip("PIL.Image")
    from odoo_mcp.capture_worker import render

    async def serve_page(route, **kwargs):
        await route.fulfill(
            content_type="text/html",
            body="""
            <style>body {margin:0; height:4000px; background:red}
            #target {position:absolute; left:200px; top:1800px;
                     width:600px; height:400px; background:rgb(0,128,0)}</style>
            <div id="target" aria-label="Measured section">
                <div id="first" style="position:absolute;left:0;top:0;width:100px;height:100px"></div>
                <div id="last" style="position:absolute;right:0;bottom:0;width:100px;height:100px"></div>
            </div>""",
        )

    async def capture():
        async with async_playwright() as playwright:
            if not Path(playwright.chromium.executable_path).exists():
                pytest.skip("Install Chromium with playwright install chromium")
        request = CaptureRequest(
            url="https://test.leonix.cc",
            device_scale_factor=scale,
            selectors=selectors,
        )
        proxy = MagicMock(server_address=("127.0.0.1", 1234), blocked=False)
        with patch.object(Route, "continue_", serve_page), patch(
            "odoo_mcp.capture_worker.capture_proxy", return_value=nullcontext(proxy)
        ):
            measured = await render(request.worker_payload(), policy(), measure_only=True)
            assert "content_base64" not in measured
            assert len(measured["anchors"]) == len(selectors)
            # The agent expands the server suggestion independently of the measurement input.
            bounds = measured["clip"]
            chosen = dict(
                x=bounds["x"] - margin,
                y=bounds["y"] - margin,
                width=bounds["width"] + 2 * margin,
                height=bounds["height"] + 2 * margin,
            )
            capture = CaptureRequest(url=request.url, device_scale_factor=scale, clip=chosen)
            return await render(capture.worker_payload(), policy())

    result = asyncio.run(capture())
    assert result["clip"] == dict(x=200 - margin, y=1800 - margin, width=600 + 2 * margin, height=400 + 2 * margin)
    with Image.open(io.BytesIO(base64.b64decode(result["content_base64"]))) as image:
        assert image.size == ((600 + 2 * margin) * scale, (400 + 2 * margin) * scale)
        assert image.getpixel((image.width // 2, image.height // 2))[:3] == (0, 128, 0)
        assert image.getpixel((0, 0))[:3] == ((255, 0, 0) if margin > 0 else (0, 128, 0))


@pytest.mark.parametrize(
    "padding,expected",
    [
        (dict(top=0, right=0, bottom=0, left=0), dict(x=100, y=200, width=500, height=800)),
        (dict(top=20, right=30, bottom=40, left=10), dict(x=90, y=180, width=540, height=860)),
    ],
)
def test_region_uses_combined_anchor_bounds_and_padding(padding, expected):
    from odoo_mcp.capture_worker import region_clip

    bounds = [dict(x=100, y=200, width=200, height=100), dict(x=400, y=900, width=200, height=100)]
    assert region_clip(bounds, padding) == expected


def test_region_refuses_padding_outside_document_origin():
    from odoo_mcp.capture_worker import region_clip

    with pytest.raises(CaptureError, match="negative"):
        region_clip([dict(x=0, y=0, width=100, height=100)], dict(top=20, right=0, bottom=0, left=0))


def test_measure_region_waits_for_all_anchors_before_measuring(browser_stubs):
    import asyncio
    from unittest.mock import AsyncMock

    from odoo_mcp.capture_worker import measure_region

    page, first, _ = browser_stubs
    second = MagicMock()
    second.count = AsyncMock(return_value=1)
    second.wait_for = AsyncMock()
    second.scroll_into_view_if_needed = AsyncMock()
    second.inner_text = AsyncMock(return_value="Last section")
    first_box = dict(x=20, y=1800, width=600, height=400)
    last_box = dict(x=20, y=2400, width=600, height=400)
    first.evaluate.side_effect = [None, first_box, first_box, first_box]
    second.evaluate = AsyncMock(side_effect=[None, last_box, last_box, last_box])
    page.locator.side_effect = [first, second]
    targets, anchors, clip = asyncio.run(
        measure_region(page, ["#first", "#last"], "Last section", dict(top=0, right=0, bottom=0, left=0))
    )
    assert len(targets) == len(anchors) == 2
    assert clip == dict(x=20, y=1800, width=600, height=1000)
    second.scroll_into_view_if_needed.assert_awaited_once()


def test_measurement_returns_coordinates_without_attachment(stub):
    measured = dict(
        success=True,
        clip=dict(x=20, y=1800, width=600, height=400),
        anchors=[dict(selector="#first", clip=dict(x=20, y=1800, width=600, height=400))],
    )
    with patch.object(server, "run_capture", return_value=measured.copy()) as worker:
        result = server.measure_page(ctx=MagicMock(), url="https://test.leonix.cc", selectors=["#first"])
    assert result.success and result.result["clip"] == measured["clip"]
    assert "measurement_token" not in result.result
    assert worker.call_args.kwargs["measure_only"] is True
    stub.execute_method.assert_not_called()


def test_measurement_worker_does_not_take_screenshot(browser_stubs):
    import asyncio
    from contextlib import nullcontext

    from odoo_mcp.capture_worker import render

    page, target, manager = browser_stubs
    proxy = MagicMock(server_address=("127.0.0.1", 1234), blocked=False)
    request = CaptureRequest(url=page.url, selectors=["#target"])
    with patch("playwright.async_api.async_playwright", return_value=manager), patch(
        "odoo_mcp.capture_worker.capture_proxy", return_value=nullcontext(proxy)
    ):
        result = asyncio.run(render(request.worker_payload(), policy(), measure_only=True))
    assert result["clip"] == dict(x=20, y=1800, width=600, height=400)
    page.screenshot.assert_not_called()
    assert "content_base64" not in result


def test_agent_can_adjust_measurement_before_capture(stub):
    from odoo_mcp.capture import CaptureClip

    bounds = dict(x=20, y=1800, width=600, height=400)
    measured_result = dict(success=True, clip=bounds, anchors=[dict(selector="#target", clip=bounds)])
    with patch.object(server, "run_capture", return_value=measured_result.copy()) as worker:
        measured = server.measure_page(ctx=MagicMock(), url="https://test.leonix.cc", selectors=["#target"])
        assert measured.success
        assert "measurement_token" not in measured.result
        stub.execute_method.assert_not_called()
        worker.reset_mock()
        chosen = CaptureClip(x=0, y=1700, width=1400, height=700)
        args = dict(ctx=MagicMock(), url="https://test.leonix.cc", clip=chosen)
        first = server.capture_page(**args)
        worker.assert_not_called()
        worker.return_value = {**captured(), "clip": chosen.model_dump()}
        result = server.capture_page(**args, confirmed=True, confirmation_token=token(first))
        assert result.success
        assert worker.call_args.args[0].clip == chosen
        assert not worker.call_args.kwargs


@pytest.mark.parametrize(
    "clip",
    [
        dict(x=-1, y=0, width=100, height=100),
        dict(x=0, y=0, width=0, height=100),
        dict(x=0, y=0, width=100, height=float("inf")),
        dict(x=0, y=0, width=4097, height=100),
    ],
)
def test_chosen_clip_keeps_normal_coordinate_limits(clip):
    with pytest.raises(ValueError):
        CaptureRequest(url="https://test.leonix.cc", clip=clip)


@pytest.mark.parametrize("fmt", ["pdf", "html", "text", "md"])
def test_chosen_clip_is_only_for_screenshots(fmt):
    with pytest.raises(ValueError, match="PNG and JPEG"):
        CaptureRequest(url="https://test.leonix.cc", format=fmt, clip=dict(x=0, y=0, width=100, height=100))
