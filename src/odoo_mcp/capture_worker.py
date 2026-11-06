"""One-shot Playwright subprocess. Protocol: JSON on stdin/stdout, no browser logs."""

import asyncio
import base64
import json
import sys
from datetime import datetime, timezone

from .capture import CaptureClip, origin
from .capture_policy import CaptureError, CapturePolicy, safe_url
from .capture_proxy import capture_proxy

MIMETYPES = {
    "png": "image/png",
    "jpeg": "image/jpeg",
    "pdf": "application/pdf",
    "html": "text/html",
    "text": "text/plain",
    "md": "text/markdown",
}


# Read layout and identity together; all coordinates stay inside this browser session.
SECTION_BOUNDS = """el => {
    const r = el.getBoundingClientRect();
    const x = Math.floor(r.left + scrollX), y = Math.floor(r.top + scrollY);
    return {x, y, width: Math.ceil(r.right + scrollX) - x,
            height: Math.ceil(r.bottom + scrollY) - y};
}"""


def region_clip(bounds, padding):
    """Derive one rectangle from measured anchors, with explicit outward padding."""
    import math

    x = math.floor(min(box["x"] for box in bounds) - padding["left"])
    y = math.floor(min(box["y"] for box in bounds) - padding["top"])
    right = math.ceil(max(box["x"] + box["width"] for box in bounds) + padding["right"])
    bottom = math.ceil(max(box["y"] + box["height"] for box in bounds) + padding["bottom"])
    try:
        for box in bounds:
            CaptureClip(**box)
        return CaptureClip(x=x, y=y, width=right - x, height=bottom - y).model_dump()
    except ValueError:
        raise CaptureError("Measured region or padding has empty, negative or oversized bounds") from None


async def measure_region(page, selectors, expected_text, padding):
    targets = [page.locator(selector) for selector in selectors]
    for target in targets:
        if await target.count() != 1:
            raise CaptureError("Each anchor selector must match exactly one element; inspect the page HTML")
        await target.wait_for(state="visible")
    # Settle animations before measuring: screenshot's animation handling must not move anchors.
    await page.add_style_tag(content="*, *::before, *::after {animation: none !important; transition: none !important}")
    texts = []
    for target in targets:
        await target.scroll_into_view_if_needed()
        await target.evaluate("""async el => {
            await document.fonts.ready;
            await Promise.all(Array.from(el.querySelectorAll('img'), img => {
                img.loading = 'eager';
                return img.decode().catch(() => {});
            }));
        }""")
        texts.append(" ".join((await target.inner_text()).split()))
    if expected_text and " ".join(expected_text.split()) not in " ".join(texts):
        raise CaptureError("Anchor content does not match expected_text; inspect the page HTML")
    # Sample all anchors together only after scrolling/loading every anchor. Never try alternative crops.
    previous = None
    stable_frames = 0
    for _ in range(12):
        await page.evaluate("() => new Promise(resolve => requestAnimationFrame(resolve))")
        bounds = [await target.evaluate(SECTION_BOUNDS) for target in targets]
        stable_frames = stable_frames + 1 if bounds == previous else 0
        if stable_frames >= 2:
            anchors = [{"selector": selector, "clip": box} for selector, box in zip(selectors, bounds)]
            return targets, anchors, region_clip(bounds, padding)
        previous = bounds
    raise CaptureError("Anchor layout is moving; no screenshot was taken")


async def render(request, policy, *, measure_only=False):
    try:
        from playwright.async_api import Error, TimeoutError, async_playwright
    except ImportError:
        raise CaptureError("Install odoo-mcp-19[capture] and run playwright install chromium") from None
    if request["selectors"] and not measure_only:
        raise CaptureError("Use measure_page for anchors, then capture_page with the region you choose")
    policy.validate_url(request["url"])
    credential_origin = origin(request["url"]) if request["headers"] or request["cookies"] else None
    with capture_proxy(policy, credential_origin) as proxy:
        async with async_playwright() as playwright:
            try:
                browser = await playwright.chromium.launch(
                    headless=True,
                    chromium_sandbox=True,
                    proxy={"server": f"http://127.0.0.1:{proxy.server_address[1]}", "bypass": "<-loopback>"},
                    args=[
                        "--disable-quic",
                        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                        "--disable-background-networking",
                        "--disable-extensions",
                    ],
                )
            except Error:
                raise CaptureError(
                    "Chromium could not start; install browsers and enable the non-root sandbox"
                ) from None
            try:
                context = await browser.new_context(
                    viewport=request["viewport"],
                    device_scale_factor=request["device_scale_factor"],
                    color_scheme=request["color_scheme"] or "light",
                    accept_downloads=False,
                    service_workers="block",
                    ignore_https_errors=False,
                )
                source_origin = origin(request["url"])
                blocked = []

                async def route_request(route):
                    try:
                        policy.validate_url(route.request.url)
                    except CaptureError:
                        blocked.append(True)
                        await route.abort("blockedbyclient")
                        return
                    headers = dict(route.request.headers)
                    # Credentials are applied only to requests to the exact source origin.
                    if origin(route.request.url) == source_origin:
                        headers.update(request["headers"])
                    else:
                        for key in request["headers"]:
                            headers.pop(key.lower(), None)
                    await route.continue_(headers=headers)

                await context.route("**/*", route_request)
                await context.route_web_socket("**/*", lambda ws: ws.close())
                if request["cookies"]:
                    await context.add_cookies([{**cookie, "url": request["url"]} for cookie in request["cookies"]])
                page = await context.new_page()
                page.set_default_timeout(policy.navigation_timeout * 1000)
                page.on("dialog", lambda dialog: dialog.dismiss())
                # Do not permit page scripts to spawn additional tabs or browser windows.
                context.on("page", lambda popup: popup.close() if popup != page else None)
                navigation_complete = False
                try:
                    response = await page.goto(
                        request["url"], wait_until=request["wait_until"], timeout=policy.navigation_timeout * 1000
                    )
                    policy.validate_url(page.url)
                    navigation_complete = True
                    if request["wait_for_selector"]:
                        await page.locator(request["wait_for_selector"]).first.wait_for(state="visible")
                    if request["extra_delay_ms"]:
                        await page.wait_for_timeout(request["extra_delay_ms"])
                    dimensions = await page.evaluate("""() => ({
                        height: Math.max(document.documentElement.scrollHeight, document.body?.scrollHeight || 0),
                        width: Math.max(document.documentElement.scrollWidth, document.body?.scrollWidth || 0)
                    })""")
                    anchors = []
                    clip = request["clip"]
                    if request["selectors"]:
                        _, anchors, clip = await measure_region(
                            page, request["selectors"], request["expected_text"], request["padding"]
                        )
                        # Scrolling to load a section may change the document dimensions.
                        dimensions = await page.evaluate("""() => ({
                            height: Math.max(document.documentElement.scrollHeight, document.body?.scrollHeight || 0),
                            width: Math.max(document.documentElement.scrollWidth, document.body?.scrollWidth || 0)
                        })""")
                    if clip:
                        if clip["height"] > policy.max_height or clip["width"] > 4096:
                            raise CaptureError("Clip exceeds capture dimensions")
                        if (
                            clip["x"] + clip["width"] > dimensions["width"]
                            or clip["y"] + clip["height"] > dimensions["height"]
                        ):
                            raise CaptureError("Clip rectangle must fit within the page in CSS pixels")
                    elif request["full_page"] and (
                        dimensions["height"] > policy.max_height or dimensions["width"] > 4096
                    ):
                        raise CaptureError(
                            "Page exceeds capture dimensions; use full_page=false or choose a smaller clip"
                        )
                    capture_width = (
                        clip["width"]
                        if clip
                        else dimensions["width"] if request["full_page"] else request["viewport"]["width"]
                    )
                    capture_height = (
                        clip["height"]
                        if clip
                        else dimensions["height"] if request["full_page"] else request["viewport"]["height"]
                    )
                    if capture_width * capture_height * request["device_scale_factor"] ** 2 > 60_000_000:
                        raise CaptureError(
                            "Capture exceeds the 60 megapixel limit; reduce scale, viewport or clip size"
                        )
                    if measure_only:
                        if not clip:
                            raise CaptureError("Measurement requires anchor selectors")
                        return {
                            "success": True,
                            "clip": clip,
                            "anchors": anchors,
                            "selectors": request["selectors"],
                            "viewport": request["viewport"],
                            "page_dimensions": dimensions,
                            "url_final": safe_url(page.url),
                            "title": (await page.title())[:512],
                            "http_status": response.status if response else None,
                            "blocked_subrequests": bool(blocked or proxy.blocked),
                        }
                    fmt = request["format"]
                    if fmt in {"png", "jpeg"}:
                        options = {"type": fmt, "animations": "disabled", "timeout": policy.navigation_timeout * 1000}
                        if fmt == "jpeg":
                            options["quality"] = 85
                        if clip:
                            data = await page.screenshot(clip=clip, full_page=True, **options)
                        else:
                            data = await page.screenshot(full_page=request["full_page"], **options)
                    elif fmt == "pdf":
                        data = await page.pdf(format="A4", print_background=True)
                    elif fmt == "text":
                        data = (await page.locator("body").inner_text()).encode("utf-8")
                    else:
                        html = await page.content()
                        if fmt == "md":
                            from markdownify import markdownify

                            html = markdownify(html, strip=["script", "style"])
                        data = html.encode("utf-8")
                    if len(data) > policy.max_bytes:
                        raise CaptureError("Capture exceeds the configured output byte limit")
                    return {
                        "success": True,
                        "content_base64": base64.b64encode(data).decode("ascii"),
                        "mimetype": MIMETYPES[fmt],
                        "selectors": request["selectors"],
                        "anchors": anchors,
                        "clip": clip,
                        "size": len(data),
                        "url_final": safe_url(page.url),
                        "title": (await page.title())[:512],
                        "http_status": response.status if response else None,
                        "captured_at": datetime.now(timezone.utc).isoformat(),
                        "blocked_subrequests": bool(blocked or proxy.blocked),
                    }
                except TimeoutError:
                    raise CaptureError("Capture navigation or selector timed out") from None
                except Error as exc:
                    message = str(exc)
                    if proxy.failure:
                        raise CaptureError(proxy.failure) from None
                    if blocked and not navigation_complete:
                        raise CaptureError("Navigation or redirect blocked by capture host policy") from None
                    if "ERR_CERT" in message or "ERR_SSL" in message:
                        raise CaptureError("Capture TLS certificate validation failed") from None
                    if navigation_complete:
                        raise CaptureError("Page rendering or screenshot capture failed") from None
                    raise CaptureError("Capture navigation failed") from None
            finally:
                await browser.close()


def main():
    try:
        raw = sys.stdin.buffer.read(262145)
        if len(raw) > 262144:
            raise CaptureError("Capture worker input exceeds the size limit")
        payload = json.loads(raw)
        policy = CapturePolicy(**payload["policy"])
        result = asyncio.run(
            render(
                payload["request"],
                policy,
                measure_only=payload.get("measure_only", False),
            )
        )
    except CaptureError as exc:
        result = {"success": False, "error": str(exc)}
    except Exception:
        result = {"success": False, "error": "Capture worker failed; no browser diagnostics are exposed"}
    sys.stdout.write(json.dumps(result))


if __name__ == "__main__":
    main()
