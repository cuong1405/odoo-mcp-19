"""Validated capture requests and isolated, bounded browser worker execution."""

import hashlib
import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections import OrderedDict, deque
from dataclasses import asdict
from typing import Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

from .capture_policy import CaptureError, CapturePolicy


class Viewport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    width: int = Field(default=1440, ge=320, le=2560)
    height: int = Field(default=900, ge=240, le=2160)


class CaptureClip(BaseModel):
    """Rectangle in CSS pixels from the document top-left."""

    model_config = ConfigDict(extra="forbid")
    x: float = Field(ge=0, allow_inf_nan=False, description="Page horizontal offset in CSS pixels")
    y: float = Field(ge=0, allow_inf_nan=False, description="Page vertical offset in CSS pixels")
    width: float = Field(gt=0, le=4096, allow_inf_nan=False)
    height: float = Field(gt=0, allow_inf_nan=False)


class CaptureRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(max_length=8192)
    format: Literal["png", "jpeg", "pdf", "html", "text", "md"] = "png"
    full_page: bool = True
    viewport: Viewport = Field(default_factory=Viewport)
    device_scale_factor: float = Field(default=1, ge=1, le=2)
    wait_until: Literal["load", "domcontentloaded", "networkidle"] = "networkidle"
    wait_for_selector: str | None = Field(default=None, max_length=1024)
    extra_delay_ms: int = Field(default=0, ge=0, le=10000)
    color_scheme: Literal["light", "dark"] | None = None
    clip: CaptureClip | None = None
    # SecretStr prevents validation/repr from revealing values. Worker input uses explicit extraction.
    headers: dict[str, SecretStr] = Field(default_factory=dict)
    cookies: list[dict[str, SecretStr]] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_credentials(self):
        if self.clip is not None and self.format not in {"png", "jpeg"}:
            raise ValueError("clip is supported only for PNG and JPEG screenshots")
        if len(self.headers) > 20 or len(self.cookies) > 30:
            raise ValueError("Too many capture headers or cookies")
        for key, value in self.headers.items():
            if (
                not key.isascii()
                or not key.replace("-", "").isalnum()
                or key.lower()
                in {
                    "host",
                    "proxy-authorization",
                    "proxy-connection",
                    "connection",
                    "content-length",
                    "transfer-encoding",
                    "upgrade",
                    "cookie",
                }
                or "\r" in value.get_secret_value()
                or "\n" in value.get_secret_value()
            ):
                raise ValueError("Invalid or forbidden capture header")
        for cookie in self.cookies:
            if set(cookie) != {"name", "value"}:
                raise ValueError("Capture cookies accept name/value only and are scoped to the source host")
        if (
            sum(len(v.get_secret_value()) for v in self.headers.values())
            + sum(len(v.get_secret_value()) for cookie in self.cookies for v in cookie.values())
            > 16384
        ):
            raise ValueError("Capture credentials exceed the 16 KiB limit")
        return self

    def worker_payload(self):
        payload = self.model_dump(exclude={"headers", "cookies"})
        payload["headers"] = {key: value.get_secret_value() for key, value in self.headers.items()}
        payload["cookies"] = [{key: value.get_secret_value() for key, value in c.items()} for c in self.cookies]
        return payload

    def digest(self):
        return hashlib.sha256(json.dumps(self.worker_payload(), sort_keys=True).encode()).hexdigest()


_LIMIT_LOCK = threading.Lock()
_LIMIT_CONDITION = threading.Condition(_LIMIT_LOCK)
_ACTIVE = 0
_WAITING = 0
_HISTORY: OrderedDict[str, deque] = OrderedDict()


def _claim_slot(identity: str, policy: CapturePolicy):
    global _ACTIVE, _WAITING
    with _LIMIT_CONDITION:
        if _WAITING >= 16:
            raise CaptureError("Capture queue is full; retry shortly")
        _WAITING += 1
        try:
            available = _LIMIT_CONDITION.wait_for(lambda: _ACTIVE < policy.concurrency, timeout=policy.timeout)
        finally:
            _WAITING -= 1
        if not available:
            raise CaptureError("Capture queue timed out; retry shortly")
        now = time.monotonic()
        history = _HISTORY.get(identity, deque())
        while history and history[0] < now - 3600:
            history.popleft()
        if len(history) >= policy.hourly_limit:
            raise CaptureError("Hourly capture limit reached for this Odoo identity")
        # Never evict an identity with a live quota, which would reset its limit.
        for key in list(_HISTORY):
            if not _HISTORY[key] or _HISTORY[key][-1] < now - 3600:
                del _HISTORY[key]
        if identity not in _HISTORY and len(_HISTORY) >= 10000:
            raise CaptureError("Capture quota tracker is full; retry later")
        _HISTORY[identity] = history
        history.append(now)
        _ACTIVE += 1


def run_capture(request: CaptureRequest, policy: CapturePolicy, identity: str) -> dict:
    """No browser, cookies, Odoo keys or files persist between capture processes."""
    global _ACTIVE
    policy.validate_url(request.url)
    _claim_slot(identity, policy)
    process = None
    try:
        # Only browser runtime configuration crosses into the child, never Odoo/API credentials.
        env = {
            key: value
            for key, value in os.environ.items()
            if key
            in {
                "PATH",
                "HOME",
                "LANG",
                "LC_ALL",
                "TZ",
                "PLAYWRIGHT_BROWSERS_PATH",
                "LD_LIBRARY_PATH",
            }
        }
        process = subprocess.Popen(
            [sys.executable, "-m", "odoo_mcp.capture_worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=env,
            start_new_session=True,
        )
        try:
            output, _ = process.communicate(
                json.dumps({"request": request.worker_payload(), "policy": asdict(policy)}).encode(),
                timeout=policy.timeout,
            )
        except subprocess.TimeoutExpired:
            raise CaptureError("Total capture timeout exceeded") from None
        if len(output) > policy.max_bytes * 4 // 3 + 65536:
            raise CaptureError("Capture output exceeds the configured size limit")
        try:
            result = json.loads(output)
        except (ValueError, UnicodeError):
            raise CaptureError(
                "Capture worker failed; check optional capture installation and Chromium sandbox"
            ) from None
        if not isinstance(result, dict):
            raise CaptureError("Capture worker returned an invalid response")
        if not result.get("success"):
            raise CaptureError(result.get("error", "Capture worker failed"))
        return result
    finally:
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
        with _LIMIT_CONDITION:
            _ACTIVE -= 1
            _LIMIT_CONDITION.notify_all()


def origin(url: str) -> tuple:
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
