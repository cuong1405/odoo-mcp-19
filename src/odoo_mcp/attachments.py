"""Validate portable workflow artifacts without accessing the server filesystem."""

import base64
import binascii
import mimetypes
import re

from .constants import _validate_model

MAX_ATTACHMENT_BYTES = 25 * 1024 * 1024


def attachment_values(
    name: str,
    content_base64: str,
    mimetype: str | None,
    res_model: str | None,
    res_id: int | None,
    description: str | None,
) -> dict:
    """Build ir.attachment create values; binary content is canonicalized for token binding."""
    if not name or len(name) > 255 or name in {".", ".."} or any(c in name for c in "/\\"):
        raise ValueError("name must be a filename without path components, at most 255 characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError("name must not contain control characters")
    if len(content_base64) > 4 * ((MAX_ATTACHMENT_BYTES + 2) // 3):
        raise ValueError("Attachment exceeds the 25 MiB decoded limit")
    try:
        content = base64.b64decode(content_base64, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("content_base64 must be standard base64 without a data URL prefix") from None
    if not content or len(content) > MAX_ATTACHMENT_BYTES:
        raise ValueError("Attachment must contain between 1 byte and 25 MiB")
    if (res_model is None) != (res_id is None):
        raise ValueError("res_model and res_id must be supplied together")
    if res_model is not None:
        error = _validate_model(res_model)
        if error:
            raise ValueError(error)
        if type(res_id) is not int or res_id <= 0:
            raise ValueError("res_id must be a positive integer")
    if mimetype is not None and not re.fullmatch(r"[\w.+-]+/[\w.+-]+", mimetype, flags=re.ASCII):
        raise ValueError("mimetype must be a MIME type such as image/png")
    if description is not None and len(description) > 4096:
        raise ValueError("description must be at most 4096 characters")
    vals = {
        "name": name,
        "type": "binary",
        "datas": base64.b64encode(content).decode("ascii"),
        "mimetype": mimetype or mimetypes.guess_type(name)[0] or "application/octet-stream",
        "public": False,
        "res_model": res_model or False,
        "res_id": res_id or 0,
        "res_field": False,
    }
    if description is not None:
        vals["description"] = description
    return vals
