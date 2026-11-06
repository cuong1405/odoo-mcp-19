"""
MCP Server for Odoo 19+

Provides MCP tools and resources for interacting with Odoo ERP via JSON-2 API.

MCP 2025-11-25 Features:
- Background Tasks (SEP-1686) - Async operations with progress tracking
- Icons (SEP-973) - Visual icons for server and components
- Structured Output Schemas - Typed Pydantic responses
- User Elicitation - Interactive configuration
"""

import asyncio
import base64
import functools
import hashlib
import json
import logging
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Literal, TypeVar

import anyio
from fastmcp import Context
from fastmcp.dependencies import Progress
from fastmcp.tools import ToolResult
from mcp.types import TextContent
from pydantic import SecretStr, ValidationError

from . import prompts as _prompts  # noqa: F401 -- import triggers prompt registration
from . import resources as _resources  # noqa: F401 -- import triggers resource registration
from .app import ODOO_ICON, mcp  # noqa: F401 -- mcp import triggers FastMCP setup
from .arg_mapping import convert_args_to_v2
from .attachment_content import METADATA_FIELDS, TEXT_MIMETYPES, preview_content
from .attachments import attachment_values
from .capture import CaptureClip, CapturePadding, CaptureRequest, Viewport, run_capture
from .capture_policy import CaptureError, CapturePolicy, safe_url
from .constants import (
    _READ_RESOURCE_MAX_CHARS,
    COMPACT_FIELD_ATTRIBUTES,
    DEFAULT_LIMIT,
    MAX_LIMIT,
    PRIVATE_METHOD_HINTS,
    _merge_context,
    _validate_method,
    _validate_model,
)
from .models import (
    BatchExecuteResponse,
    BatchOperationResult,
    ExecuteMethodResponse,
    IssueAnalysis,
)
from .odoo_client import get_odoo_client
from .safety import (
    BLOCKED_MODELS,
    RiskLevel,
    SafetyClassification,
    audit_log,
    classify_batch,
    classify_operation,
    is_side_effect_method,
)
from .safety_profile import get_profile
from .user_clients import current_role
from .utils import (
    _get_live_doc,
    _track_model_issue,
    get_error_suggestion,
    get_fields_for_model,
)

logger = logging.getLogger(__name__)

_T = TypeVar("_T")


async def _run_blocking(fn: Callable[..., _T], /, *args: Any, **kwargs: Any) -> _T:
    """Run a synchronous OdooClient call in the anyio worker threadpool.

    ``batch_execute`` is ``async def`` (it reports
    progress), but ``OdooClient`` is built on synchronous ``requests``. Calling
    it inline would block the event loop for the whole round-trip — in HTTP
    multi-user mode a 100-op batch would freeze every session for 100 × RTT.
    Contextvars propagate through ``anyio.to_thread``, so ``get_odoo_client()``
    and the current access token resolve exactly as on the loop thread.
    """
    return await anyio.to_thread.run_sync(functools.partial(fn, *args, **kwargs))


# ----- Confirmation Token Store -----
# Stateful nonces that tie a confirmed=True re-call to the original safety classification
# AND the original payload (args/kwargs/operations/params). Prevents an agent from bypassing
# the gate by passing confirmed=true with substituted arguments.

# token → (timestamp, model, method, payload_digest)
_CONFIRMATION_TOKENS: dict[str, tuple[float, str, str, str]] = {}
_CONFIRMATION_LOCK = threading.Lock()
_CONFIRMATION_TTL = 120  # seconds


def _payload_digest(payload: Any) -> str:
    """SHA-256 hex digest of a JSON-serializable payload, with sorted keys for determinism.

    Used to bind a confirmation token to the exact arguments seen at gate-issue time.
    Any change between issue and consume — added IDs, swapped model on a resolve target,
    different operation count or content — produces a different digest, invalidating the token.
    """
    serialized = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _issue_confirmation_token(model: str, method: str, payload_digest: str) -> str:
    """Issue a short-lived nonce for a pending confirmation."""
    token = secrets.token_urlsafe(16)
    now = time.time()
    with _CONFIRMATION_LOCK:
        # Evict expired tokens
        expired = [k for k, (ts, *_) in _CONFIRMATION_TOKENS.items() if now - ts > _CONFIRMATION_TTL]
        for k in expired:
            del _CONFIRMATION_TOKENS[k]
        _CONFIRMATION_TOKENS[token] = (now, model, method, payload_digest)
    return token


def _validate_confirmation_token(token: str | None, model: str, method: str, payload_digest: str) -> str | None:
    """Validate and consume a confirmation token. Returns error message or None if valid."""
    if not token:
        return "confirmed=true requires a confirmation_token from the safety gate response."
    with _CONFIRMATION_LOCK:
        entry = _CONFIRMATION_TOKENS.pop(token, None)
    if not entry:
        return "Confirmation token is invalid or already used."
    ts, stored_model, stored_method, stored_digest = entry
    if time.time() - ts > _CONFIRMATION_TTL:
        return f"Confirmation token expired (>{_CONFIRMATION_TTL}s). Re-call without confirmed=true to get a new token."
    if stored_model != model or stored_method != method:
        return f"Confirmation token was issued for {stored_model}.{stored_method}, not {model}.{method}."
    if stored_digest != payload_digest:
        return (
            "Confirmation token was issued for a different payload. The arguments must match "
            "exactly between the gate response and the confirmation re-call. Re-call without "
            "confirmed=true to get a new token for the current payload."
        )
    return None


# ----- Shared guards for the write-capable tools -----


def _elapsed_ms(start_time: float) -> float:
    return round((time.time() - start_time) * 1000, 2)


def _read_only_error(subject: str) -> str:
    """Uniform rejection text for the MCP_READ_ONLY / locked-mode kill-switch."""
    return (
        f"read-only mode is active: {subject}. Set MCP_READ_ONLY=false to enable "
        f"writes (or change MCP_SAFETY_MODE away from 'locked' if MCP_READ_ONLY "
        f"is not set explicitly)."
    )


@dataclass(frozen=True)
class _GateDecision:
    """Outcome of the confirmation gate for one gated operation.

    ``outcome`` is ``"issue"`` (first call — hand ``token`` back to the caller),
    ``"reject"`` (confirmed re-call with a bad token — surface ``error``) or
    ``"proceed"`` (token validated and consumed).
    """

    outcome: str
    token: str | None = None
    error: str | None = None


def _confirmation_gate(
    model_key: str,
    method_key: str,
    payload: Any,
    confirmed: bool,
    confirmation_token: str | None,
) -> _GateDecision:
    """Issue a token on the first call; validate and consume it on the confirmed re-call.

    ``payload`` is the exact operation content the token must be bound to —
    post-resolve args/kwargs for ``execute_method``, the operations list for
    ``batch_execute``. Its digest is what stops a re-call from substituting
    arguments after the gate was shown.
    """
    digest = _payload_digest(payload)
    if not confirmed:
        return _GateDecision("issue", token=_issue_confirmation_token(model_key, method_key, digest))
    error = _validate_confirmation_token(confirmation_token, model_key, method_key, digest)
    if error:
        return _GateDecision("reject", error=f"Confirmation rejected: {error}")
    return _GateDecision("proceed")


# ----- execute_method phases -----


def _parse_json_args(args_json: str | None, kwargs_json: str | None) -> tuple[list, dict, str | None]:
    """Decode the JSON-string parameters and merge MCP_DEFAULT_CONTEXT.

    Returns ``(args, kwargs, error)``; ``error`` is set on malformed input.
    """
    args: list = []
    kwargs: dict = {}
    if args_json:
        try:
            args = json.loads(args_json)
        except json.JSONDecodeError as e:
            return [], {}, f"Invalid args_json: {e}"
        if not isinstance(args, list):
            return [], {}, "args_json must be a JSON array"
    if kwargs_json:
        try:
            kwargs = json.loads(kwargs_json)
        except json.JSONDecodeError as e:
            return [], {}, f"Invalid kwargs_json: {e}"
        if not isinstance(kwargs, dict):
            return [], {}, "kwargs_json must be a JSON object"
    merged_ctx = _merge_context(kwargs.get("context"))
    if merged_ctx is not None:
        kwargs = {**kwargs, "context": merged_ctx}
    return args, kwargs, None


def _lookup_resolve_target(
    odoo: Any, field_name: str, spec: Any, start_time: float
) -> tuple[int | None, ExecuteMethodResponse | None]:
    """Resolve one ``resolve_json`` entry to a record id via ``name_search``."""
    target_model = spec.get("model") if isinstance(spec, dict) else None
    search_term = spec.get("search") if isinstance(spec, dict) else None
    if not target_model or not search_term:
        return None, ExecuteMethodResponse(
            success=False, error=f"resolve_json['{field_name}'] requires 'model' and 'search' keys"
        )
    model_err = _validate_model(target_model)
    if model_err:
        return None, ExecuteMethodResponse(success=False, error=f"resolve_json['{field_name}']: {model_err}")
    # Block reads against security-critical models
    if target_model in BLOCKED_MODELS:
        return None, ExecuteMethodResponse(
            success=False, error=f"resolve_json['{field_name}']: model '{target_model}' is blocked for safety."
        )
    # The lookup *and* the unpacking of its result share one boundary: a malformed
    # name_search tuple must surface as a resolve_json failure, not as a generic error.
    try:
        matches = odoo.execute_method(target_model, "name_search", name=search_term, limit=5)
        if not matches:
            return None, ExecuteMethodResponse(
                success=False,
                error=f"resolve_json: No match for '{search_term}' in {target_model}",
                hint=f"Search {target_model} manually to find the correct record",
                execution_time_ms=_elapsed_ms(start_time),
            )
        if len(matches) > 1:
            options = [f"  {m[0]}: {m[1]}" for m in matches[:5]]
            return None, ExecuteMethodResponse(
                success=False,
                error=f"resolve_json: Ambiguous match for '{search_term}' in {target_model} ({len(matches)} results)",
                hint="Multiple matches found:\n" + "\n".join(options) + "\nUse the numeric ID directly instead.",
                execution_time_ms=_elapsed_ms(start_time),
            )
        return matches[0][0], None
    except Exception as e:
        return None, ExecuteMethodResponse(
            success=False,
            error=f"resolve_json: Failed to resolve '{field_name}': {e}",
            execution_time_ms=_elapsed_ms(start_time),
        )


def _inject_resolved_values(method: str, args: list, resolved: dict[str, int]) -> list:
    """Return a copy of ``args`` with the resolved ids merged into the vals dict(s)."""
    if not resolved or not args:
        return args
    if method == "write" and len(args) >= 2 and isinstance(args[1], dict):
        return [args[0], {**args[1], **resolved}, *args[2:]]
    if method == "create":
        if isinstance(args[0], dict):
            return [{**args[0], **resolved}, *args[1:]]
        if isinstance(args[0], list):
            vals_list = [{**vals, **resolved} if isinstance(vals, dict) else vals for vals in args[0]]
            return [vals_list, *args[1:]]
    return args


def _resolve_many2one_names(
    odoo: Any, resolve_json: str, method: str, args: list, start_time: float
) -> tuple[list, ExecuteMethodResponse | None]:
    """Apply ``resolve_json``: name_search every entry and inject the ids into the payload."""
    try:
        resolves = json.loads(resolve_json)
    except json.JSONDecodeError as e:
        return args, ExecuteMethodResponse(success=False, error=f"Invalid resolve_json: {e}")
    if not isinstance(resolves, dict):
        return args, ExecuteMethodResponse(success=False, error="resolve_json must be a JSON object")
    resolved: dict[str, int] = {}
    for field_name, spec in resolves.items():
        record_id, failure = _lookup_resolve_target(odoo, field_name, spec, start_time)
        if failure:
            return args, failure
        resolved[field_name] = record_id  # type: ignore[assignment]
    return _inject_resolved_values(method, args, resolved), None


def _reject_private_method(model: str, method: str, start_time: float) -> ExecuteMethodResponse | None:
    """Refuse ``@api.private`` methods: static hint table first, then the live /doc-bearer/ check."""
    if method in PRIVATE_METHOD_HINTS:
        return ExecuteMethodResponse(
            success=False,
            error=f"Method '{method}' is @api.private and cannot be called via RPC.",
            hint=PRIVATE_METHOD_HINTS[method],
            execution_time_ms=_elapsed_ms(start_time),
        )
    if method.startswith("_"):
        live_doc = _get_live_doc(model)
        if live_doc and method not in live_doc.get("methods", {}):
            return ExecuteMethodResponse(
                success=False,
                error=f"Method '{method}' is not a public method on {model}. It may be @api.private or doesn't exist.",
                hint=f"Use odoo://methods/{model} to see available public methods.",
                execution_time_ms=_elapsed_ms(start_time),
            )
    return None


def _fields_loader(odoo: Any) -> Callable[[str], dict]:
    """Schema loader for the classifier's relational check (cached compact fields_get)."""
    return lambda model: get_fields_for_model(odoo, model, attributes=COMPACT_FIELD_ATTRIBUTES)


def _classify_and_gate(
    odoo: Any,
    model: str,
    method: str,
    args: list,
    kwargs: dict,
    confirmed: bool,
    confirmation_token: str | None,
    start_time: float,
) -> tuple[ExecuteMethodResponse | None, SafetyClassification]:
    """Run the safety classifier, the payload pre-flight and the confirmation gate.

    Returns ``(response, classification)``: the response to send when the call must
    stop here (blocked, token issued, token rejected, payload invalid), or ``None``
    when execution may proceed. The classification is always returned so the
    success response can report it — a caller must be able to see *why* a write
    was or was not gated.
    """
    classification = classify_operation(
        model, method, args, kwargs, role=current_role(), fields_loader=_fields_loader(odoo)
    )

    if classification.risk_level == RiskLevel.BLOCKED:
        audit_log(classification, confirmed=confirmed, executed=False)
        return (
            ExecuteMethodResponse(
                success=False,
                pending_confirmation=True,
                safety=classification,
                error=classification.blocked_reason,
                hint="Use the Odoo web interface instead.",
                execution_time_ms=_elapsed_ms(start_time),
            ),
            classification,
        )

    if classification.requires_confirmation:
        # Payload pre-flight against live fields_get — only when the profile asks
        # for it AND this is a write-shaped call — so a typo'd field fails before
        # a gate round-trip is spent on it.
        if get_profile().validate_payloads and is_side_effect_method(method):
            from .safety import validate_payload_against_schema as _validate_payload

            validation = _validate_payload(odoo, model, method, args=args, kwargs=kwargs)
            if not validation.ok:
                return (
                    ExecuteMethodResponse(
                        success=False,
                        safety=classification,
                        error="Payload validation failed:\n  - " + "\n  - ".join(validation.errors),
                        hint=f"Read odoo://model/{model}/quick-schema for the field list.",
                        execution_time_ms=_elapsed_ms(start_time),
                    ),
                    classification,
                )

        # Args/kwargs are post-resolve_json and post-context-merge, so the digest
        # captures what would actually be sent to Odoo.
        decision = _confirmation_gate(model, method, {"args": args, "kwargs": kwargs}, confirmed, confirmation_token)
        if decision.outcome == "issue":
            audit_log(classification, confirmed=False, executed=False)
            message = classification.reason
            if classification.cascade_warning:
                message += f"\n\nWARNING: {classification.cascade_warning}"
            return (
                ExecuteMethodResponse(
                    success=False,
                    pending_confirmation=True,
                    safety=classification,
                    error=message,
                    hint=(
                        f"Re-call execute_method with confirmed=true and "
                        f"confirmation_token='{decision.token}' to proceed."
                    ),
                    execution_time_ms=_elapsed_ms(start_time),
                ),
                classification,
            )
        if decision.outcome == "reject":
            return (
                ExecuteMethodResponse(
                    success=False,
                    safety=classification,
                    error=decision.error,
                    execution_time_ms=_elapsed_ms(start_time),
                ),
                classification,
            )

    if classification.risk_level != RiskLevel.SAFE:
        audit_log(classification, confirmed=confirmed, executed=True)
    return None, classification


def _apply_search_defaults(method: str, args: list, kwargs: dict) -> tuple[list, dict]:
    """Default/cap the search limit and unwrap a double-wrapped ``[[domain]]``."""
    if method in ("search", "search_read"):
        if "limit" not in kwargs:
            kwargs = {**kwargs, "limit": DEFAULT_LIMIT}
            logger.debug("Applied default limit=%d", DEFAULT_LIMIT)
        elif kwargs.get("limit", 0) > MAX_LIMIT:
            kwargs = {**kwargs, "limit": MAX_LIMIT}
            logger.debug("Capped limit to %d", MAX_LIMIT)
    if method in ("search", "search_read", "search_count") and args:
        domain = args[0]
        if isinstance(domain, list) and len(domain) == 1 and isinstance(domain[0], list):
            if domain[0] and isinstance(domain[0][0], list):
                args = [domain[0], *args[1:]]
    return args, kwargs


def _search_read_fallback(
    odoo: Any, model: str, kwargs: dict, error_msg: str, start_time: float
) -> ExecuteMethodResponse:
    """Retry a failed ``search_read`` as ``search`` + ``read`` and record the runtime issue."""
    domain = kwargs.get("domain", [])
    fields = kwargs.get("fields", [])
    context = kwargs.get("context")
    try:
        search_kwargs: dict[str, Any] = {
            "domain": domain,
            "limit": kwargs.get("limit", 100),
            "offset": kwargs.get("offset", 0),
        }
        if kwargs.get("order"):
            search_kwargs["order"] = kwargs["order"]
        if context:
            search_kwargs["context"] = context
        ids = odoo.execute_method(model, "search", **search_kwargs)

        result: Any = []
        if ids:
            read_kwargs: dict[str, Any] = {}
            if fields:
                read_kwargs["fields"] = fields
            if context:
                read_kwargs["context"] = context
            result = odoo.execute_method(model, "read", ids, **read_kwargs)

        analysis = _track_model_issue(model, "search_read", error_msg, domain=domain, fields=fields)
        return ExecuteMethodResponse(
            success=True,
            result=result,
            fallback_used=True,
            issue_analysis=IssueAnalysis(
                category=analysis["category"],
                cause=analysis["cause"],
                domain_patterns=analysis["domain_patterns"],
                problematic_fields=analysis.get("problematic_fields", []),
                suggested_solutions=analysis["solutions"][:2],
                model_specific_advice=analysis.get("model_specific_advice", []),
            ),
            note=f"Fallback search+read used. Cause: {analysis['cause']}",
            execution_time_ms=_elapsed_ms(start_time),
        )
    except Exception as fallback_error:
        return ExecuteMethodResponse(
            success=False,
            error=f"{error_msg}; Fallback also failed: {fallback_error}",
            suggestion=(
                "Both search_read and fallback search+read failed. " "Check odoo://model-limitations for known issues."
            ),
            execution_time_ms=_elapsed_ms(start_time),
        )


_MISSING_METHOD_PATTERNS = ("the method", "does not exist")
_FIELD_ERROR_PATTERNS = ("invalid field", "unknown field", "field_get", "keyerror", "no field", "does not exist")


def _failure_response(model: str, method: str, error_msg: str, start_time: float) -> ExecuteMethodResponse:
    """Wrap an Odoo error with a pattern-matched suggestion and a schema hint."""
    suggestion = get_error_suggestion(error_msg, model, method)
    hint = None
    lowered = error_msg.lower()
    if all(p in lowered for p in _MISSING_METHOD_PATTERNS):
        # "The method 'res.partner.read_group' does not exist" also contains a
        # field-error pattern; it is about the method, not a field.
        hint = (
            f"'{method}' does not exist on '{model}' in this Odoo version. Read odoo://methods/{model} for the "
            f"methods that exist, or odoo://api/version-drift for renamed and removed ones."
        )
    elif any(p in lowered for p in _FIELD_ERROR_PATTERNS):
        hint = (
            f"Field name error detected. Read odoo://model/{model}/fields to get exact field names, "
            f"or odoo://model/{model}/schema for full details."
        )
    elif suggestion:
        hint = f"Check odoo://methods/{model} or odoo://module-knowledge for special methods"
    return ExecuteMethodResponse(
        success=False,
        error=error_msg,
        suggestion=suggestion,
        hint=hint,
        execution_time_ms=_elapsed_ms(start_time),
    )


# ----- MCP Tools (execute_method, batch_execute, read_resource) -----

# Icon list for tools (reusable)
_tool_icons = [ODOO_ICON] if ODOO_ICON else None


@mcp.tool(
    description="""Execute ANY Odoo method on ANY model.

    This is the universal tool for full Odoo API access.

    BEFORE USING: Read these resources for guidance:
    - odoo://actions/{model} - Discover available actions
    - odoo://methods/{model} - Method signatures
    - odoo://domain-syntax - Domain filter reference
    - odoo://aggregation - Aggregation guide (formatted_read_group)

    MANDATORY WORKFLOW (no guessing!):
    1. FIRST: Read odoo://model/{model}/quick-schema to get exact field names/types
    2. THEN: Build your query using schema field names
    Never guess field names - introspect schema first to avoid failed requests.

    Common patterns:
    - search_read: kwargs_json='{"domain": [...], "fields": [...], "limit": 100}'
    - create: kwargs_json='{"vals_list": [{"field": "value"}]}'
    - write: args_json='[[ids], {"field": "value"}]'
    - unlink: args_json='[[ids]]'
    - formatted_read_group (v19): kwargs_json='{"domain": [...], "groupby": ["field"], "aggregates": ["field:sum"]}'

    RELATIONAL FIELD WRITES (critical -- wrong syntax = silent failure):
    - Many2one: ALWAYS numeric ID, never name. Use resolve_json to auto-resolve.
    - Many2many: (4, id) link, (3, id) unlink, (6, 0, [ids]) replace all, (5, 0, 0) clear
    - One2many: (0, 0, {vals}) create child, (1, id, {vals}) update, (2, id, 0) delete

    DATE/DATETIME FORMATS (wrong format = 500 or silent failure):
    - date fields: "YYYY-MM-DD" (e.g. "2026-04-10")
    - datetime fields: "YYYY-MM-DD HH:MM:SS" in UTC (e.g. "2026-04-10 14:30:00")

    STATE CHANGES: Never use write() to change state fields directly.
    Use action methods instead (action_confirm, action_set_won, action_post, etc.).
    Read odoo://methods/{model} to find the correct action method.

    Smart limits: Default 100, Max 1000 records

    DISCOVERY RESOURCES (read these before querying):
    - odoo://model/{model}/quick-schema - Compact field names & types (densest form, best for token savings)
    - odoo://model/{model}/fields - Lightweight field list (e.g. odoo://model/res.partner/fields)
    - odoo://model/{model}/workflow - State machine transitions (e.g. odoo://model/sale.order/workflow)
    - odoo://bundle/{models} - Batch quick-schema for N models (e.g. odoo://bundle/res.partner,sale.order)
    - odoo://session-bootstrap - Bootstrap conversation with schemas + workflows
    - odoo://methods/{model} - Available methods (e.g. odoo://methods/crm.lead)
    - odoo://actions/{model} - Discover actions (e.g. odoo://actions/sale.order)
    - odoo://model/{model}/docs - Rich docs with help text
    - odoo://record/{model}/{id} - Read a record
    - odoo://find-model/{concept} - Natural language lookup
    - odoo://tools/{query} - Search operations
    - odoo://docs/{target} - Documentation URLs
    - odoo://module-knowledge/{name} - Module-specific methods

    SAFETY: Dangerous operations return pending_confirmation=true with a single-use
    confirmation_token in the hint. After reviewing the classification, re-call with the
    identical arguments plus confirmed=true and that confirmation_token; confirmed=true
    alone is refused.
    """,
    annotations={
        "title": "Execute Odoo Method",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
    icons=_tool_icons,
)
def execute_method(
    ctx: Context,
    model: str,
    method: str,
    args_json: str | None = None,
    kwargs_json: str | None = None,
    confirmed: bool = False,
    confirmation_token: str | None = None,
    resolve_json: str | None = None,
) -> ExecuteMethodResponse:
    """
    Execute any method on an Odoo model.

    Parameters:
        model: Model name (e.g., 'res.partner')
        method: Method name (e.g., 'search_read', 'create')
        args_json: JSON array of positional arguments
        kwargs_json: JSON object of keyword arguments
        confirmed: Set to true to bypass safety confirmation
        resolve_json: JSON object to auto-resolve Many2one names to IDs.
            Format: '{"field_name": {"model": "target.model", "search": "name to find"}}'
            Resolves via name_search before execution. Errors if 0 or >1 matches.

    Examples:
        Search partners:
            model='res.partner'
            method='search_read'
            args_json='[[["is_company", "=", true]]]'
            kwargs_json='{"fields": ["name", "email"], "limit": 10}'

        Create record:
            model='res.partner'
            method='create'
            args_json='[{"name": "Test Company"}]'

        Write with auto-resolved Many2one:
            model='res.partner'
            method='write'
            args_json='[[1], {"user_id": null}]'
            resolve_json='{"user_id": {"model": "res.users", "search": "Administrator"}}'
    """
    start_time = time.time()

    model_err = _validate_model(model)
    if model_err:
        return ExecuteMethodResponse(success=False, error=model_err, execution_time_ms=0)
    method_err = _validate_method(method)
    if method_err:
        return ExecuteMethodResponse(success=False, error=method_err, execution_time_ms=0)

    # Read-only kill-switch — cheap set lookup, runs before the classifier and any round-trip.
    if get_profile().read_only and is_side_effect_method(method):
        return ExecuteMethodResponse(
            success=False,
            error=_read_only_error(f"'{method}' on '{model}' is a side-effect operation"),
            execution_time_ms=_elapsed_ms(start_time),
        )

    odoo = get_odoo_client()
    # Runs outside the try below on purpose: _parse_json_args reports malformed input
    # as a response and must never raise (json errors are caught inside it and
    # _merge_context swallows its own). Keep that invariant if you touch either.
    args, kwargs, parse_err = _parse_json_args(args_json, kwargs_json)
    if parse_err:
        return ExecuteMethodResponse(success=False, error=parse_err)

    try:
        if resolve_json:
            args, failure = _resolve_many2one_names(odoo, resolve_json, method, args, start_time)
            if failure:
                return failure

        rejected = _reject_private_method(model, method, start_time)
        if rejected:
            return rejected

        # Reject a payload JSON-2 cannot express (unmappable positional, parameter
        # given twice) before the gate: no token is spent on a call that cannot be sent,
        # and the gate never classifies a payload that differs from the one sent.
        convert_args_to_v2(method, tuple(args), kwargs)

        gated, classification = _classify_and_gate(
            odoo, model, method, args, kwargs, confirmed, confirmation_token, start_time
        )
        if gated:
            return gated

        args, kwargs = _apply_search_defaults(method, args, kwargs)
        result = odoo.execute_method(model, method, *args, **kwargs)
        return ExecuteMethodResponse(
            success=True, result=result, safety=classification, execution_time_ms=_elapsed_ms(start_time)
        )

    except Exception as e:
        error_msg = str(e)
        if method == "search_read" and ("500" in error_msg or "Internal Server Error" in error_msg):
            return _search_read_fallback(odoo, model, kwargs, error_msg, start_time)
        return _failure_response(model, method, error_msg, start_time)


@mcp.tool(
    description=(
        "Store a screenshot or workflow file as a non-public Odoo ir.attachment. "
        "Accepts standard base64 bytes (maximum 25 MiB decoded), including Playwright screenshot bytes. "
        "Optionally link to res_model/res_id and describe the workflow or source URL. "
        "Uses the same safety gate as execute_method: repeat identical inputs with confirmed=true "
        "and the returned confirmation_token when requested. Returns create's attachment ID list; "
        "authenticated download: /web/content/<id>?download=true. "
        "Capture screenshots in the caller's browser; this tool uploads bytes and does not browse URLs."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
)
def upload_attachment(
    ctx: Context,
    name: str,
    content_base64: str,
    mimetype: str | None = None,
    res_model: str | None = None,
    res_id: int | None = None,
    description: str | None = None,
    confirmed: bool = False,
    confirmation_token: str | None = None,
) -> ExecuteMethodResponse:
    """Upload portable artifact bytes using the standard per-user Odoo execution path."""
    try:
        vals = attachment_values(name, content_base64, mimetype, res_model, res_id, description)
    except ValueError as exc:
        return ExecuteMethodResponse(success=False, error=str(exc))
    return execute_method(
        ctx=ctx,
        model="ir.attachment",
        method="create",
        kwargs_json=json.dumps({"vals_list": [vals]}),
        confirmed=confirmed,
        confirmation_token=confirmation_token,
    )


@mcp.tool(
    description=(
        "FIRST STEP for region screenshots: identify actual anchor selectors from current page HTML "
        "or selectors supplied by the user, then call measure_page. Never guess coordinates or brute-force "
        "selectors/crops. This read-only tool returns per-anchor bounds, page dimensions, viewport and a "
        "suggested clip={x,y,width,height}; no screenshot is taken and no attachment is created. "
        "One or multiple anchors define a suggested rectangle including intervening space; "
        "optional padding extends it. "
        "The suggestion is ADVISORY: the agent decides the final region using these measured coordinates, "
        "and may expand, shrink, combine or crop it. NEXT: call capture_page with your chosen clip. "
        "No measurement token or exact-coordinate match is required. Keep the same viewport/browser settings "
        "for consistent layout; remeasure if layout changes. Coordinates are page-relative CSS pixels."
    ),
    annotations={"readOnlyHint": True, "openWorldHint": True},
)
def measure_page(
    ctx: Context,
    url: str,
    selectors: list[str],
    padding: CapturePadding | None = None,
    expected_text: str | None = None,
    viewport: Viewport | None = None,
    device_scale_factor: float = 1,
    wait_until: Literal["load", "domcontentloaded", "networkidle"] = "networkidle",
    wait_for_selector: str | None = None,
    extra_delay_ms: int = 0,
    color_scheme: Literal["light", "dark"] | None = None,
    cookies: list[dict[str, SecretStr]] | None = None,
    headers: dict[str, SecretStr] | None = None,
) -> ExecuteMethodResponse:
    """Return server-suggested coordinates before any screenshot or attachment write."""
    started = time.time()
    try:
        request = CaptureRequest(
            url=url,
            selectors=selectors,
            padding=padding or CapturePadding(),
            expected_text=expected_text,
            viewport=viewport or Viewport(),
            device_scale_factor=device_scale_factor,
            wait_until=wait_until,
            wait_for_selector=wait_for_selector,
            extra_delay_ms=extra_delay_ms,
            color_scheme=color_scheme,
            cookies=cookies or [],
            headers=headers or {},
        )
        if not request.selectors:
            raise CaptureError("measure_page requires at least one anchor selector")
        policy = CapturePolicy.from_env()
        policy.validate_url(url)
        odoo = get_odoo_client()
        identity = hashlib.sha256(f"{odoo.url}\0{odoo.username}".encode()).hexdigest()
        measured = run_capture(request, policy, identity, measure_only=True)
        measured.pop("success", None)
        return ExecuteMethodResponse(success=True, result=measured, execution_time_ms=_elapsed_ms(started))
    except ValidationError:
        return ExecuteMethodResponse(
            success=False, error="Invalid measurement inputs; check anchors and browser options"
        )
    except CaptureError as exc:
        return ExecuteMethodResponse(success=False, error=str(exc))
    except Exception:
        return ExecuteMethodResponse(success=False, error="Page measurement failed; check server configuration")


@mcp.tool(
    description=(
        "Capture a webpage on the server using Playwright and save it in Odoo ir.attachment. "
        "Returns attachment ID and metadata only; never returns screenshot bytes. Use read_attachment "
        "explicitly when the user wants to view it. Capture is restricted to configured hosts. "
        "Requires the optional capture extra and sandboxed Chromium. In strict mode repeat identical "
        "inputs with confirmed=true and the returned confirmation_token. Cookies accept name/value "
        "pairs only; headers and cookies are ephemeral and scoped to the source site. "
        "Captured URLs omit query strings from stored metadata. Non-2xx pages are still captured. "
        "REGION WORKFLOW: Identify real anchor elements from HTML or user-supplied selectors, then call "
        "measure_page FIRST to obtain element bounds and suggested coordinates. Never guess coordinates "
        "from a preview or brute-force trial crops. The agent chooses the final region based on those measurements; "
        "it may expand, shrink, combine or crop the suggestion. Pass your chosen clip={x,y,width,height} here. "
        "The suggestion is advisory: no measurement token, exact-match check or automatic remeasurement is required. "
        "Coordinates are CSS pixels from the document top-left; clip overrides full_page and is PNG/JPEG only. "
        "Use the same viewport/browser settings as measurement; remeasure if layout changes. "
        "Only normal coordinate/page/size limits apply to clip. Omit clip for whole-page/viewport capture."
    ),
    annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": True},
)
def capture_page(
    ctx: Context,
    url: str,
    format: Literal["png", "jpeg", "pdf", "html", "text", "md"] = "png",
    full_page: bool = True,
    viewport: Viewport | None = None,
    device_scale_factor: float = 1,
    wait_until: Literal["load", "domcontentloaded", "networkidle"] = "networkidle",
    wait_for_selector: str | None = None,
    extra_delay_ms: int = 0,
    color_scheme: Literal["light", "dark"] | None = None,
    clip: CaptureClip | None = None,
    cookies: list[dict[str, SecretStr]] | None = None,
    headers: dict[str, SecretStr] | None = None,
    res_model: str | None = None,
    res_id: int | None = None,
    name: str | None = None,
    confirmed: bool = False,
    confirmation_token: str | None = None,
) -> ExecuteMethodResponse:
    """Gate capture before network access and create through the caller's Odoo client."""
    started = time.time()
    if get_profile().read_only:
        return ExecuteMethodResponse(success=False, error=_read_only_error("capture creates an attachment"))
    try:
        policy = CapturePolicy.from_env()
        request = CaptureRequest(
            url=url,
            format=format,
            full_page=full_page,
            viewport=viewport or Viewport(),
            device_scale_factor=device_scale_factor,
            wait_until=wait_until,
            wait_for_selector=wait_for_selector,
            extra_delay_ms=extra_delay_ms,
            color_scheme=color_scheme,
            clip=clip,
            cookies=cookies or [],
            headers=headers or {},
        )
        policy.validate_url(url)
        filename = name if name is not None else f"capture.{ {'text': 'txt'}.get(format, format)}"
        # Synthetic bytes allow normal schema/classifier checks BEFORE rendering. Only the
        # digest is bound into confirmation state; secrets never enter descriptions or logs.
        template = attachment_values(filename, "Y2FwdHVyZQ==", None, res_model, res_id, "Page capture")
        odoo = get_odoo_client()
        identity = hashlib.sha256(f"{odoo.url}\0{odoo.username}".encode()).hexdigest()
        template["description"] = json.dumps({"capture_digest": request.digest(), "identity": identity})
        _, kwargs, parse_error = _parse_json_args(None, json.dumps({"vals_list": [template]}))
        if parse_error:
            raise CaptureError("Invalid default Odoo context")
        gated, classification = _classify_and_gate(
            odoo, "ir.attachment", "create", [], kwargs, confirmed, confirmation_token, started
        )
        if gated:
            if gated.hint:
                gated.hint = gated.hint.replace("Re-call execute_method", "Re-call capture_page with identical inputs")
            return gated
        captured = run_capture(request, policy, identity)
        description = json.dumps(
            {
                "source_url": safe_url(url),
                "url_final": captured["url_final"],
                "captured_at": captured["captured_at"],
                "viewport": request.viewport.model_dump(),
                "device_scale_factor": device_scale_factor,
                "clip": captured.get("clip"),
                "http_status": captured["http_status"],
            },
            ensure_ascii=False,
        )
        # Include storage metadata in token binding as well as browser inputs.
        vals = attachment_values(
            filename, captured["content_base64"], captured["mimetype"], res_model, res_id, description
        )
        kwargs["vals_list"] = [vals]
        ids = odoo.execute_method("ir.attachment", "create", **kwargs)
        if not isinstance(ids, list) or len(ids) != 1 or type(ids[0]) is not int:
            return ExecuteMethodResponse(success=False, error="Odoo returned an unexpected attachment ID result")
        metadata = {key: value for key, value in captured.items() if key not in {"content_base64", "success"}}
        metadata.update(attachment_id=ids[0], name=filename, res_model=res_model, res_id=res_id)
        # Odoo may resize images or normalize MIME types. Report stored metadata
        # without fetching file bytes.
        try:
            stored = odoo.execute_method(
                "ir.attachment",
                "read",
                ids=ids,
                fields=["name", "mimetype", "file_size"],
                context=kwargs.get("context") or {},
            )[0]
            metadata.update(name=stored["name"], mimetype=stored["mimetype"], size=stored["file_size"])
        except Exception:
            # Create already committed: avoid reporting failure and inviting duplicates.
            metadata["size"] = None
            metadata["note"] = "Attachment created; stored metadata unavailable. Use list_attachments to inspect it."
        return ExecuteMethodResponse(
            success=True, result=metadata, safety=classification, execution_time_ms=_elapsed_ms(started)
        )
    except ValidationError:
        return ExecuteMethodResponse(
            success=False,
            error=(
                "Invalid capture inputs; check clip (PNG/JPEG only, nonnegative x/y, positive width/height), "
                "viewport, credentials and limits"
            ),
        )
    except (CaptureError, ValueError) as exc:
        # Validation errors are safe; Odoo/network exceptions must not echo payloads or page secrets.
        if isinstance(exc, CaptureError):
            return ExecuteMethodResponse(success=False, error=str(exc))
        return ExecuteMethodResponse(success=False, error="Capture inputs or Odoo attachment operation failed")
    except Exception:
        return ExecuteMethodResponse(
            success=False, error="Capture or attachment storage failed; check server configuration"
        )


@mcp.tool(
    description="Find Odoo attachments by record, filename or MIME type. Returns metadata only, never file bytes.",
    annotations={"readOnlyHint": True, "openWorldHint": True},
)
def list_attachments(
    ctx: Context,
    res_model: str | None = None,
    res_id: int | None = None,
    name_contains: str | None = None,
    mimetype: str | None = None,
    limit: int = 20,
    offset: int = 0,
    order: Literal["newest", "oldest", "name"] = "newest",
) -> ExecuteMethodResponse:
    """Use ordinary ORM metadata reads so ACLs and record rules remain authoritative."""
    if not 1 <= limit <= 100 or offset < 0:
        return ExecuteMethodResponse(success=False, error="limit must be 1..100 and offset must be nonnegative")
    if res_model is not None and _validate_model(res_model):
        return ExecuteMethodResponse(success=False, error="Invalid res_model")
    if res_id is not None and (not res_model or res_id <= 0):
        return ExecuteMethodResponse(success=False, error="res_id requires res_model and a positive integer")
    domain = [
        [key, operator, value]
        for key, operator, value in (
            ("res_model", "=", res_model),
            ("res_id", "=", res_id),
            ("name", "ilike", name_contains),
            ("mimetype", "=", mimetype),
        )
        if value is not None
    ]
    return execute_method(
        ctx,
        "ir.attachment",
        "search_read",
        kwargs_json=json.dumps(
            {
                "domain": domain,
                "fields": METADATA_FIELDS,
                "limit": limit,
                "offset": offset,
                "order": {
                    "newest": "create_date desc, id desc",
                    "oldest": "create_date asc, id asc",
                    "name": "name, id",
                }[order],
            }
        ),
    )


@mcp.tool(
    description=(
        "Explicitly read an Odoo attachment on demand. Returns images as MCP image content, text as paginated "
        "untrusted data, PDF text by one-based page and optionally up to two rendered page images. "
        "Tall images use zero-based tile indexes; inspect tile_count for more. Max 25 MiB input, "
        "1568px image preview edge, 2 MiB per image, 30000 text characters. Unsupported files return metadata only."
    ),
    annotations={"readOnlyHint": True, "openWorldHint": True},
)
def read_attachment(
    ctx: Context,
    attachment_id: int,
    tile: int = 0,
    page: int = 1,
    offset: int = 0,
    max_chars: int = 12000,
    render_pages: list[int] | None = None,
) -> ToolResult:
    """Read metadata first, then bytes only when a supported preview was explicitly requested."""

    def result(payload, images=None, error=False):
        return ToolResult(
            content=[TextContent(type="text", text=json.dumps(payload, ensure_ascii=False)), *(images or [])],
            is_error=error,
        )

    if attachment_id <= 0 or tile < 0 or page < 1 or offset < 0 or not 1 <= max_chars <= 30000:
        return result({"success": False, "error": "Invalid attachment ID, tile, page, offset or max_chars"}, error=True)
    if render_pages and (len(render_pages) > 2 or any(number < 1 for number in render_pages)):
        return result({"success": False, "error": "render_pages accepts up to two positive page numbers"}, error=True)
    try:
        odoo = get_odoo_client()
        context = _merge_context({}) or {}
        rows = odoo.execute_method(
            "ir.attachment", "read", ids=[attachment_id], fields=METADATA_FIELDS, context=context
        )
        if not rows:
            raise CaptureError("Attachment not found or inaccessible")
        metadata = rows[0]
        mimetype = metadata.get("mimetype") or ""
        if metadata.get("type") == "url" or not (
            mimetype.startswith(("image/", "text/")) or mimetype in TEXT_MIMETYPES or mimetype == "application/pdf"
        ):
            return result(
                {
                    "success": True,
                    "metadata": metadata,
                    "supported": False,
                    "note": "Preview unsupported; metadata only. URL attachments are never fetched.",
                }
            )
        max_bytes = CapturePolicy.from_env().max_bytes
        if not 0 < metadata.get("file_size", 0) <= max_bytes:
            raise CaptureError("Attachment is empty or exceeds the configured preview byte limit")
        rows = odoo.execute_method(
            "ir.attachment", "read", ids=[attachment_id], fields=["datas"], context={**context, "bin_size": False}
        )
        encoded = rows[0].get("datas") if rows else None
        if not isinstance(encoded, str) or len(encoded) > 4 * ((max_bytes + 2) // 3):
            raise CaptureError("Attachment bytes are missing or exceed the configured size limit")
        data = base64.b64decode(encoded, validate=True)
        if len(data) > max_bytes:
            raise CaptureError("Attachment exceeds the configured preview byte limit")
        payload, images = preview_content(
            metadata, data, tile=tile, page=page, offset=offset, max_chars=max_chars, render_pages=render_pages
        )
        return result(payload, images)
    except CaptureError as exc:
        return result({"success": False, "error": str(exc)}, error=True)
    except Exception:
        return result(
            {"success": False, "error": "Attachment unavailable, access denied, or content could not be decoded"},
            error=True,
        )


# ----- batch_execute phases -----


def _batch_response(
    operations: List[Dict[str, Any]],
    results: List[BatchOperationResult],
    start_time: float,
    **extra: Any,
) -> BatchExecuteResponse:
    """Build a ``BatchExecuteResponse`` with the counters derived from ``results``.

    ``success`` defaults to "no failed result"; gate/rejection responses pass
    ``success=False`` explicitly along with their ``error``/``safety_preview``.
    """
    successful = sum(1 for r in results if r.success)
    failed = len(results) - successful
    return BatchExecuteResponse(
        success=extra.pop("success", failed == 0),
        results=results,
        total_operations=len(operations),
        successful_operations=successful,
        failed_operations=failed,
        execution_time_ms=_elapsed_ms(start_time),
        **extra,
    )


def _batch_read_only_rejection(operations: List[Dict[str, Any]], start_time: float) -> BatchExecuteResponse | None:
    """Reject the whole batch when the read-only kill-switch is on and any op is a side effect."""
    if not get_profile().read_only:
        return None
    for op in operations:
        method = op.get("method", "")
        if is_side_effect_method(method):
            return _batch_response(
                operations,
                [],
                start_time,
                success=False,
                error=_read_only_error(f"batch contains side-effect operation '{method}' on '{op.get('model', '?')}'"),
            )
    return None


def _batch_safety_gate(
    operations: List[Dict[str, Any]],
    classifications: List[SafetyClassification],
    overall_risk: RiskLevel,
    any_needs_confirmation: bool,
    confirmed: bool,
    confirmation_token: str | None,
    start_time: float,
) -> BatchExecuteResponse | None:
    """Refuse BLOCKED ops, run the confirmation gate, audit what will proceed.

    Returns the response to send when the batch must stop here, else ``None``.
    """
    blocked = [c for c in classifications if c.risk_level == RiskLevel.BLOCKED]
    if blocked:
        for c in blocked:
            audit_log(c, confirmed=confirmed, executed=False)
        blocked_models = ", ".join(sorted({c.model for c in blocked}))
        return _batch_response(
            operations,
            [],
            start_time,
            success=False,
            error=f"Batch contains blocked operations on: {blocked_models}. Remove them and retry.",
            pending_confirmation=True,
            safety_preview=classifications,
            overall_risk=overall_risk.value,
        )

    if any_needs_confirmation:
        # Bind the token to the exact list of operations. Substituting any op (or even
        # a single arg within an op) on the re-call produces a different digest.
        decision = _confirmation_gate("__batch__", "batch", operations, confirmed, confirmation_token)
        if decision.outcome == "issue":
            for c in classifications:
                if c.requires_confirmation:
                    audit_log(c, confirmed=False, executed=False)
            return _batch_response(
                operations,
                [],
                start_time,
                success=False,
                error=(
                    "Batch contains operations that require confirmation. Review safety_preview "
                    f"and re-call with confirmed=true and confirmation_token='{decision.token}'."
                ),
                pending_confirmation=True,
                safety_preview=classifications,
                overall_risk=overall_risk.value,
            )
        if decision.outcome == "reject":
            return _batch_response(operations, [], start_time, success=False, error=decision.error)

    for c in classifications:
        if c.risk_level != RiskLevel.SAFE:
            audit_log(c, confirmed=confirmed, executed=True)
    return None


def _parse_batch_operation(idx: int, op: Dict[str, Any]) -> tuple[str, str, list, dict]:
    """Validate one batch op and decode its payload the same way ``execute_method`` does.

    Raises ``ValueError`` prefixed with the operation index so the caller can
    report which op was malformed without calling Odoo.
    """
    if not op.get("model") or not op.get("method"):
        raise ValueError(f"Operation {idx}: 'model' and 'method' required")
    for err in (_validate_model(op["model"]), _validate_method(op["method"])):
        if err:
            raise ValueError(f"Operation {idx}: {err}")
    args, kwargs, parse_err = _parse_json_args(op.get("args_json"), op.get("kwargs_json"))
    if parse_err:
        raise ValueError(f"Operation {idx}: {parse_err}")
    return op["model"], op["method"], args, kwargs


async def _run_batch_operation(odoo: Any, idx: int, op: Dict[str, Any]) -> BatchOperationResult:
    """Parse, then execute one operation off the loop thread; never raises."""
    try:
        model, method, args, kwargs = _parse_batch_operation(idx, op)
        result = await _run_blocking(odoo.execute_method, model, method, *args, **kwargs)
        return BatchOperationResult(operation_index=idx, success=True, result=result)
    except Exception as e:
        return BatchOperationResult(operation_index=idx, success=False, error=str(e))


@mcp.tool(
    description="""Execute multiple Odoo operations in a batch with progress tracking.

    SAFETY: Dangerous operations return pending_confirmation=true with a single-use
    confirmation_token in the error message, bound to the whole operations list. After
    reviewing the safety preview, re-call with the identical operations plus
    confirmed=true and that confirmation_token; confirmed=true alone is refused.

    atomic=True stops at the first failure; it does not roll back. Each operation is a
    separate request, so operations that completed stay committed.""",
    annotations={
        "title": "Batch Execute",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    },
    icons=_tool_icons,
    task=True,  # Enable background task execution with progress
)
async def batch_execute(
    operations: List[Dict[str, Any]],
    atomic: bool = True,
    confirmed: bool = False,
    confirmation_token: str | None = None,
    progress: Progress = Progress(),
) -> BatchExecuteResponse:
    """
    Execute multiple operations efficiently with progress tracking.

    Parameters:
        operations: List of operations, each with:
            - model: str (required)
            - method: str (required)
            - args_json: str (optional)
            - kwargs_json: str (optional)
        atomic: If True, fail fast on first error
        confirmed: Set to true to bypass safety confirmation
    """
    start_time = time.time()

    rejected = _batch_read_only_rejection(operations, start_time)
    if rejected:
        return rejected

    # Get Odoo client directly (works in both sync and background task modes)
    odoo = get_odoo_client()
    await progress.set_total(len(operations))

    # Off the loop thread: the relational check may call fields_get.
    classifications, overall_risk, any_needs_confirmation = await _run_blocking(
        classify_batch, operations, role=current_role(), fields_loader=_fields_loader(odoo)
    )
    gated = _batch_safety_gate(
        operations, classifications, overall_risk, any_needs_confirmation, confirmed, confirmation_token, start_time
    )
    if gated:
        return gated

    results: List[BatchOperationResult] = []
    try:
        for idx, op in enumerate(operations):
            label = f"{op.get('model', 'unknown')}.{op.get('method', 'unknown')}"
            await progress.set_message(f"Operation {idx + 1}/{len(operations)}: {label}")
            outcome = await _run_batch_operation(odoo, idx, op)
            results = [*results, outcome]
            if not outcome.success and atomic:
                return _batch_response(
                    operations, results, start_time, success=False, error=f"Failed at operation {idx}: {outcome.error}"
                )
            await progress.increment()
            # Yield to let the event loop flush progress notifications.
            # Was sleep(0.01) — that added ~1s of dead wall-time to a 100-op batch
            # without buying anything; sleep(0) is enough to schedule pending sends.
            await asyncio.sleep(0)

        failed = sum(1 for r in results if not r.success)
        return _batch_response(
            operations, results, start_time, error=None if failed == 0 else f"{failed} operations failed"
        )
    except Exception as e:
        return _batch_response(operations, results, start_time, success=False, error=str(e))


# ----- URI Routing for read_resource tool -----
# Maps odoo:// URIs to their handler functions. Patterns are compiled once at
# import time (re.Pattern objects) so read_resource doesn't depend on Python's
# implicit re._MAXCACHE for its dispatch path.
# More specific patterns (e.g. /schema, /fields, /docs) MUST come before generic /model/{name}.

_RESOURCE_ROUTES: list[tuple[re.Pattern[str], Any, list[str]]] = [
    (re.compile(pattern), handler, param_names)
    for pattern, handler, param_names in [
        (r"^odoo://models$", _resources.get_models, []),
        (r"^odoo://session-bootstrap$", _resources.get_session_bootstrap, []),
        (r"^odoo://server-status$", _resources._server_status_payload, []),
        (r"^odoo://bundle/(.+)$", _resources.get_bundle, ["models_csv"]),
        (r"^odoo://model/([^/]+)/quick-schema$", _resources.get_model_quick_schema, ["model_name"]),
        (r"^odoo://model/([^/]+)/workflow$", _resources.get_model_workflow, ["model_name"]),
        (r"^odoo://model/([^/]+)/schema$", _resources.get_model_schema, ["model_name"]),
        (r"^odoo://model/([^/]+)/fields$", _resources.get_model_fields_light, ["model_name"]),
        (r"^odoo://model/([^/]+)/docs$", _resources.get_model_docs, ["model_name"]),
        (r"^odoo://model/([^/]+)$", _resources.get_model_info, ["model_name"]),
        (r"^odoo://record/([^/]+)/(\d+)$", _resources.get_record, ["model_name", "record_id"]),
        (r"^odoo://methods/([^/]+)$", _resources.get_methods, ["model_name"]),
        (r"^odoo://find-model/(.+)$", _resources.find_model_resource, ["concept"]),
        (r"^odoo://actions/([^/]+)$", _resources.discover_actions_resource, ["model"]),
        (r"^odoo://tools/(.+)$", _resources.search_tools_resource, ["query"]),
        (r"^odoo://docs/(.+)$", _resources.get_documentation_urls, ["target"]),
        (r"^odoo://module-knowledge/(.+)$", _resources.get_module_knowledge_by_name, ["module_name"]),
        (r"^odoo://module-knowledge$", _resources.get_module_knowledge, []),
        (r"^odoo://concepts$", _resources.get_concept_mappings, []),
        (r"^odoo://templates$", _resources.get_resource_templates, []),
        (r"^odoo://workflows$", _resources.get_workflows, []),
        (r"^odoo://server/info$", _resources.get_server_info, []),
        (r"^odoo://domain-syntax$", _resources.get_domain_syntax, []),
        (r"^odoo://model-limitations$", _resources.get_model_limitations, []),
        (r"^odoo://pagination$", _resources.get_pagination_guide, []),
        (r"^odoo://hierarchical$", _resources.get_hierarchical_guide, []),
        (r"^odoo://aggregation$", _resources.get_aggregation_guide, []),
        (r"^odoo://tool-registry$", _resources.get_tool_registry, []),
        (r"^odoo://api/json2-protocol$", _resources.get_json2_protocol, []),
        (r"^odoo://api/version-drift$", _resources.get_version_drift, []),
        (r"^odoo://api/x2many-commands$", _resources.get_x2many_commands, []),
        (r"^odoo://api-index$", _resources.get_api_index, []),
        (r"^odoo://api/datetime$", _resources.get_datetime_guide, []),
        (r"^odoo://api/mail-thread$", _resources.get_mail_thread_guide, []),
        (r"^odoo://api/security-model$", _resources.get_security_model_guide, []),
        (r"^odoo://api/web-read$", _resources.get_web_read_guide, []),
        (r"^odoo://api/xmlids$", _resources.get_xmlids_guide, []),
        (r"^odoo://session$", _resources.get_session, []),
    ]
]


@mcp.tool(
    description="""Read any odoo:// resource by URI. Use this for schema discovery, method lookup, guides, etc.

    IMPORTANT: Only fetch resources relevant to the user's current task. Do NOT explore multiple resources just to see what's available.

    Recommended workflow:
    1. odoo://find-model/{concept} - Find the right model name
    2. odoo://model/{model}/quick-schema - Get field names and types (ultra-compact, best for tokens)
    3. odoo://methods/{model} - Check available methods if needed
    Then use execute_method() to query.

    Batch operations:
    - odoo://bundle/{models} - Quick-schema for N models in one call (e.g. odoo://bundle/res.partner,sale.order)
    - odoo://session-bootstrap - Bootstrap conversation with schemas + workflows for common models

    Other useful resources:
    - odoo://model/{model}/workflow - State machine transitions
    - odoo://model/{model}/fields - Lightweight field list (larger than quick-schema, includes labels)
    - odoo://domain-syntax - Domain filter reference
    - odoo://aggregation - Aggregation/groupby guide
    - odoo://templates - List all available resource URIs
    """,
    annotations={
        "title": "Read Resource",
        "readOnlyHint": True,
        "openWorldHint": False,
    },
    icons=_tool_icons,
)
def read_resource(uri: str, max_chars: int = _READ_RESOURCE_MAX_CHARS) -> str:
    """Read an Odoo MCP resource by URI.

    Parameters:
        uri: Resource URI (e.g. 'odoo://model/res.partner/fields')
        max_chars: Max output length in characters (default: 15000). Set to 0 for unlimited.
    """
    if not uri.startswith("odoo://"):
        return json.dumps({"error": "Invalid URI: must start with odoo://", "uri": uri})

    for pattern, handler, param_names in _RESOURCE_ROUTES:
        match = pattern.match(uri)
        if match:
            args = dict(zip(param_names, match.groups()))
            result = handler(**args)
            if max_chars and len(result) > max_chars:
                truncated = result[:max_chars]
                warning = json.dumps(
                    {
                        "_truncated": True,
                        "_total_chars": len(result),
                        "_returned_chars": max_chars,
                        "_hint": f"Output truncated from {len(result):,} to {max_chars:,} chars. "
                        f"Use max_chars=0 for full output, or use narrower queries "
                        f"(e.g. odoo://model/{{model}}/fields instead of /schema).",
                    }
                )
                return truncated + "\n\n" + warning
            return result

    return json.dumps(
        {
            "error": f"Unknown resource URI: {uri}",
            "hint": "Use odoo://templates to list all available resource URIs",
            "examples": [
                "odoo://model/res.partner/schema",
                "odoo://model/sale.order/fields",
                "odoo://methods/res.partner",
                "odoo://find-model/invoice",
                "odoo://domain-syntax",
            ],
        },
        indent=2,
    )
