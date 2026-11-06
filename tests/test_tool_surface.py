"""Pin the published tool surface, including workflow artifact uploads.

``execute_workflow`` ran two hard-coded workflows, ``lead_to_won`` and
``create_and_post_invoice``, and both were wrong against Odoo 19 JSON-2: the
first sent ``partner_id`` to ``convert_opportunity`` (the parameter is
``partner``) and marked the lead won anyway, the second treated ``create``'s
``[id]`` result as an int. They are removed rather than repaired: multi-step
operations go through ``batch_execute`` or successive ``execute_method`` calls,
which the safety gate already covers one operation at a time.
"""

import asyncio
from pathlib import Path

import odoo_mcp
import odoo_mcp.server  # noqa: F401  registers every tool the server publishes
from odoo_mcp import resources
from odoo_mcp.app import mcp

REMOVED_TOOL = "execute_workflow"


def _published_tools():
    return asyncio.run(mcp.list_tools())


def test_the_published_tools_are_execute_method_batch_execute_and_read_resource():
    assert {tool.name for tool in _published_tools()} == {
        "execute_method",
        "batch_execute",
        "read_resource",
        "upload_attachment",
        "capture_page",
        "measure_page",
        "list_attachments",
        "read_attachment",
    }


def test_the_tool_registry_resource_does_not_offer_the_removed_tool():
    assert REMOVED_TOOL not in resources.get_tool_registry()


def test_the_tools_search_resource_does_not_offer_the_removed_tool():
    assert REMOVED_TOOL not in resources.search_tools_resource("lead")


def test_nothing_the_package_ships_names_the_removed_tool():
    """Tool and parameter descriptions, resource payloads, prompts and module knowledge
    all come from these files: an agent reading any of them must not be sent to it."""
    package = Path(odoo_mcp.__file__).parent
    shipped = [path for path in package.rglob("*") if path.suffix in {".py", ".json", ".md"}]

    assert shipped, "package files not found: the assertion below would pass vacuously"
    assert [str(p.relative_to(package)) for p in shipped if REMOVED_TOOL in p.read_text(encoding="utf-8")] == []


def test_capture_tool_requires_measured_section_workflow():
    tool = next(tool for tool in _published_tools() if tool.name == "capture_page")
    schema = tool.parameters
    assert "clip" in schema["properties"]
    assert "measurement_token" not in schema["properties"]
    assert "selectors" not in schema["properties"]
    assert "wait_for_selector" in schema["properties"]
    assert "REGION WORKFLOW" in tool.description
    assert "Never guess" in tool.description
    assert "measure_page FIRST" in tool.description
    measure = next(tool for tool in _published_tools() if tool.name == "measure_page")
    assert "no screenshot is taken" in measure.description
    assert "ADVISORY" in measure.description
    assert "selectors" in measure.parameters["properties"]
