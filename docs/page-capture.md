# Page capture and attachment artifacts

Capture runs on the MCP host, where Leonix pages are reachable. It creates a
non-public `ir.attachment` through the calling user's JSON-2 API credentials.
The capture response contains metadata only. Screenshot bytes enter the MCP
conversation only after an explicit `read_attachment` call.

## Why Playwright

The inspected `/home/dev-workspace/odoo` checkout identifies itself as **19.0**
in `odoo/release.py`. Its screenshot facility is part of `ChromeBrowser` in
`odoo/tests/common.py`, using `Page.captureScreenshot` for test artifacts.
`ir.actions.report._run_wkhtmltoimage` is a private HTML-report helper that
disables JavaScript. Neither is a public runtime page-capture API suitable for
JSON-2. No Odoo addon or custom attachment fields are needed for this feature.
Compatibility with a separately deployed Odoo 20 instance has not been verified.

## Installation

```bash
pip install -e '.[capture,dev]'
python -m playwright install --with-deps chromium
# Run the MCP server normally, as a non-root user.
```

For Docker:

```bash
docker compose -f docker-compose.yml -f docker-compose.capture.yml up -d --build
# Add -f docker-compose.multiuser.yml when using the existing user registry.
```

The overlay installs Chromium and Vietnamese/CJK fonts, uses the existing
non-root user, enables an init process, and provides shared memory and the
upstream Playwright seccomp profile. The host must permit unprivileged user
namespaces. Chromium is launched with `chromium_sandbox=True`; startup fails
clearly if the sandbox is unavailable. There is no automatic unsafe fallback.
See [Playwright's Docker guidance](https://playwright.dev/python/docs/docker).

### Coolify with automatic profile provisioning

For an existing Coolify **Docker Compose Service** with the OAuth proxy, paste
[`docker-compose.coolify.yml`](../docker-compose.coolify.yml) into its Compose
editor, save, and redeploy. Keep the existing environment variables and Service
resource so the `oauth-data` volume and public endpoints remain associated with
the same stack. This template builds the fork's `master` branch with capture
enabled and preserves the `mcp`/`oauth` service names.

The template embeds the vendored seccomp JSON as a Coolify managed configuration
file (`volumes[].content`). Coolify writes `./chromium-seccomp.json` under the
Service configuration directory before Docker starts the container. The
`security_opt` references that same file. The read-only container mount lets
Coolify manage the host file; the MCP process does not install or modify it.
No manual host download, privileged installer container, or Docker socket mount
is required. See [Coolify managed files](https://coolify.io/docs/services/configuration/persistent-storage).

To generate a template pinned to a release or full commit hash:

```bash
python3 scripts/generate_coolify_compose.py --ref <full-commit-hash> --output coolify-pinned.yml
```

The generator uses only Python's standard library. The checked-in template is
generated from `docker/chromium-seccomp.json`; regenerate it whenever that
profile changes, and check consistency with:

```bash
python3 scripts/generate_coolify_compose.py --output docker-compose.coolify.yml
python3 scripts/generate_coolify_compose.py --check
```

This template is **Coolify-specific**: its managed-file `content` extension must
be processed by Coolify. For plain Docker Compose, use the existing capture
overlay from a local checkout instead. The host must still permit Chromium's
user namespaces; provisioning the seccomp file cannot change host kernel or
AppArmor policies.

The seccomp profile is a browser-sandbox compatibility setting: Docker's default
policy can block the namespace operations needed by sandboxed Chromium.
It is not needed for uploads, attachment reads, or ordinary Odoo operations.
Docker applies this policy before starting the container, so copying it into a
Dockerfile or running an MCP entrypoint script cannot apply it to that container.

The base install still works without the capture extra. Image/PDF previews and
capture require their respective optional dependencies; uploads, metadata lists,
and text reads work without a browser. An approved capture attempt without a
working browser returns an installation/sandbox error and creates no attachment.

## Tools

### `capture_page`

| Input | Default / behavior |
|---|---|
| `url` | Required HTTP/HTTPS URL; destination ports 80/443 only |
| `format` | `png`; also `jpeg`, `pdf`, `html`, `text`, `md` |
| `name` | `capture.<extension>`; filename only |
| `full_page` | `true` |
| `viewport` | `{"width":1440,"height":900}`; width 320–2560, height 240–2160 |
| `device_scale_factor` | 1; range 1–2 |
| `wait_until` | `networkidle`; also `load`, `domcontentloaded` |
| `wait_for_selector` | Optional visible element to wait for |
| `extra_delay_ms` | 0; maximum 10000 |
| `color_scheme` | `light` or `dark`; light if omitted |
| `clip` | Agent-chosen `{x, y, width, height}` in page CSS pixels; PNG/JPEG only; overrides `full_page` |
| `cookies` | Optional `[{"name":"session_id","value":"..."}]`; source-host scope only |
| `headers` | Optional request header map; restricted headers are refused |
| `res_model`, `res_id` | Supply together to link to an existing Odoo record; otherwise unlinked |
| `confirmed`, `confirmation_token` | Existing write-confirmation flow |

Example tool arguments:

```json
{
  "url": "https://leonix-krabby.greeni.leonix.cc/homepage-1",
  "name": "homepage-after.png",
  "wait_until": "domcontentloaded",
  "viewport": {"width": 1440, "height": 900}
}
```

In strict mode the first call classifies `ir.attachment.create` and issues a
single-use confirmation token. After approval, repeat the same inputs with
`confirmed=true` and that token. No page is loaded before the gate passes.
The token binds browser inputs, credentials by digest, storage target, default
Odoo context and Odoo identity. The rendered bytes are produced after approval;
the webpage can change between approval and execution.

A successful response has an `ExecuteMethodResponse.result` containing
`attachment_id`, `name`, `mimetype`, `size`, `url_final`, `title`, `http_status`,
`captured_at`, `blocked_subrequests`, and optional record linkage. A non-2xx
response is still captured and its status reported. Title and other page-derived
metadata are untrusted data. `description` stores the source/final URLs, capture
time, viewport, scale and status. URL query strings, fragments and credentials
are omitted from metadata. Page paths, titles and captured content can still
contain sensitive material; authenticated page captures deliberately store the
content visible to that browser session.

Normal Odoo attachment processing remains enabled, including automatic image
resizing (1920×1920 by default in the inspected Odoo checkout) and MIME type
normalization. Capture reports the stored file size and MIME type after creation.
The tools do not override Odoo's processing or its configured image limits.

No Odoo credentials are automatically used for page login. Without supplied
cookies/headers, capture is anonymous. For authenticated captures **all browser
connections are restricted to the exact source origin**, including redirects;
this prevents custom headers or cookies being forwarded to another host. Such
captures may omit cross-origin assets even when those hosts are allowlisted.
Browser credentials are passed over stdin, never command-line arguments, logs,
or capture descriptions. The worker never receives Odoo API credentials.

### `upload_attachment`

Inputs: `name`, `content_base64`, optional `mimetype`, `description`, record
linkage and confirmation parameters. Accepts standard base64, not a data URL,
up to 25 MiB decoded. Returns Odoo's create result (`[id]`) with the usual safety
classification. The same confirmation inputs are required on re-call.

Use for existing screenshots, PDFs, reports, and other agent workflow artifacts.
No local server paths or remote download URLs are accepted.

### `list_attachments`

Optional filters: `res_model`, `res_id`, `name_contains`, `mimetype`.
`limit` defaults to 20 (maximum 100), `offset` to 0, and `order` to `newest`
(`oldest` and `name` are also supported). Returns id, name, MIME type, file size,
creation time, record linkage, description and attachment type. Never fetches
`datas`. Use offset pagination for more results.

### `read_attachment`

Required `attachment_id`; optional zero-based `tile`, one-based PDF `page`,
character `offset`, `max_chars` (12000, maximum 30000), and `render_pages`
(up to two one-based PDF page numbers).

- Images return one MCP image block and metadata. Previews have a maximum
  1568px edge and 2 MiB JPEG payload. Tall images are cropped into readable
  vertical tiles before resizing. Use `tile_count` and `tile` to continue.
- Text, HTML, Markdown, CSV, JSON, XML and SVG return untrusted text with a
  truncation marker and `next_offset`. No HTML or SVG is executed.
- PDFs return one page's extracted text, with character pagination and
  `page_count`. Request `render_pages` to also see up to two page images.
- Other MIME types and URL attachments return metadata only; URL attachments
  are never downloaded by this tool.

The tool reads metadata first and rejects oversized files before requesting
`datas`. It explicitly disables Odoo's `bin_size` context for the subsequent
binary read. It never uses `sudo`, public URLs, attachment access tokens, or
direct filestore/database reads. Odoo ACLs and record rules govern both calls.
The original attachment bytes remain unchanged by previewing or tiling.

## Network policy and limits

| Environment variable | Default |
|---|---|
| `MCP_CAPTURE_ALLOWED_HOSTS` | `*.leonix.cc` |
| `MCP_CAPTURE_PRIVATE_HOSTS` | Empty; private addresses denied |
| `MCP_CAPTURE_CONCURRENCY` | 2; range 1–4 |
| `MCP_CAPTURE_HOURLY_LIMIT` | 60 attempts per Odoo URL/username |
| `MCP_CAPTURE_TIMEOUT` | 60 seconds per worker; separate queue-wait deadline of the same length |
| `MCP_CAPTURE_NAVIGATION_TIMEOUT` | 30 seconds |
| `MCP_CAPTURE_MAX_BYTES` | 26214400 (25 MiB); may be lowered |
| `MCP_CAPTURE_MAX_HEIGHT` | 20000 CSS pixels; may be lowered |

Host lists accept comma-separated exact hostnames and `*.domain` patterns.
The wildcard matches subdomains, not the apex. Both navigation and subresources
must be allowed; add required CDN hosts explicitly. For internal DNS pointing
to RFC1918 or ULA addresses, add the hostname to **both** lists. Loopback,
link-local/cloud metadata, unspecified, multicast and reserved addresses remain
blocked, including IPv4-mapped IPv6 forms. TLS validation stays enabled.

Every browser TCP connection goes through a local egress proxy. It resolves and
validates all returned addresses, then connects to a checked numeric address.
This closes the DNS check/use race; redirects and subrequests go through the
same policy. Playwright route checks add scheme/host enforcement. Downloads,
service workers, WebSockets, popup pages and non-proxied WebRTC UDP are disabled.
Chromium's normal sandbox is required; the proxy is not protection against a
browser or kernel exploit. Keep browser releases current.

Workers are fresh processes with fresh browsers/contexts, rather than a shared
long-lived browser. This trades startup time for simple cookie/session isolation
and process cleanup. At most 16 requests wait for a worker. The process group is
killed at the total deadline. Rate/concurrency state is process-local and resets
on restart; multiple MCP replicas need an external shared limiter for global
quotas. Captures also have a 4096px width and 60 megapixel bound. Oversized pages
fail clearly; select a section, reduce scale, or set `full_page=false`.

Writes honor existing readonly roles, `MCP_READ_ONLY`, `MCP_WRITE_ALLOWLIST`
(`ir.attachment.create`), locked-mode schema validation and confirmation rules.
Odoo itself checks access to a linked record during attachment creation. The
non-public flag does not hide attachments from other authorized Odoo users.
Retention is manual; no cleanup cron, deletion tool, custom addon or public
sharing is installed. Use existing `execute_method` operations if explicitly
authorized to clean up attachments.

## Validation

```bash
pytest tests/ --ignore=tests/live
```

`test_capture.py` covers blocked networks/hosts, DNS pinning/rebinding,
redirect-target validation, secrets, write gates, metadata-only capture returns,
ACL failures, text pagination, image tiling and PDF previews. Image/PDF tests
skip when those optional packages are absent. Live capture requires installed
Chromium and a host permitting its sandbox. A live Odoo test additionally
requires a designated development account/database; ordinary unit tests never
write attachments to a live instance.

### Region screenshots: measure for guidance, then choose the crop

1. Identify real anchor elements from page HTML (`capture_page` with `format="html"`,
   then `read_attachment`), or use selectors supplied by the user. Do not invent
   selectors, estimate page coordinates from previews or brute-force trial crops.
2. Call the read-only `measure_page` tool. It accepts `url`, one to 32 `selectors`,
   optional `padding` (`top`, `right`, `bottom`, `left`, nonnegative CSS pixels up to
   4096 each), optional `expected_text`, and the usual viewport/browser options.
   Each selector must identify one visible anchor, but a request can measure many
   sections. The server loads the elements and waits for stable layout, then returns
   individual `anchors`, `page_dimensions`, `viewport` and a suggested enclosing `clip`.
   **No screenshot is taken and no attachment is created.**

   ```json
   {
     "url": "https://example.leonix.cc/page",
     "selectors": ["#first-section", "#last-section"],
     "viewport": {"width": 1440, "height": 900}
   }
   ```

3. The agent decides the final region using the measured bounds: copy the suggestion,
   expand it for context, shrink it to inspect details, or combine measured sections.
   Call `capture_page` with `url`, the chosen `clip` and matching viewport/browser settings.
   The crop need not match the suggestion. `selectors`, `padding` and `expected_text`
   belong only to measurement and are not arguments to `capture_page`.
4. Capture uses the chosen coordinates directly. It checks ordinary coordinate,
   page-boundary, dimension, megapixel and byte limits, not equality with a measurement.
   No proof cache, measurement token, expiry, identity binding, or automatic
   remeasurement is involved. The existing attachment-write `confirmation_token`
   flow still applies in strict mode.
5. Use `read_attachment` to inspect the saved image. If the page layout changed
   between calls, remeasure before deciding on a new crop instead of blindly retrying.

The measure-first/no-guessing workflow is taught in MCP tool descriptions; it is
agent guidance rather than a server-enforced coordinate constraint. Measurement and
capture use fresh isolated browsers with the same security policy and quotas, so
keep viewport, scale, fonts and other rendering inputs consistent. Measurements
contain untrusted page data and are advisory snapshots, not a locked browser session.
Omit `clip` for whole-page/viewport capture. Region screenshots support PNG/JPEG.
