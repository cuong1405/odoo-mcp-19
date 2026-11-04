FROM python:3.12-slim

ARG INSTALL_CAPTURE=false

WORKDIR /app

# Create non-root user early for layer caching
RUN useradd --system --no-create-home --uid 1001 mcp

# Copy dependency manifests first for layer caching
COPY pyproject.toml README.md ./

# Resolve dependencies from pyproject.toml — never from a list duplicated here.
# A hand-copied list silently drifts from the declared constraints, which then
# never apply because the package itself is installed with --no-deps. It had
# already lost the deliberate `fastmcp<4` ceiling (carrying `>=3.2.0`) that
# tests/test_dependency_pins.py exists to guard, and it never listed
# `cryptography>=42` at all — token_crypto only imported because Authlib, a
# transitive FastMCP dependency, happens to pull cryptography in.
# Installing a stub package resolves the real dependency set into its own cached
# layer, so editing src/ does not re-resolve them; the stub is then replaced by
# the real package below. build/ must go with it: setuptools would otherwise keep
# the stub's empty __init__.py (newer than the COPY'd source) and ship that.
RUN mkdir -p src/odoo_mcp \
    && touch src/odoo_mcp/__init__.py \
    && if [ "$INSTALL_CAPTURE" = "true" ]; then pip install --no-cache-dir '.[capture]'; else pip install --no-cache-dir .; fi \
    && pip uninstall --yes odoo-mcp-19 \
    && rm -rf src build

# Optional browser layer. Chromium stays sandboxed at runtime under UID 1001.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/playwright
RUN if [ "$INSTALL_CAPTURE" = "true" ]; then \
        python -m playwright install --with-deps chromium \
        && apt-get update && apt-get install -y --no-install-recommends fonts-noto-core fonts-noto-cjk \
        && rm -rf /var/lib/apt/lists/* \
        && chmod -R a+rX /opt/playwright; \
    fi

# Copy source and install the local package; dependencies are already resolved
# above, so --no-deps keeps this layer cheap without weakening any constraint.
COPY src/ src/
RUN pip install --no-cache-dir --no-deps .

USER mcp

EXPOSE 8080

# Default command - STDIO transport for Claude Desktop
CMD ["python", "-m", "odoo_mcp"]
