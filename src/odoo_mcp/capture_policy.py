"""Capture policy and DNS validation, shared by the tool and its egress proxy."""

import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class CaptureError(ValueError):
    """A safe, public capture error. Never includes URLs, headers or cookies."""


def _patterns(value: str) -> tuple[str, ...]:
    patterns = tuple(p.strip().lower().rstrip(".") for p in value.split(",") if p.strip())
    if any(p == "*" or "/" in p or ":" in p or ("*" in p and not p.startswith("*.")) for p in patterns):
        raise CaptureError("Capture host configuration must contain exact hosts or *.domain patterns")
    return patterns


def host_matches(host: str, patterns: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == p or (p.startswith("*.") and host.endswith(p[1:]) and host != p[2:]) for p in patterns)


@dataclass(frozen=True)
class CapturePolicy:
    hosts: tuple[str, ...]
    private_hosts: tuple[str, ...]
    max_bytes: int = 25 * 1024 * 1024
    max_height: int = 20000
    timeout: int = 60
    navigation_timeout: int = 30
    concurrency: int = 2
    hourly_limit: int = 60

    @classmethod
    def from_env(cls):
        def number(key, default, low, high):
            try:
                value = int(os.environ.get(key, default))
            except ValueError:
                raise CaptureError(f"{key} must be an integer") from None
            if not low <= value <= high:
                raise CaptureError(f"{key} must be between {low} and {high}")
            return value

        return cls(
            hosts=_patterns(os.environ.get("MCP_CAPTURE_ALLOWED_HOSTS", "*.leonix.cc")),
            private_hosts=_patterns(os.environ.get("MCP_CAPTURE_PRIVATE_HOSTS", "")),
            max_bytes=number("MCP_CAPTURE_MAX_BYTES", 25 * 1024 * 1024, 1024, 25 * 1024 * 1024),
            max_height=number("MCP_CAPTURE_MAX_HEIGHT", 20000, 900, 20000),
            timeout=number("MCP_CAPTURE_TIMEOUT", 60, 5, 120),
            navigation_timeout=number("MCP_CAPTURE_NAVIGATION_TIMEOUT", 30, 1, 60),
            concurrency=number("MCP_CAPTURE_CONCURRENCY", 2, 1, 4),
            hourly_limit=number("MCP_CAPTURE_HOURLY_LIMIT", 60, 1, 1000),
        )

    def validate_url(self, url: str) -> tuple[str, int]:
        try:
            parsed = urlsplit(url)
            if any(ord(c) < 33 or ord(c) == 127 for c in url) or len(url) > 8192 or "\\" in url:
                raise ValueError
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError
            host = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except (ValueError, UnicodeError):
            raise CaptureError("Capture URL must be http/https without credentials or control characters") from None
        if port not in {80, 443}:
            raise CaptureError("Capture permits destination ports 80 and 443 only")
        if not host_matches(host, self.hosts):
            raise CaptureError("Destination host is blocked by MCP_CAPTURE_ALLOWED_HOSTS")
        # Literal addresses are checked before DNS, including alternate IPv4 forms via getaddrinfo.
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            self.check_address(host, address)
        return host, port

    def check_address(self, host, address):
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        # These ranges stay forbidden even for explicitly private-enabled hosts.
        if address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified:
            raise CaptureError("Loopback, link-local, multicast and metadata addresses are blocked")
        if not address.is_global:
            private = any(
                address in network
                for network in (
                    ipaddress.ip_network("10.0.0.0/8"),
                    ipaddress.ip_network("172.16.0.0/12"),
                    ipaddress.ip_network("192.168.0.0/16"),
                    ipaddress.ip_network("fc00::/7"),
                )
                if address.version == network.version
            )
            if not private or not host_matches(host, self.private_hosts):
                raise CaptureError("Private or reserved destination is blocked; configure MCP_CAPTURE_PRIVATE_HOSTS")

    def resolve(self, host: str, port: int) -> list[tuple]:
        try:
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError:
            raise CaptureError("Capture destination DNS resolution failed") from None
        if not addresses:
            raise CaptureError("Capture destination DNS returned no addresses")
        for _, _, _, _, sockaddr in addresses:
            self.check_address(host, ipaddress.ip_address(sockaddr[0]))
        return addresses


def safe_url(url: str) -> str:
    """Never store URL credentials, query strings or fragments in metadata."""
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme, parsed.hostname or "", parsed.path, "", ""))
