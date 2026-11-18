"""Value checks used by virtual-patch rules.

Each check takes the value under test and a ``Context`` and returns a short
human reason when the value is dangerous, or ``None`` when it is fine.
Checks are deliberately boring and explainable: a defender should be able to
read one and predict what it blocks.
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
from dataclasses import dataclass, field
from fnmatch import fnmatch
from typing import Callable
from urllib.parse import urlsplit

LOOPBACK_HOSTNAMES = ("localhost", "127.0.0.1", "::1", "[::1]")


@dataclass
class Context:
    """Deployment facts a rule may need (filled from CLI flags or a test)."""

    roots: list[str] = field(default_factory=lambda: [os.getcwd()])
    allow_hosts: list[str] = field(default_factory=list)
    allow_origins: list[str] = field(default_factory=list)


Check = Callable[[object, dict, Context], "str | None"]
CHECKS: dict[str, Check] = {}


def check(name: str):
    def deco(fn: Check) -> Check:
        CHECKS[name] = fn
        return fn
    return deco


# --- argument / flag injection -------------------------------------------------

@check("starts_with_dash")
def starts_with_dash(value, params, ctx):
    """A value that begins with '-' is parsed as an option by find, git, tar, curl..."""
    if isinstance(value, str) and value.lstrip().startswith("-"):
        return f"value {value[:40]!r} starts with '-' and would be parsed as a command-line option"
    return None


@check("shell_metachar")
def shell_metachar(value, params, ctx):
    if isinstance(value, str):
        m = re.search(r"[;&|`$<>\n\r]|\$\(", value)
        if m:
            return f"value contains shell metacharacter {m.group(0)!r}"
    return None


@check("regex")
def regex(value, params, ctx):
    if isinstance(value, str) and re.search(params["pattern"], value):
        return params.get("reason") or f"value matches {params['pattern']!r}"
    return None


# --- paths ---------------------------------------------------------------------

def _resolve(path: str, base: str) -> str:
    path = os.path.expanduser(path)
    if not os.path.isabs(path):
        path = os.path.join(base, path)
    # realpath follows symlinks that exist, so a link inside a root that points
    # outside it is judged by where it really goes.
    return os.path.realpath(path)


def _within(path: str, root: str) -> bool:
    root = os.path.realpath(os.path.expanduser(root))
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:  # different drives on Windows
        return False


@check("path_outside_roots")
def path_outside_roots(value, params, ctx):
    if not isinstance(value, str) or not value:
        return None
    roots = params.get("roots") or ctx.roots
    resolved = _resolve(value, roots[0])
    if any(_within(resolved, r) for r in roots):
        return None
    return f"path {value[:60]!r} resolves to {resolved!r}, outside the allowed roots"


DEFAULT_SENSITIVE = [
    "/proc/*", "/etc/*", "/sys/*", "/dev/*", "/root/*",
    "*/.ssh/*", "*/.kube/*", "*/.aws/*", "*/.gnupg/*", "*/.docker/config.json",
    "*/.config/gcloud/*", "*/.azure/*", "*/.git-credentials", "*/.netrc",
    "*/.env", "*/.env.*", "*/id_rsa*", "*/id_ed25519*",
]


@check("path_sensitive")
def path_sensitive(value, params, ctx):
    if not isinstance(value, str) or not value:
        return None
    resolved = _resolve(value, ctx.roots[0]).replace("\\", "/")
    resolved = re.sub(r"^[A-Za-z]:", "", resolved)  # judge C:/etc/x like /etc/x
    for pat in params.get("patterns") or DEFAULT_SENSITIVE:
        if fnmatch(resolved, pat) or fnmatch(resolved.lower(), pat.lower()):
            return f"path {value[:60]!r} points at a sensitive location ({pat})"
    return None


@check("not_suffix")
def not_suffix(value, params, ctx):
    if not isinstance(value, str) or not value:
        return None
    suffixes = tuple(s.lower() for s in params["suffixes"])
    if not value.lower().endswith(suffixes):
        return f"path {value[:60]!r} does not end in one of {list(suffixes)}"
    return None


# --- outbound URLs (SSRF) ------------------------------------------------------

def _literal_ip(host: str):
    """Parse every literal form an HTTP client might accept for an IP."""
    host = host.strip("[]")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # Legacy IPv4 spellings (decimal integer, octal, hex, short forms) that
    # libc and many HTTP stacks still accept: 2130706433, 0x7f.1, 0177.0.0.1
    if re.fullmatch(r"[0-9a-fA-FxX.]+", host):
        try:
            return ipaddress.ip_address(socket.inet_aton(host))
        except OSError:
            return None
    return None


def _ip_is_internal(ip) -> bool:
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_unspecified or ip.is_multicast)


INTERNAL_NAMES = ("localhost", "*.localhost", "*.local", "*.internal",
                  "metadata.google.internal", "*.home.arpa")


@check("url_internal_host")
def url_internal_host(value, params, ctx):
    if not isinstance(value, str) or "://" not in value:
        return None
    try:
        host = urlsplit(value.strip()).hostname or ""
    except ValueError:
        return f"URL {value[:60]!r} does not parse"
    host = host.rstrip(".").lower()
    if not host:
        return f"URL {value[:60]!r} has no host"
    ip = _literal_ip(host)
    if ip is not None:
        if _ip_is_internal(ip):
            return f"URL host {host!r} is an internal address ({ip})"
        return None
    if any(fnmatch(host, n) for n in INTERNAL_NAMES):
        return f"URL host {host!r} is an internal name"
    if params.get("resolve_dns"):
        # Best effort only: the target can re-resolve differently later
        # (DNS rebinding), so the server's own fetch must re-check the IP.
        try:
            infos = socket.getaddrinfo(host, None)
        except OSError:
            return None
        for info in infos:
            ip = ipaddress.ip_address(info[4][0].split("%")[0])
            if _ip_is_internal(ip):
                return f"URL host {host!r} resolves to internal address {ip}"
    return None


# --- HTTP transport (path / Host / Origin) ----------------------------------------

def normalize_path(target: str) -> str:
    """Normalize a request target the way a lenient router would see it.

    Express (and many routers) match case-insensitively, ignore a trailing
    slash and decode percent-escapes, so a path rule must compare the same
    canonical form or "/API/auth/%63li-token/" walks past it.
    """
    from urllib.parse import unquote
    p = target.split("?", 1)[0].split("#", 1)[0]
    if "://" in p:  # absolute-form request target
        p = urlsplit(p).path or "/"
    for _ in range(3):  # double-encoding
        q = unquote(p)
        if q == p:
            break
        p = q
    p = re.sub(r"/{2,}", "/", p.replace("\\", "/"))
    parts: list[str] = []
    for seg in p.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if parts:
                parts.pop()
            continue
        parts.append(seg)
    return ("/" + "/".join(parts)).lower()


@check("path_is")
def path_is(value, params, ctx):
    """value: the request target. Fires when it names one of params.paths."""
    if not value:
        return None
    norm = normalize_path(value)
    for p in params["paths"]:
        if norm == normalize_path(p):
            return f"request path {value[:60]!r} is {p!r}, which must not be reachable through this hop"
    return None


# --- HTTP transport (Host / Origin) ----------------------------------------------

def _host_only(hostport: str) -> str:
    hostport = hostport.strip().lower()
    if hostport.startswith("["):
        return hostport[: hostport.find("]") + 1]
    return hostport.rsplit(":", 1)[0] if hostport.count(":") == 1 else hostport


@check("host_not_loopback")
def host_not_loopback(value, params, ctx):
    """value: the Host header (None if absent)."""
    if not value:
        return "request has no Host header"
    host = _host_only(value)
    if host in LOOPBACK_HOSTNAMES or host in (h.lower() for h in ctx.allow_hosts):
        return None
    return f"Host {value!r} is not a loopback name (DNS rebinding shape)"


@check("origin_not_loopback")
def origin_not_loopback(value, params, ctx):
    """value: the Origin header. Absent Origin = not a browser cross-site call."""
    if not value:
        return None
    if value in ctx.allow_origins:
        return None
    if value == "null":
        return "Origin 'null' (sandboxed or file:// page)"
    try:
        host = (urlsplit(value).hostname or "").lower()
    except ValueError:
        return f"Origin {value!r} does not parse"
    if host in ("localhost", "127.0.0.1", "::1"):
        return None
    return f"Origin {value!r} is a different site calling a local server"
