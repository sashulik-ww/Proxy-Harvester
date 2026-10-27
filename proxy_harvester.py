#!/usr/bin/env python3
"""Collect public proxy configuration URIs and verify them through Xray and sing-box.

This script only contacts hosts explicitly published in public configuration feeds.
It does not scan port ranges or probe arbitrary IP ranges.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import dataclasses
import datetime as dt
import html
import ipaddress
import json
import logging
import math
import os
import platform
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, quote, unquote, urlencode, urljoin, urlsplit, urlunsplit

import requests
try:
    import pycountry  # type: ignore
except ImportError:  # fallback map still covers common countries
    pycountry = None

ROOT = Path(__file__).resolve().parent
CONFIG_DIR = ROOT / "config"
OUTPUT_DIR = ROOT / "output"
CACHE_DIR = ROOT / ".cache"
LOG = logging.getLogger("proxy-harvester")

PROTOCOL_RE = re.compile(
    r"(?i)(?:vless|vmess|trojan|ss|shadowsocks|hysteria2|hy2|tuic|socks5?|socks)://[^\s<>\"']+"
)
TELEGRAM_RE = re.compile(r"(?i)https?://(?:www\.)?t\.me/(?:s/)?([A-Za-z][A-Za-z0-9_]{3,})")
RAW_GITHUB_RE = re.compile(r"https?://(?:raw\.githubusercontent\.com|gist\.githubusercontent\.com)/[^\s\"'<>]+", re.I)
MAX_DOWNLOAD_BYTES = 2_000_000
USER_AGENT = "Proxy-Harvester/1.0 (+public-config-validation; polite-fetching)"

EU_COUNTRIES = {
    "AL", "AD", "AT", "BA", "BE", "BG", "BY", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GB", "GR", "HR", "HU", "IE", "IS", "IT", "LI", "LT", "LU", "LV", "MC", "MD", "ME", "MK", "MT", "NL", "NO", "PL", "PT", "RO", "RS", "SE", "SI", "SK", "SM", "UA", "VA", "XK"
}
COUNTRY_NAMES = {
    "AT": "Austria", "BE": "Belgium", "BG": "Bulgaria", "CH": "Switzerland", "CY": "Cyprus", "CZ": "Czechia", "DE": "Germany", "DK": "Denmark", "EE": "Estonia", "ES": "Spain", "FI": "Finland", "FR": "France", "GB": "United Kingdom", "GR": "Greece", "HR": "Croatia", "HU": "Hungary", "IE": "Ireland", "IS": "Iceland", "IT": "Italy", "LT": "Lithuania", "LU": "Luxembourg", "LV": "Latvia", "MD": "Moldova", "ME": "Montenegro", "MK": "North Macedonia", "NL": "Netherlands", "NO": "Norway", "PL": "Poland", "PT": "Portugal", "RO": "Romania", "RS": "Serbia", "SE": "Sweden", "SI": "Slovenia", "SK": "Slovakia", "UA": "Ukraine", "RU": "Russia", "US": "United States", "CA": "Canada", "KZ": "Kazakhstan", "TR": "Türkiye", "GE": "Georgia", "AM": "Armenia", "AZ": "Azerbaijan", "JP": "Japan", "KR": "South Korea", "SG": "Singapore", "HK": "Hong Kong", "TW": "Taiwan", "IN": "India", "ID": "Indonesia", "TH": "Thailand", "VN": "Vietnam", "MY": "Malaysia", "PH": "Philippines", "AU": "Australia", "NZ": "New Zealand", "BR": "Brazil", "AR": "Argentina", "CL": "Chile", "MX": "Mexico", "CO": "Colombia", "ZA": "South Africa", "IL": "Israel", "AE": "United Arab Emirates", "SA": "Saudi Arabia", "IR": "Iran", "PK": "Pakistan", "BD": "Bangladesh", "CN": "China", "MO": "Macao", "XX": "Unknown", "ZZ": "Unknown"
}
DEFAULT_WHITE_SNI_DOMAINS = {
    "vk.com", "vk.ru", "mail.ru", "yandex.ru", "yandex.net", "ya.ru", "yastatic.net",
    "ozon.ru", "wildberries.ru", "wb.ru", "sber.ru", "sberbank.ru", "tbank.ru",
    "gosuslugi.ru", "rutube.ru", "ok.ru", "rambler.ru", "avito.ru", "kinopoisk.ru"
}
def load_white_sni_domains() -> set[str]:
    path = CONFIG_DIR / "white_sni_domains.txt"
    try:
        entries = {line.strip().lower().rstrip(".") for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")}
        return entries or set(DEFAULT_WHITE_SNI_DOMAINS)
    except Exception:
        return set(DEFAULT_WHITE_SNI_DOMAINS)
WHITE_SNI_DOMAINS = load_white_sni_domains()

@dataclass
class Node:
    uri: str
    protocol: str
    host: str
    port: int
    username: str = ""
    password: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    name: str = ""
    source: str = ""
    ip: str = ""
    country: str = "ZZ"
    tcp_ms: float | None = None
    speed_mbps: float | None = None
    xray_ok: bool = False
    singbox_ok: bool = False
    xray_status: str = "not_tested"
    singbox_status: str = "not_tested"
    xray_ms: float | None = None
    singbox_ms: float | None = None
    error: str = ""

    @property
    def country_name(self) -> str:
        if self.country in COUNTRY_NAMES:
            return COUNTRY_NAMES[self.country]
        if self.country in ("", "ZZ", "XX"):
            return "Unknown"
        if pycountry is not None:
            entry = pycountry.countries.get(alpha_2=self.country)
            if entry is not None:
                return str(entry.name)
        return f"Country {self.country}"

    @property
    def is_udp_only(self) -> bool:
        return self.protocol in {"hysteria2", "tuic"}

    @property
    def is_reality_vless(self) -> bool:
        return self.protocol == "vless" and str(self.params.get("security", "")).lower() == "reality"


def _b64decode(value: str) -> str:
    value = unquote(value.strip())
    value = value.replace("-", "+").replace("_", "/")
    value += "=" * ((4 - len(value) % 4) % 4)
    return base64.b64decode(value.encode("ascii"), validate=False).decode("utf-8", "replace")


def _parse_host_port(authority: str) -> tuple[str, int]:
    parsed = urlsplit("//" + authority)
    host = parsed.hostname or ""
    port = parsed.port
    if not host or not port:
        raise ValueError("missing host/port")
    return host, int(port)


def parse_uri(uri: str, source: str = "") -> Node | None:
    """Parse a supported share URI; HTTP/HTTPS proxy endpoints are intentionally excluded."""
    uri = html.unescape(uri.strip()).rstrip(".,;)]}>，。")
    if not uri:
        return None
    try:
        scheme = uri.split("://", 1)[0].lower()
        if scheme in {"http", "https", "socks4", "socks4a"}:
            return None
        if scheme not in {"vless", "vmess", "trojan", "ss", "shadowsocks", "hysteria2", "hy2", "tuic", "socks", "socks5"}:
            return None
        p = urlsplit(uri)
        query_raw = parse_qs(p.query, keep_blank_values=True)
        q = {k: v[-1] for k, v in query_raw.items() if v}
        name = unquote(p.fragment or "")

        if scheme == "vmess":
            encoded = p.netloc + p.path
            decoded = _b64decode(encoded)
            data = json.loads(decoded)
            host = str(data.get("add") or data.get("host") or "")
            port = int(data.get("port") or 0)
            username = str(data.get("id") or "")
            params = {
                "security": "tls" if str(data.get("tls", "")).lower() in {"tls", "true", "1"} else "none",
                "type": str(data.get("net") or "tcp").lower(),
                "host": str(data.get("host") or ""),
                "path": str(data.get("path") or ""),
                "sni": str(data.get("sni") or data.get("host") or ""),
                "fp": str(data.get("fp") or ""),
                "alpn": str(data.get("alpn") or ""),
                "alterId": str(data.get("aid") or "0"),
                "cipher": str(data.get("scy") or "auto"),
                "headerType": str(data.get("type") or "none"),
                "allowInsecure": str(data.get("allowInsecure") or "false"),
            }
            name = str(data.get("ps") or name)
            if not host or not (1 <= port <= 65535) or not username:
                raise ValueError("incomplete vmess config")
            return Node(uri, "vmess", host, port, username=username, params=params, name=name, source=source)

        if scheme in {"ss", "shadowsocks"}:
            body = uri.split("://", 1)[1].split("#", 1)[0]
            body = body.split("?", 1)[0]
            if "@" not in body:
                decoded = _b64decode(body)
                if "@" in decoded:
                    body = decoded
            userinfo, authority = body.rsplit("@", 1) if "@" in body else ("", "")
            if not authority:
                raise ValueError("unrecognized shadowsocks URI")
            if "://" not in authority:
                authority = authority.split("/", 1)[0]
            host, port = _parse_host_port(authority)
            if ":" not in userinfo:
                decoded_userinfo = _b64decode(userinfo)
                if ":" not in decoded_userinfo:
                    raise ValueError("missing shadowsocks method/password")
                userinfo = decoded_userinfo
            method, password = userinfo.split(":", 1)
            method, password = unquote(method), unquote(password)
            if not method or not password:
                raise ValueError("missing shadowsocks method/password")
            return Node(uri, "shadowsocks", host, port, username=method, password=password, params={"security": "none", "plugin": q.get("plugin", "")}, name=name, source=source)

        host = p.hostname or ""
        port = p.port or 0
        if not host or not (1 <= int(port) <= 65535):
            raise ValueError("missing or invalid host/port")
        params: dict[str, Any] = dict(q)
        protocol = {"hy2": "hysteria2", "socks5": "socks"}.get(scheme, scheme)
        username = unquote(p.username or "")
        password = unquote(p.password or "")
        if protocol in {"vless", "trojan", "hysteria2", "tuic", "socks"}:
            if protocol == "tuic":
                if not password and ":" in username:
                    username, password = username.split(":", 1)
            elif protocol in {"trojan", "hysteria2"} and not username:
                username = password
                password = ""
        if protocol == "vless":
            if not username:
                raise ValueError("missing VLESS UUID")
            params.setdefault("type", "tcp")
            params.setdefault("security", "none")
        elif protocol == "trojan":
            if not username:
                raise ValueError("missing Trojan password")
            params.setdefault("security", "tls")
            params.setdefault("type", "tcp")
        elif protocol == "hysteria2":
            if not username:
                raise ValueError("missing Hysteria2 password")
            params.setdefault("security", "tls")
        elif protocol == "tuic":
            if not username or not password:
                raise ValueError("missing TUIC UUID/password")
            params.setdefault("security", "tls")
        elif protocol == "socks":
            params.setdefault("security", "none")
        return Node(uri, protocol, host, int(port), username=username, password=password, params=params, name=name, source=source)
    except Exception as exc:
        LOG.debug("Skip malformed URI from %s (%s)", source, type(exc).__name__)
        return None


def extract_uris(text: str, source: str = "") -> list[Node]:
    text = html.unescape(text or "")
    decoded = _maybe_decode_subscription(text)
    if decoded != text:
        text = decoded
    found: list[Node] = []
    seen: set[str] = set()
    for match in PROTOCOL_RE.finditer(text):
        raw = match.group(0).rstrip(".,;)]}>，。")
        if raw in seen:
            continue
        seen.add(raw)
        node = parse_uri(raw, source)
        if node:
            found.append(node)
    return found


def normalize_source_url(url: str) -> str:
    url = url.strip().rstrip(".,;)]}>，。")
    # Convert common GitHub web-file links into raw content URLs.
    match = re.match(r"https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$", url, re.I)
    if match:
        owner, repo, branch, path = match.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{quote(branch, safe='')}/{quote(path, safe='/')}"
    match = re.match(r"https?://github\.com/([^/]+)/([^/]+)/raw/([^/]+)/(.+)$", url, re.I)
    if match:
        owner, repo, branch, path = match.groups()
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{quote(branch, safe='')}/{quote(path, safe='/')}"
    return url


def extract_feed_urls(text: str) -> list[str]:
    """Find additional raw text feeds without following arbitrary third-party URLs."""
    candidates = [m.group(0).rstrip(".,;)]}>，。") for m in RAW_GITHUB_RE.finditer(text or "")]
    candidates.extend(m.group(0).rstrip(".,;)]}>，。") for m in re.finditer(r"https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:blob|raw)/[^\s\"'<>]+", text or "", re.I))
    # Only keep direct text-like files; do not recursively download generic web pages.
    out: list[str] = []
    for url in candidates:
        normalized = normalize_source_url(url)
        parsed = urlsplit(normalized)
        path = parsed.path.lower()
        if parsed.netloc.lower() in {"raw.githubusercontent.com", "gist.githubusercontent.com"} and path.endswith((".txt", ".list", ".conf", ".json", ".yaml", ".yml", ".sub", ".subscription", ".config")):
            out.append(normalized)
        elif parsed.netloc.lower() == "gist.githubusercontent.com" and "/raw/" in path:
            out.append(normalized)
    return list(dict.fromkeys(out))


def _maybe_decode_subscription(text: str) -> str:
    stripped = "".join(text.strip().split())
    if len(stripped) < 80 or len(stripped) > MAX_DOWNLOAD_BYTES * 2:
        return text
    if re.search(r"(?i)(vless|vmess|trojan|ss|hysteria2|hy2|tuic|socks)://", text):
        return text
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", stripped):
        return text
    try:
        decoded = _b64decode(stripped)
        if re.search(r"(?i)(vless|vmess|trojan|ss|hysteria2|hy2|tuic|socks)://", decoded):
            return decoded
    except Exception:
        pass
    return text


class TelegramPreviewParser(HTMLParser):
    """Collect readable text and links from Telegram's public channel preview only."""
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.in_message_text = 0
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self._tag_stack: list[tuple[str, bool]] = []
        self._void_tags = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = dict(attrs)
        classes = set((attrs_dict.get("class") or "").split())
        if tag == "a" and attrs_dict.get("href"):
            href = attrs_dict["href"] or ""
            if href.startswith(("http://", "https://", "vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")):
                self.links.append(href)
        is_text = tag == "div" and "tgme_widget_message_text" in classes
        if tag not in self._void_tags:
            self._tag_stack.append((tag, is_text))
        if is_text:
            self.in_message_text += 1

    def handle_endtag(self, tag: str) -> None:
        # HTMLParser may encounter Telegram's imperfect HTML; close back to the most
        # recent matching tag rather than assuming every start tag gets an end tag.
        for index in range(len(self._tag_stack) - 1, -1, -1):
            if self._tag_stack[index][0] == tag:
                popped = self._tag_stack[index:]
                del self._tag_stack[index:]
                self.in_message_text = max(0, self.in_message_text - sum(1 for _, was_text in popped if was_text))
                break

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        self.handle_endtag(tag)

    def handle_data(self, data: str) -> None:
        if self.in_message_text and data.strip():
            self.text_parts.append(data.strip())


def _assert_public_http_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("only absolute HTTP(S) source URLs are allowed")
    if parsed.username or parsed.password:
        raise ValueError("source URLs with embedded credentials are not allowed")
    host = parsed.hostname
    try:
        direct = ipaddress.ip_address(host)
        if not direct.is_global:
            raise ValueError("non-public source IP is blocked")
        return
    except ValueError as exc:
        if str(exc) == "non-public source IP is blocked":
            raise
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme.lower() == "https" else 80), type=socket.SOCK_STREAM)
        addresses = {item[4][0] for item in infos}
    except OSError as exc:
        raise ValueError("source hostname did not resolve") from exc
    if not addresses or any(not _is_global_ip(address) for address in addresses):
        raise ValueError("source URL resolves to a non-public IP")


def http_get_text(url: str, timeout: tuple[float, float] = (5, 12), max_bytes: int = MAX_DOWNLOAD_BYTES, headers: dict[str, str] | None = None) -> str:
    session_headers = {"User-Agent": USER_AGENT, "Accept": "text/plain,text/html,application/json,*/*"}
    if headers:
        session_headers.update(headers)
    current_url = url
    for _redirect in range(6):
        _assert_public_http_url(current_url)
        with requests.get(current_url, headers=session_headers, timeout=timeout, stream=True, allow_redirects=False) as response:
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    raise ValueError("redirect has no Location header")
                current_url = urljoin(current_url, location)
                continue
            response.raise_for_status()
            chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(65536):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"source exceeds {max_bytes} bytes")
                chunks.append(chunk)
            data = b"".join(chunks)
            charset = response.encoding or "utf-8"
            return data.decode(charset, "replace")
    raise ValueError("too many redirects")


def fetch_source(url: str) -> str:
    """Fetch a text feed; Telegram channels use their public t.me/s preview."""
    url = url.strip()
    match = TELEGRAM_RE.search(url)
    if match:
        channel = match.group(1)
        if channel.lower().endswith("bot"):
            LOG.info("Skip Telegram bot link (not a public channel): %s", channel)
            return ""
        page_url = f"https://t.me/s/{channel}"
        page = http_get_text(page_url, timeout=(5, 15), max_bytes=MAX_DOWNLOAD_BYTES)
        parser = TelegramPreviewParser()
        parser.feed(page)
        # Some preview links contain config URLs as anchors; append them to post text.
        return "\n".join(parser.text_parts + parser.links)
    return http_get_text(url, timeout=(5, 15), max_bytes=MAX_DOWNLOAD_BYTES)


def read_noncomment_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            rows.append(line)
    return rows


def github_api_get(url: str, token: str = "") -> dict[str, Any] | list[Any]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": USER_AGENT}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = requests.get(url, headers=headers, timeout=(5, 15))
    response.raise_for_status()
    return response.json()


def github_sources(token: str, explicit_repos: list[str], max_repos: int = 15, max_files_per_repo: int = 8) -> tuple[list[tuple[str, str]], list[str]]:
    """Discover likely config files in public repos and explicitly configured repos.

    Returns ([(source URL, content)], discovered Telegram channel names).
    """
    repo_branches: dict[str, str] = {}
    for repo in explicit_repos:
        if re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            repo_branches[repo] = ""

    queries = ["v2ray subscription", "vless proxy config", "hysteria2 nodes"]
    for query in queries:
        try:
            data = github_api_get("https://api.github.com/search/repositories?" + urlencode({"q": query, "sort": "updated", "per_page": 10}), token)
            for item in data.get("items", []):
                full_name = item.get("full_name", "")
                if full_name:
                    repo_branches.setdefault(full_name, item.get("default_branch", "main"))
        except Exception as exc:
            LOG.warning("GitHub repository search failed (%s)", type(exc).__name__)
        time.sleep(0.25)
    # Prioritize explicitly listed repos first, then cap API work to avoid rate limits.
    selected = list(repo_branches.items())[:max_repos]
    output: list[tuple[str, str]] = []
    tg_channels: set[str] = set()
    for full_name, branch in selected:
        try:
            repo_meta = github_api_get(f"https://api.github.com/repos/{full_name}", token)
            branch = branch or repo_meta.get("default_branch") or "main"
            tree = github_api_get(f"https://api.github.com/repos/{full_name}/git/trees/{quote(branch, safe='')}?recursive=1", token)
            entries = tree.get("tree", []) if isinstance(tree, dict) else []
            candidates = []
            for item in entries:
                if item.get("type") != "blob":
                    continue
                path = str(item.get("path", ""))
                size = int(item.get("size") or 0)
                low = path.lower()
                if size <= 0 or size > 350_000:
                    continue
                name = low.rsplit("/", 1)[-1]
                if name in {"readme.md", "readme.txt", "readme.rst"}:
                    # README is used only to discover public source links/channels.
                    candidates.append((path, size, 0))
                elif low.endswith((".txt", ".conf", ".json", ".yaml", ".yml", ".list")) and re.search(r"(sub|node|proxy|config|v2ray|xray|sing.?box|hysteria|all|base64|free|tcp-pass)", low):
                    score = 3
                    if re.search(r"(all|base64|sub|node|config|tcp-pass)", name):
                        score += 3
                    if name.endswith((".json", ".yaml", ".yml")):
                        score -= 1
                    candidates.append((path, size, score))
            candidates.sort(key=lambda x: (-x[2], x[1], x[0]))
            # Keep one README even when it would otherwise be pushed below config files.
            readmes = [x for x in candidates if x[2] == 0][:1]
            configfiles = [x for x in candidates if x[2] > 0][:max_files_per_repo]
            picked = (readmes + configfiles)[:max_files_per_repo + 1]
            for path, _size, _score in picked:
                raw_url = f"https://raw.githubusercontent.com/{full_name}/{quote(branch, safe='')}/{quote(path, safe='/')}"
                try:
                    content = http_get_text(raw_url, timeout=(5, 15), max_bytes=350_000)
                except Exception:
                    continue
                output.append((raw_url, content))
                for match in TELEGRAM_RE.finditer(content):
                    channel = match.group(1)
                    if not channel.lower().endswith("bot"):
                        tg_channels.add(channel)
            LOG.info("GitHub source scan: %s (%d files)", full_name, len(picked))
        except Exception as exc:
            LOG.debug("Skip GitHub repo %s (%s)", full_name, type(exc).__name__)
        time.sleep(0.2)
    return output, sorted(tg_channels)


def _is_global_ip(ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_text)
        return ip.is_global and not ip.is_multicast and not ip.is_unspecified
    except ValueError:
        return False


def resolve_node(node: Node, timeout: float = 3.0) -> Node | None:
    try:
        try:
            ip_obj = ipaddress.ip_address(node.host)
            if not ip_obj.is_global:
                return None
            node.ip = str(ip_obj)
            return node
        except ValueError:
            pass
        infos = socket.getaddrinfo(node.host, node.port, type=socket.SOCK_STREAM)
        ips: list[str] = []
        for info in infos:
            ip = info[4][0]
            if _is_global_ip(ip) and ip not in ips:
                ips.append(ip)
        if not ips:
            return None
        # Prefer stable order; IPv4 first for common client compatibility, then IPv6.
        ips.sort(key=lambda x: (ipaddress.ip_address(x).version != 4, x))
        node.ip = ips[0]
        return node
    except Exception:
        return None


def load_country_cache() -> dict[str, str]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    p = CACHE_DIR / "country_cache.json"
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
        return {str(k): str(v) for k, v in raw.items()}
    except Exception:
        return {}


def save_country_cache(cache: dict[str, str]) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    (CACHE_DIR / "country_cache.json").write_text(json.dumps(cache, ensure_ascii=False, indent=2), encoding="utf-8")


def lookup_countries(nodes: list[Node]) -> None:
    """Resolve IP country using country.is (free HTTPS API); cache answers locally."""
    cache = load_country_cache()
    ips = sorted({n.ip for n in nodes if n.ip and n.ip not in cache})
    for start in range(0, len(ips), 100):
        batch = ips[start:start + 100]
        try:
            response = requests.post(
                "https://api.country.is/",
                json=batch,
                headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
                timeout=(5, 15),
            )
            response.raise_for_status()
            data = response.json()
            if isinstance(data, dict):
                data = [data]
            for row in data if isinstance(data, list) else []:
                ip = str(row.get("ip", ""))
                country = str(row.get("country", "ZZ") or "ZZ").upper()
                if ip:
                    cache[ip] = country
        except Exception as exc:
            LOG.warning("Country lookup failed for %d IPs (%s)", len(batch), type(exc).__name__)
            for ip in batch:
                cache.setdefault(ip, "ZZ")
        time.sleep(0.2)
    save_country_cache(cache)
    for node in nodes:
        node.country = cache.get(node.ip, "ZZ")


def tcp_probe(node: Node, timeout: float) -> Node:
    if node.is_udp_only:
        # Hysteria2/TUIC use QUIC/UDP; a TCP probe would falsely reject valid nodes.
        node.tcp_ms = None
        return node
    started = time.perf_counter()
    try:
        with socket.create_connection((node.host, node.port), timeout=timeout):
            node.tcp_ms = round((time.perf_counter() - started) * 1000, 2)
    except Exception:
        node.tcp_ms = None
    return node


def _transport_params(node: Node) -> tuple[str, dict[str, Any]]:
    p = node.params
    net = str(p.get("type", p.get("network", "tcp")) or "tcp").lower()
    if net in {"tcp", "raw", "none"}:
        return "tcp", {}
    if net in {"ws", "websocket"}:
        host = str(p.get("host") or p.get("wsHost") or "")
        return "ws", {"path": str(p.get("path") or "/"), "host": host}
    if net in {"grpc"}:
        return "grpc", {"service_name": str(p.get("serviceName") or p.get("service_name") or "")}
    if net in {"httpupgrade", "http-upgrade"}:
        return "httpupgrade", {"path": str(p.get("path") or "/"), "host": str(p.get("host") or "")}
    if net in {"xhttp", "splithttp"}:
        return "xhttp", {"path": str(p.get("path") or "/"), "host": str(p.get("host") or ""), "mode": str(p.get("mode") or "auto")}
    if net in {"h2", "http"}:
        return "http", {"path": str(p.get("path") or "/"), "host": str(p.get("host") or "")}
    return net, {"path": str(p.get("path") or "/"), "host": str(p.get("host") or "")}


def _split_alpn(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(x) for x in value if str(x)]
    return [x.strip() for x in re.split(r"[,|]", str(value)) if x.strip()]


def build_xray_outbound(node: Node) -> dict[str, Any] | None:
    p = node.params
    if node.protocol in {"hysteria2", "tuic"}:
        return None
    if node.protocol == "vless":
        user = {"id": node.username, "encryption": "none"}
        if p.get("flow"):
            user["flow"] = str(p["flow"])
        outbound: dict[str, Any] = {"protocol": "vless", "settings": {"vnext": [{"address": node.ip or node.host, "port": node.port, "users": [user]}]}}
    elif node.protocol == "vmess":
        outbound = {"protocol": "vmess", "settings": {"vnext": [{"address": node.ip or node.host, "port": node.port, "users": [{"id": node.username, "alterId": int(p.get("alterId", 0) or 0), "security": str(p.get("cipher", "auto") or "auto")}]}]}}
    elif node.protocol == "trojan":
        outbound = {"protocol": "trojan", "settings": {"servers": [{"address": node.ip or node.host, "port": node.port, "password": node.username}]}}
    elif node.protocol == "shadowsocks":
        outbound = {"protocol": "shadowsocks", "settings": {"servers": [{"address": node.ip or node.host, "port": node.port, "method": node.username, "password": node.password}]}}
    elif node.protocol == "socks":
        server: dict[str, Any] = {"address": node.ip or node.host, "port": node.port}
        if node.username:
            server.update({"users": [{"user": node.username, "pass": node.password}]})
        outbound = {"protocol": "socks", "settings": {"servers": [server]}}
    else:
        return None
    network, network_params = _transport_params(node)
    security = str(p.get("security", "none") or "none").lower()
    stream: dict[str, Any] = {"network": network}
    if network == "ws":
        ws: dict[str, Any] = {"path": network_params.get("path") or "/"}
        if network_params.get("host"):
            ws["headers"] = {"Host": network_params["host"]}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": network_params.get("service_name", "")}
    elif network == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": network_params.get("path") or "/", "host": network_params.get("host", "")}
    elif network == "xhttp":
        stream["xhttpSettings"] = {"path": network_params.get("path") or "/", "host": network_params.get("host", ""), "mode": network_params.get("mode", "auto")}
    elif network == "http":
        stream["httpSettings"] = {"path": network_params.get("path") or "/", "host": [network_params.get("host")] if network_params.get("host") else []}
    if security == "reality":
        stream["security"] = "reality"
        reality: dict[str, Any] = {
            "serverName": str(p.get("sni") or p.get("serverName") or node.host),
            "fingerprint": str(p.get("fp") or p.get("fingerprint") or "chrome"),
            "publicKey": str(p.get("pbk") or p.get("publicKey") or ""),
            "shortId": str(p.get("sid") or p.get("shortId") or ""),
            "spiderX": str(p.get("spx") or p.get("spiderX") or "/"),
        }
        if not reality["publicKey"]:
            return None
        stream["realitySettings"] = reality
    elif security == "tls" or str(p.get("tls", "")).lower() in {"1", "true"}:
        stream["security"] = "tls"
        tls: dict[str, Any] = {"serverName": str(p.get("sni") or p.get("peer") or node.host), "allowInsecure": str(p.get("insecure", p.get("allowInsecure", "false"))).lower() in {"1", "true", "yes"}}
        if p.get("fp") or p.get("fingerprint"):
            tls["fingerprint"] = str(p.get("fp") or p.get("fingerprint"))
        if p.get("alpn"):
            tls["alpn"] = _split_alpn(p.get("alpn"))
        stream["tlsSettings"] = tls
    else:
        stream["security"] = "none"
    outbound["streamSettings"] = stream
    outbound["tag"] = "proxy"
    return outbound


def _singbox_tls(node: Node) -> dict[str, Any] | None:
    p = node.params
    security = str(p.get("security", "none") or "none").lower()
    tls_enabled = security in {"tls", "reality"} or str(p.get("tls", "")).lower() in {"1", "true"}
    if not tls_enabled:
        return None
    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": str(p.get("sni") or p.get("peer") or node.host),
        "insecure": str(p.get("insecure", p.get("allowInsecure", "false"))).lower() in {"1", "true", "yes"},
    }
    alpn = _split_alpn(p.get("alpn"))
    if alpn:
        tls["alpn"] = alpn
    fingerprint = str(p.get("fp") or p.get("fingerprint") or "")
    if fingerprint:
        tls["utls"] = {"enabled": True, "fingerprint": fingerprint}
    if security == "reality":
        public_key = str(p.get("pbk") or p.get("publicKey") or "")
        if not public_key:
            return None
        tls["reality"] = {"enabled": True, "public_key": public_key, "short_id": str(p.get("sid") or p.get("shortId") or "")}
    return tls


def build_singbox_outbound(node: Node) -> dict[str, Any] | None:
    p = node.params
    out: dict[str, Any] = {"tag": "proxy", "server": node.ip or node.host, "server_port": node.port}
    if node.protocol == "vless":
        out.update({"type": "vless", "uuid": node.username})
        if p.get("flow"):
            out["flow"] = str(p["flow"])
    elif node.protocol == "vmess":
        out.update({"type": "vmess", "uuid": node.username, "alter_id": int(p.get("alterId", 0) or 0), "security": str(p.get("cipher", "auto") or "auto")})
    elif node.protocol == "trojan":
        out.update({"type": "trojan", "password": node.username})
    elif node.protocol == "shadowsocks":
        out.update({"type": "shadowsocks", "method": node.username, "password": node.password})
    elif node.protocol == "socks":
        out.update({"type": "socks"})
        if node.username:
            out.update({"username": node.username, "password": node.password})
    elif node.protocol == "hysteria2":
        out.update({"type": "hysteria2", "password": node.username})
        obfs = str(p.get("obfs") or "")
        obfs_password = str(p.get("obfs-password") or p.get("obfs_password") or "")
        if obfs:
            out["obfs"] = {"type": obfs, "password": obfs_password}
        for param, target in (("upmbps", "up_mbps"), ("downmbps", "down_mbps"), ("up_mbps", "up_mbps"), ("down_mbps", "down_mbps")):
            if p.get(param):
                try:
                    out[target] = int(str(p[param]))
                except ValueError:
                    pass
    elif node.protocol == "tuic":
        out.update({"type": "tuic", "uuid": node.username, "password": node.password})
        if p.get("congestion_control"):
            out["congestion_control"] = str(p["congestion_control"])
        if p.get("udp_relay_mode"):
            out["udp_relay_mode"] = str(p["udp_relay_mode"])
        if p.get("zero_rtt_handshake"):
            out["zero_rtt_handshake"] = str(p["zero_rtt_handshake"]).lower() in {"true", "1", "yes"}
    else:
        return None
    tls = _singbox_tls(node)
    if tls is not None:
        out["tls"] = tls
    if node.protocol in {"vless", "vmess", "trojan"}:
        network, net_params = _transport_params(node)
        if network == "ws":
            transport: dict[str, Any] = {"type": "ws", "path": net_params.get("path") or "/"}
            if net_params.get("host"):
                transport["headers"] = {"Host": net_params["host"]}
            out["transport"] = transport
        elif network == "grpc":
            out["transport"] = {"type": "grpc", "service_name": net_params.get("service_name", "")}
        elif network == "httpupgrade":
            out["transport"] = {"type": "httpupgrade", "path": net_params.get("path") or "/", "host": net_params.get("host", "")}
        elif network == "xhttp":
            # xHTTP support is version-dependent in sing-box; leave it to the core's validation.
            out["transport"] = {"type": "http", "path": net_params.get("path") or "/", "host": [net_params.get("host")] if net_params.get("host") else []}
        elif network == "http":
            out["transport"] = {"type": "http", "path": net_params.get("path") or "/", "host": [net_params.get("host")] if net_params.get("host") else []}
    return out


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")


def _find_binary(cli_path: str, names: tuple[str, ...]) -> str | None:
    if cli_path:
        p = Path(cli_path).expanduser()
        if p.exists():
            return str(p.resolve())
        located = shutil.which(cli_path)
        return located
    for name in names:
        located = shutil.which(name)
        if located:
            return located
    return None


def _core_config(node: Node, core: str, listen_port: int) -> dict[str, Any] | None:
    if core == "xray":
        outbound = build_xray_outbound(node)
        if not outbound:
            return None
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": listen_port, "protocol": "socks", "settings": {"auth": "noauth", "udp": False}, "tag": "test-in"}],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
            "routing": {"domainStrategy": "AsIs", "rules": []},
        }
    outbound = build_singbox_outbound(node)
    if not outbound:
        return None
    return {
        "log": {"level": "warn"},
        "inbounds": [{"type": "socks", "tag": "test-in", "listen": "127.0.0.1", "listen_port": listen_port}],
        "outbounds": [outbound, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }


def _reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def _requests_speed_test(local_port: int, timeout: tuple[float, float], speed_url: str) -> tuple[bool, float | None, float | None, str]:
    proxies = {"http": f"socks5h://127.0.0.1:{local_port}", "https": f"socks5h://127.0.0.1:{local_port}"}
    errors: list[str] = []
    # First try a small real download for throughput. If that CDN is blocked, a
    # successful HTTPS health endpoint still counts as working, but has no speed score.
    for url, measure_speed in ((speed_url, True), ("https://www.gstatic.com/generate_204", False), ("https://cp.cloudflare.com/generate_204", False)):
        started = time.perf_counter()
        try:
            with requests.get(url, proxies=proxies, timeout=timeout, stream=True, headers={"User-Agent": USER_AGENT}) as response:
                if response.status_code < 200 or response.status_code >= 400:
                    errors.append(f"HTTP {response.status_code}")
                    continue
                size = 0
                if measure_speed:
                    for chunk in response.iter_content(chunk_size=65536):
                        if chunk:
                            size += len(chunk)
                        if size >= 262144:
                            break
                    elapsed = max(time.perf_counter() - started, 0.001)
                    if size >= 1024:
                        return True, round(elapsed * 1000, 2), round((size * 8 / 1_000_000) / elapsed, 2), "ok"
                    errors.append("too little speed-test data")
                else:
                    return True, round((time.perf_counter() - started) * 1000, 2), None, "health_endpoint_ok"
        except Exception as exc:
            errors.append(type(exc).__name__)
    return False, None, None, ";".join(errors[-3:]) or "connection_failed"


def core_test(node: Node, core: str, binary: str, speed_url: str, connect_timeout: float, read_timeout: float) -> tuple[bool, float | None, float | None, str]:
    port = _reserve_port()
    config = _core_config(node, core, port)
    if config is None:
        return False, None, None, "unsupported"
    temp_dir = Path(tempfile.mkdtemp(prefix=f"proxy-harvester-{core}-"))
    config_path = temp_dir / "config.json"
    _write_json(config_path, config)
    proc: subprocess.Popen | None = None
    try:
        if core == "xray":
            test_commands = [[binary, "run", "-test", "-config", str(config_path)], [binary, "-test", "-config", str(config_path)]]
            validated = False
            for cmd in test_commands:
                try:
                    check = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=8)
                    if check.returncode == 0:
                        validated = True
                        break
                except (subprocess.TimeoutExpired, OSError):
                    continue
            if not validated:
                return False, None, None, "invalid_config"
            run_cmd = [binary, "run", "-config", str(config_path)]
        else:
            check = subprocess.run([binary, "check", "-c", str(config_path)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=8)
            if check.returncode != 0:
                return False, None, None, "invalid_config"
            run_cmd = [binary, "run", "-c", str(config_path)]
        proc = subprocess.Popen(run_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                return False, None, None, "core_exit"
            if _port_open(port):
                break
            time.sleep(0.1)
        else:
            return False, None, None, "inbound_timeout"
        ok, latency, speed, reason = _requests_speed_test(port, (connect_timeout, read_timeout), speed_url)
        return ok, latency, speed, reason
    except subprocess.TimeoutExpired:
        return False, None, None, "core_timeout"
    except Exception as exc:
        return False, None, None, type(exc).__name__
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=1.5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        shutil.rmtree(temp_dir, ignore_errors=True)


def node_identity(node: Node) -> tuple[Any, ...]:
    # Keep credentials/private IDs only in process memory for de-duplication; never log them.
    key_params = tuple(sorted((str(k), str(v)) for k, v in node.params.items() if k not in {"name", "ps"}))
    return (node.protocol, node.host.lower(), node.port, node.username, node.password, key_params)


def deduplicate(nodes: Iterable[Node]) -> list[Node]:
    unique: dict[tuple[Any, ...], Node] = {}
    for n in nodes:
        key = node_identity(n)
        previous = unique.get(key)
        if previous is None:
            unique[key] = n
        elif previous.source and not n.source:
            unique[key] = n
    return list(unique.values())


def sni_matches_allowlist(node: Node) -> bool:
    if not node.is_reality_vless:
        return False
    sni = str(node.params.get("sni") or "").strip().lower().rstrip(".")
    if not sni:
        return False
    return any(sni == domain or sni.endswith("." + domain) for domain in WHITE_SNI_DOMAINS)


def _server_name(node: Node) -> str:
    flag = country_flag(node.country)
    if node.country in {"", "ZZ", "XX"}:
        country = "Unknown"
    else:
        country = node.country_name
    proto = node.protocol.upper()
    if node.is_reality_vless:
        proto += " REALITY"
    if node.tcp_ms is not None:
        latency = f"{node.tcp_ms:.0f}ms"
    elif node.xray_ms is not None or node.singbox_ms is not None:
        values = [v for v in (node.xray_ms, node.singbox_ms) if v is not None]
        latency = f"~{min(values):.0f}ms"
    else:
        latency = "untested"
    speed = f" | {node.speed_mbps:.1f}Mbps" if node.speed_mbps is not None else ""
    return f"{flag} {country} | {proto} | {latency}{speed}"


def country_flag(country: str) -> str:
    c = country.upper()
    if len(c) != 2 or not c.isalpha() or c in {"ZZ", "XX"}:
        return "🏳️"
    return "".join(chr(127397 + ord(ch)) for ch in c)


def named_uri(node: Node) -> str:
    name = _server_name(node)
    if node.protocol == "vmess":
        try:
            p = urlsplit(node.uri)
            data = json.loads(_b64decode(p.netloc + p.path))
            data["ps"] = name
            encoded = base64.b64encode(json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()).decode()
            return "vmess://" + encoded
        except Exception:
            pass
    p = urlsplit(node.uri)
    fragment = quote(name, safe="-_.~")
    return urlunsplit((p.scheme, p.netloc, p.path, p.query, fragment))


def rank_key(node: Node) -> tuple[float, float, int, str]:
    # Higher measured throughput first; latency and European diversity break ties.
    speed = node.speed_mbps if node.speed_mbps is not None else -1.0
    latency = node.tcp_ms if node.tcp_ms is not None else 999999.0
    eu_penalty = 0 if node.country in EU_COUNTRIES else 1
    return (-speed, latency, eu_penalty, node.host)


def pretest_rank_key(node: Node) -> tuple[int, float, int, str]:
    latency = node.tcp_ms if node.tcp_ms is not None else 999999.0
    eu_penalty = 0 if node.country in EU_COUNTRIES else 1
    return (eu_penalty, latency, 0 if node.country not in {"US", "CA"} else 1, node.host)


def apply_low_priority_reduction(nodes: list[Node]) -> list[Node]:
    """Reduce Shadowsocks and SOCKS candidates by 80%, retaining the fastest TCP endpoints."""
    kept: list[Node] = []
    by_proto: dict[str, list[Node]] = {}
    for node in nodes:
        by_proto.setdefault(node.protocol, []).append(node)
    for proto, group in by_proto.items():
        group.sort(key=pretest_rank_key)
        if proto in {"shadowsocks", "socks"}:
            limit = max(1, math.ceil(len(group) * 0.20))
            group = group[:limit]
            LOG.info("Reduced %s candidates to top 20%% (%d kept)", proto, len(group))
        kept.extend(group)
    return sorted(kept, key=pretest_rank_key)


def select_nodes(nodes: Iterable[Node], limit: int, max_per_ip: int, max_per_country: int = 5, required_core: str = "any", protocol: str | None = None, only_country: str | None = None, white_only: bool = False) -> list[Node]:
    ranked = []
    for node in nodes:
        if protocol and node.protocol != protocol:
            continue
        if only_country and node.country != only_country:
            continue
        if white_only and not sni_matches_allowlist(node):
            continue
        if required_core == "xray" and not node.xray_ok:
            continue
        if required_core == "singbox" and not node.singbox_ok:
            continue
        if required_core == "any" and not (node.xray_ok or node.singbox_ok):
            continue
        ranked.append(node)
    ranked.sort(key=rank_key)
    selected: list[Node] = []
    ip_counts: dict[str, int] = {}
    country_counts: dict[str, int] = {}
    for node in ranked:
        if len(selected) >= limit:
            break
        if not node.ip or ip_counts.get(node.ip, 0) >= max_per_ip:
            continue
        country_limit = max_per_country
        if node.country in {"US", "CA"}:
            country_limit = max(1, max_per_country // 2)
        if country_counts.get(node.country, 0) >= country_limit:
            continue
        selected.append(node)
        ip_counts[node.ip] = ip_counts.get(node.ip, 0) + 1
        country_counts[node.country] = country_counts.get(node.country, 0) + 1
    return selected


def write_uri_file(path: Path, nodes: Iterable[Node]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = [named_uri(n) for n in nodes]
    path.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
    return len(rows)


def make_outputs(nodes: list[Node], limits: dict[str, int]) -> dict[str, int]:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    cap = int(limits["general_max"])
    max_country = int(limits["max_per_country"])
    common = select_nodes(nodes, cap, max_per_ip=int(limits["common_max_per_ip"]), max_per_country=max_country)
    counts["working_proxies.txt"] = write_uri_file(OUTPUT_DIR / "working_proxies.txt", common)

    xray = select_nodes(nodes, int(limits["core_max"]), max_per_ip=1, max_per_country=max_country, required_core="xray")
    sing = select_nodes(nodes, int(limits["core_max"]), max_per_ip=1, max_per_country=max_country, required_core="singbox")
    counts["xray_passed.txt"] = write_uri_file(OUTPUT_DIR / "xray_passed.txt", xray)
    counts["singbox_passed.txt"] = write_uri_file(OUTPUT_DIR / "singbox_passed.txt", sing)
    counts["v2rayng.txt"] = write_uri_file(OUTPUT_DIR / "v2rayng.txt", xray)
    counts["karing.txt"] = write_uri_file(OUTPUT_DIR / "karing.txt", sing)

    for proto in ("vless", "vmess", "trojan", "shadowsocks", "socks", "hysteria2", "tuic"):
        selected = select_nodes(nodes, cap, max_per_ip=int(limits["common_max_per_ip"]), max_per_country=max_country, protocol=proto)
        counts[f"by_protocol/{proto}.txt"] = write_uri_file(OUTPUT_DIR / "by_protocol" / f"{proto}.txt", selected)

    russian = select_nodes(nodes, min(250, int(limits["russian_max"])), max_per_ip=2, max_per_country=250, only_country="RU")
    counts["russian_servers.txt"] = write_uri_file(OUTPUT_DIR / "russian_servers.txt", russian)

    white = select_nodes(nodes, min(450, int(limits["white_max"])), max_per_ip=2, max_per_country=5, white_only=True)
    counts["white_checked.txt"] = write_uri_file(OUTPUT_DIR / "white_checked.txt", white)

    hysteria = select_nodes(nodes, cap, max_per_ip=1, max_per_country=max_country, required_core="singbox", protocol="hysteria2")
    counts["hysteria2.txt"] = write_uri_file(OUTPUT_DIR / "hysteria2.txt", hysteria)
    return counts


def _load_settings() -> dict[str, Any]:
    path = CONFIG_DIR / "settings.json"
    defaults = {
        "max_repositories": 15,
        "max_files_per_repository": 8,
        "max_core_candidates": 1200,
        "core_test_fraction": 0.90,
        "tcp_timeout_seconds": 2.5,
        "core_connect_timeout_seconds": 5,
        "core_read_timeout_seconds": 10,
        "speed_test_url": "https://speed.cloudflare.com/__down?bytes=262144",
        "general_max": 600,
        "core_max": 600,
        "russian_max": 250,
        "white_max": 450,
        "max_per_country": 5,
        "common_max_per_ip": 2,
        "refresh_hours": 1.5,
        "github_auto_discovery": True,
        "telegram_discover_from_github_readmes": True,
        "max_telegram_channels": 25,
    }
    try:
        return {**defaults, **json.loads(path.read_text(encoding="utf-8"))}
    except Exception:
        return defaults


def _save_report(nodes: list[Node], output_counts: dict[str, int], stats: dict[str, Any]) -> None:
    report = {
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "statistics": stats,
        "output_files": output_counts,
        "nodes": [
            {
                "name": _server_name(n), "protocol": n.protocol, "host": n.host, "port": n.port,
                "ip": n.ip, "country_code": n.country, "country": n.country_name,
                "tcp_ms": n.tcp_ms, "speed_mbps": n.speed_mbps,
                "xray": n.xray_status, "sing_box": n.singbox_status,
                "source": n.source,
            } for n in sorted(nodes, key=rank_key)
        ],
    }
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "run_report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    csv_lines = ["name,protocol,host,port,ip,country_code,country,tcp_ms,speed_mbps,xray,sing_box,source"]
    import csv
    from io import StringIO
    buf = StringIO()
    writer = csv.writer(buf)
    writer.writerow(["name", "protocol", "host", "port", "ip", "country_code", "country", "tcp_ms", "speed_mbps", "xray", "sing_box", "source"])
    for n in sorted(nodes, key=rank_key):
        writer.writerow([_server_name(n), n.protocol, n.host, n.port, n.ip, n.country, n.country_name, n.tcp_ms, n.speed_mbps, n.xray_status, n.singbox_status, n.source])
    (OUTPUT_DIR / "run_report.csv").write_text(buf.getvalue(), encoding="utf-8")


def run(args: argparse.Namespace) -> int:
    settings = _load_settings()
    token = (os.environ.get("GH_PAT", "") or os.environ.get("GITHUB_TOKEN", "")).strip()
    source_urls = read_noncomment_lines(CONFIG_DIR / "sources.txt")
    telegram_channels = read_noncomment_lines(CONFIG_DIR / "telegram_channels.txt")
    github_repos = read_noncomment_lines(CONFIG_DIR / "github_repos.txt")
    all_nodes: list[Node] = []
    discovered_channels: set[str] = set()

    if settings.get("github_auto_discovery", True) and not args.no_auto_github:
        LOG.info("Discovering public GitHub repositories (GITHUB_TOKEN increases API limits)")
        repo_sources, repo_channels = github_sources(
            token, github_repos,
            max_repos=int(settings.get("max_repositories", 15)),
            max_files_per_repo=int(settings.get("max_files_per_repository", 8)),
        )
        for url, content in repo_sources:
            all_nodes.extend(extract_uris(content, url))
        discovered_channels.update(repo_channels)
        LOG.info("GitHub scan produced %d URI candidates", len(all_nodes))

    # Explicit feeds plus raw text feeds linked by public GitHub READMEs or feed posts.
    feed_queue: list[str] = []
    feed_seen: set[str] = set()
    for url in source_urls:
        normalized = normalize_source_url(url)
        if normalized and normalized not in feed_seen:
            feed_seen.add(normalized)
            feed_queue.append(normalized)
    for _repo_url, content in locals().get("repo_sources", []):
        for url in extract_feed_urls(content):
            if url not in feed_seen and len(feed_queue) < 100:
                feed_seen.add(url)
                feed_queue.append(url)
    cursor = 0
    while cursor < len(feed_queue) and cursor < 100:
        url = feed_queue[cursor]
        cursor += 1
        try:
            content = fetch_source(url)
            all_nodes.extend(extract_uris(content, url))
            for match in TELEGRAM_RE.finditer(content):
                channel = match.group(1)
                if not channel.lower().endswith("bot"):
                    discovered_channels.add(channel)
            for linked in extract_feed_urls(content):
                if linked not in feed_seen and len(feed_queue) < 100:
                    feed_seen.add(linked)
                    feed_queue.append(linked)
        except Exception as exc:
            LOG.warning("Source failed: %s (%s)", url, type(exc).__name__)
        time.sleep(0.15)

    # Telegram public previews are fetched only for supplied/discovered channel names.
    channel_urls: list[tuple[str, str]] = []
    seen_channel: set[str] = set()
    for entry in telegram_channels:
        match = TELEGRAM_RE.search(entry)
        channel = match.group(1) if match else entry.strip().lstrip("@")
        if channel and not channel.lower().endswith("bot") and channel not in seen_channel:
            seen_channel.add(channel)
            channel_urls.append((channel, f"https://t.me/s/{channel}"))
    if settings.get("telegram_discover_from_github_readmes", True):
        for channel in sorted(discovered_channels):
            if channel not in seen_channel and len(channel_urls) < int(settings.get("max_telegram_channels", 25)):
                seen_channel.add(channel)
                channel_urls.append((channel, f"https://t.me/s/{channel}"))
    for channel, url in channel_urls[:int(settings.get("max_telegram_channels", 25))]:
        try:
            content = fetch_source(url)
            found = extract_uris(content, url)
            all_nodes.extend(found)
            LOG.info("Telegram preview scanned: %s (%d configs)", channel, len(found))
        except Exception as exc:
            LOG.debug("Telegram channel unavailable: %s (%s)", channel, type(exc).__name__)
        time.sleep(0.25)

    before_dedupe = len(all_nodes)
    nodes = deduplicate(all_nodes)
    LOG.info("Extracted %d URIs; %d unique configs", before_dedupe, len(nodes))
    if not nodes:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        (OUTPUT_DIR / "run_report.json").write_text(json.dumps({"generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(), "error": "No proxy URIs extracted. Add sources to config/sources.txt, configure public Telegram channels, or verify GitHub API access."}, ensure_ascii=False, indent=2), encoding="utf-8")
        LOG.error("No proxy configs collected. Check source files and connectivity.")
        return 2

    # Resolve only endpoints explicitly published in source material and reject non-public IPs.
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(4, args.workers)) as pool:
        resolved = list(pool.map(resolve_node, nodes))
    nodes = [n for n in resolved if n is not None]
    LOG.info("Public/global endpoints after DNS/IP safety filter: %d", len(nodes))
    if not nodes:
        LOG.error("No globally routable proxy endpoints left after the safety filter")
        return 3

    lookup_countries(nodes)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(4, args.workers)) as pool:
        nodes = list(pool.map(lambda n: tcp_probe(n, float(settings.get("tcp_timeout_seconds", 2.5))), nodes))
    tcp_passed = [n for n in nodes if n.tcp_ms is not None or n.is_udp_only]
    tcp_failed_count = len(nodes) - len(tcp_passed)
    LOG.info("TCP reachable: %d; TCP/QUIC-appropriate candidates: %d; TCP failures: %d", sum(n.tcp_ms is not None for n in nodes), len(tcp_passed), tcp_failed_count)

    candidates = apply_low_priority_reduction(tcp_passed)
    fraction = max(0.0, min(1.0, float(settings.get("core_test_fraction", 0.9))))
    target_count = min(int(settings.get("max_core_candidates", 1200)), max(1, math.ceil(len(candidates) * fraction)))
    candidates = sorted(candidates, key=pretest_rank_key)[:target_count]
    LOG.info("Core testing %d candidates (%.0f%% of eligible pool, capped at %d)", len(candidates), fraction * 100, int(settings.get("max_core_candidates", 1200)))

    xray_bin = _find_binary(args.xray_bin, ("xray", "xray.exe"))
    sing_bin = _find_binary(args.singbox_bin, ("sing-box", "sing-box.exe", "singbox"))
    if args.collect_only:
        for n in candidates:
            n.xray_status = "not_tested_collect_only"
            n.singbox_status = "not_tested_collect_only"
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        write_uri_file(OUTPUT_DIR / "collected_candidates_unverified.txt", candidates)
        _save_report(candidates, {"collected_candidates_unverified.txt": len(candidates)}, {"extracted": before_dedupe, "unique": len(nodes), "tcp_or_udp_eligible": len(tcp_passed), "core_tested": 0})
        LOG.warning("Collect-only mode: these entries are NOT marked as working/verified.")
        return 0
    if args.core in {"xray", "both"} and not xray_bin:
        LOG.error("Xray binary not found. Install Xray-core or pass --xray-bin. Use --collect-only to skip core tests.")
        return 4
    if args.core in {"sing-box", "both"} and not sing_bin:
        LOG.error("sing-box binary not found. Install sing-box or pass --singbox-bin. Use --collect-only to skip core tests.")
        return 4

    speed_url = str(settings.get("speed_test_url", "https://speed.cloudflare.com/__down?bytes=262144"))
    connect_timeout = float(settings.get("core_connect_timeout_seconds", 5))
    read_timeout = float(settings.get("core_read_timeout_seconds", 10))

    def verify_one(node: Node) -> Node:
        speeds: list[float] = []
        if args.core in {"xray", "both"} and xray_bin:
            ok, latency, speed, status = core_test(node, "xray", xray_bin, speed_url, connect_timeout, read_timeout)
            node.xray_ok = ok
            node.xray_status = "passed" if ok else status
            node.xray_ms = latency
            if speed is not None:
                speeds.append(speed)
        else:
            node.xray_status = "not_requested" if args.core != "xray" else "binary_missing"
        if args.core in {"sing-box", "both"} and sing_bin:
            ok, latency, speed, status = core_test(node, "sing-box", sing_bin, speed_url, connect_timeout, read_timeout)
            node.singbox_ok = ok
            node.singbox_status = "passed" if ok else status
            node.singbox_ms = latency
            if speed is not None:
                speeds.append(speed)
        else:
            node.singbox_status = "not_requested" if args.core != "sing-box" else "binary_missing"
        if speeds:
            node.speed_mbps = max(speeds)
        return node

    verified: list[Node] = []
    done = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(args.workers, 8))) as pool:
        futures = [pool.submit(verify_one, node) for node in candidates]
        for future in concurrent.futures.as_completed(futures):
            try:
                verified.append(future.result())
            except Exception as exc:
                LOG.debug("Node verification exception (%s)", type(exc).__name__)
            done += 1
            if done % 25 == 0 or done == len(futures):
                LOG.info("Core validation progress: %d/%d", done, len(futures))
    verified.sort(key=rank_key)
    working = [n for n in verified if n.xray_ok or n.singbox_ok]

    counts = make_outputs(working, {
        "general_max": int(settings.get("general_max", 600)),
        "core_max": int(settings.get("core_max", 600)),
        "russian_max": int(settings.get("russian_max", 250)),
        "white_max": int(settings.get("white_max", 450)),
        "max_per_country": int(settings.get("max_per_country", 5)),
        "common_max_per_ip": int(settings.get("common_max_per_ip", 2)),
    })
    counts["run_report.json"] = 1
    counts["run_report.csv"] = len(working)
    stats = {
        "source_urls_configured": len(source_urls), "source_feeds_fetched": cursor, "telegram_channels_checked": min(len(channel_urls), int(settings.get("max_telegram_channels", 25))),
        "uris_extracted_before_deduplication": before_dedupe, "unique_parsed_configs": len(deduplicate(all_nodes)),
        "public_endpoints": len(nodes), "tcp_or_quic_eligible": len(tcp_passed), "tcp_failed": tcp_failed_count,
        "core_candidates_tested": len(verified), "working_on_at_least_one_core": len(working),
        "xray_passed": sum(1 for n in working if n.xray_ok), "sing_box_passed": sum(1 for n in working if n.singbox_ok),
        "country_lookup_note": "Unknown country is marked ZZ when the geolocation endpoint has no result.",
        "white_checked_note": "SNI-matched candidate list only; not proof that a node works through a particular ISP whitelist.",
    }
    _save_report(working, counts, stats)
    (OUTPUT_DIR / "run_report.txt").write_text(
        "Proxy Harvester Run Report\n"
        f"Generated: {dt.datetime.now(dt.timezone.utc).isoformat()}\n"
        f"Parsed unique configs: {stats['unique_parsed_configs']}\n"
        f"Public endpoints: {stats['public_endpoints']}\n"
        f"TCP/QUIC eligible: {stats['tcp_or_quic_eligible']}\n"
        f"Core candidates tested: {stats['core_candidates_tested']}\n"
        f"Working on at least one core: {stats['working_on_at_least_one_core']}\n"
        f"Xray passed: {stats['xray_passed']}\n"
        f"sing-box passed: {stats['sing_box_passed']}\n\n"
        "Files:\n" + "\n".join(f"- {name}: {count}" for name, count in counts.items()) + "\n",
        encoding="utf-8",
    )
    LOG.info("Finished: %d configs passed at least one core", len(working))
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect public proxy share links and verify them using Xray and/or sing-box.")
    parser.add_argument("--core", choices=("both", "xray", "sing-box"), default="both", help="Which core(s) to use for verification")
    parser.add_argument("--xray-bin", default="", help="Path to Xray executable (default: search PATH)")
    parser.add_argument("--singbox-bin", default="", help="Path to sing-box executable (default: search PATH)")
    parser.add_argument("--workers", type=int, default=4, help="Concurrent checks; keep low to avoid burdening public endpoints")
    parser.add_argument("--collect-only", action="store_true", help="Collect and TCP-check but do not call entries verified")
    parser.add_argument("--no-auto-github", action="store_true", help="Skip automatic GitHub repository discovery")
    parser.add_argument("--debug", action="store_true", help="Verbose debugging logs")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        raise SystemExit(run(args))
    except KeyboardInterrupt:
        LOG.warning("Interrupted by user")
        raise SystemExit(130)
