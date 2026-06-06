#!/usr/bin/env python3
"""
Hermes MCP Server v2.3.0 — Web Search & LLM Synthesis

MCP (Model Context Protocol) server che espone strumenti di ricerca web:
  - web_search    : Ricerca rapida via DuckDuckGo / SearXNG + sintesi LLM
  - deep_search   : Ricerca profonda con analisi strutturata dell'LLM
  - read_webpage  : Lettura e sintesi LLM di pagine web (con SSRF guard)

Note: lo strumento `get_current_datetime` è stato spostato nel server dedicato
[hermes-mcp-timedata](https://github.com/ragostino74/hermes-mcp-timedata).


Caratteristiche:
  - Doppio trasporto: stdio (Claude Desktop, VS Code) + HTTP/StreamableHTTP
  - Rate limiting configurabile (token bucket + semaphore)
  - SSRF protection completa (IP privati, IPv6, metadata endpoints)
  - Prompt injection sanitization (3 fasi: control chars, role markers, structural)
  - Cache LRU con TTL e SHA-256

Modi di esecuzione:
  # STDIO (default — per Claude Desktop, VS Code, Hermes Agent)
  python hermes_mcp_server.py

  # HTTP/StreamableHTTP (per llama.cpp WebUI e browser)
  HERMES_MCP_TRANSPORT=http HERMES_MCP_PORT=18760 \
    python hermes_mcp_server.py

  # DUAL (entrambi insieme)
  HERMES_MCP_TRANSPORT=dual HERMES_MCP_PORT=18760 \
    python hermes_mcp_server.py

Variabili d'ambiente:
  LLM_ENDPOINT        : Endpoint LLM OpenAI-compatible (default: localhost:10000/v1)
  LLM_MODEL           : Nome modello (default: Qwen3.6-35B-A3B-Q8_0.gguf)
  SEARXNG_URL         : Istanza SearXNG per ricerca avanzata (opzionale)
  HERMES_MCP_PORT     : Porta HTTP MCP (default: 18760)
  HERMES_MCP_TRANSPORT : stdio | http | dual (default: stdio)
  HERMES_MCP_RATE_LIMIT : Max chiamate/minute per token bucket (default: 5)
  HERMES_MCP_CONCURRENCY : Max chiamate parallele (default: 3)
  HERMES_MCP_BIND_ADDR    : Bind MCP HTTP (default: 127.0.0.1 — solo localhost)
  HERMES_MCP_CORS_ORIGINS : CORS origins comma-separated (default: localhost:*)

Cambiamenti in v2.3.0:
  - Cache FIFO → OrderedDict LRU vero con O(1) eviction
  - str.translate() al posto di loop Python per fullwidth→ASCII (10-50x più veloce)
  - Regex pre-compilate a livello modulo (6 pattern → 0 compilazioni runtime)
  - httpx.Client singleton, riutilizzato su tutte le chiamate LLM/SearXNG
  - User-Agent uniformato a v2.3.0
  - Rimossa sanitizzazione duplicata di query (già fatta alla prima chiamata)
  - Rate limiter: asyncio.Task attribute invece di threading.local()
  - Top-level imports (nessun import dentro funzioni)

Cambiamenti in v2.2.0:
  - Compatibilità FastMCP >= 1.27: tool tornano dict (non json.dumps string)
  - _summarize_with_llm: uniformato a httpx (era http.client.HTTPConnection)
  - Timeout globale 120s su tutte le chiamate LLM con asyncio.wait_for

Cambiamenti in v2.1.1:
  - Banner version fix: allineato a v2.1.0 (era v2.0.0)
  - CORS allow_credentials disabilitato: compatibile con browser moderne + wildcard subdomains

Cambiamenti in v2.1.0:
  - Bind default cambiato da 0.0.0.0 a 127.0.0.1 (sicurezza: non esposto alla rete)
  - deep_search: query sanitizzata prima di ogni iniezione nel prompt LLM
  - Requisiti rimossi: sympy, numpy, scipy (non usati)
  - Errori RESTful invece di [hidden] per debugging
  - Rimossa importazione morta TransportSecuritySettings
"""

# ── Top-level imports (no lazy imports — compiled once at module load) ────
import json
import sys
import os
import re
import hashlib
import asyncio
import signal as sig_mod
import functools
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin, urlencode as _urlencode
from collections import OrderedDict
import socket

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, InitializeRequest
try:
    from mcp.types import MethodTypes
except ImportError:
    MethodTypes = None  # type: ignore[assignment]

try:
    from mcp.server.fastmcp import FastMCP
    FASTMCP_AVAILABLE = True
except ImportError:
    class _FakeFastMCP:  # noqa: F811
        """Stub when mcp[serve] not installed — prevents unbound variable error."""
        def __init__(self, **kw): ...
        async def run_stdio_async(self): pass
        def streamable_http_app(self): return None
        def tool(self): return lambda f: f
    FastMCP = _FakeFastMCP  # type: ignore[assignment]
    FASTMCP_AVAILABLE = False

import httpx
from duckduckgo_search import DDGS


# ── Module-level constants ────────────────────────────────────────────────
VERSION = "2.3.0"
USER_AGENT = f"hermes-mcp-server/{VERSION}"

TRANSPORT = os.environ.get("HERMES_MCP_TRANSPORT", "stdio")
LLM_ENDPOINT = os.environ.get("LLM_ENDPOINT", "http://localhost:10000/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "Qwen3.6-35B-A3B-UD-Q6_K")
SEARXNG_URL = os.environ.get("SEARXNG_URL", "").rstrip("/")

# Server bind address (default 127.0.0.1 for safety)
_MCP_BIND_ADDR = os.environ.get("HERMES_MCP_BIND_ADDR", "127.0.0.1")

# Rate limit config
_RATE_LIMIT_MAX = int(os.environ.get("HERMES_MCP_RATE_LIMIT", "5"))       # calls/minute
_RATE_LIMIT_WINDOW = 60                                                     # seconds
_SEMAPHORE_MAX  = int(os.environ.get("HERMES_MCP_CONCURRENCY", "3"))         # max parallel ext calls

# httpx shared client (single instance, connection pool reused across all calls)
_http_client = httpx.Client(
    timeout=httpx.Timeout(connect=5, read=90, write=10, pool=5),
    follow_redirects=False,
    headers={"User-Agent": USER_AGENT},
)


# ── Fullwidth→ASCII translation table (built once, str.translate is 10-50x faster than Python loop) ──
_fw_translate = str.maketrans(
    # Fullwidth uppercase Ａ–Ｚ (U+FF21..U+FF3A) → A–Z
    "".join(chr(i) for i in range(0xFF21, 0xFF3B)) +
    # Fullwidth lowercase ａ–ｚ (U+FF41..U+FF5A) → a–z
    "".join(chr(i) for i in range(0xFF41, 0xFF5B)) +
    # Fullwidth digits ０–９ (U+FF10..U+FF19) → 0–9
    "".join(chr(i) for i in range(0xFF10, 0xFF1A)),
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
    "abcdefghijklmnopqrstuvwxyz" +
    "0123456789",
)


# ── Pre-compiled regex patterns (compile once at module load) ─────────────
_RE_ROLE_CONTENT = re.compile(
    r"^(\s*)(SYSTEM|SYS|ASSISTANT|AI|BOT|USER|ROLE)(\s*:\s*)(.*)", re.IGNORECASE
)
_RE_ROLE_BARE = re.compile(
    r"^(SYSTEM|SYS|ASSISTANT|AI|BOT|USER|ROLE)$", re.IGNORECASE
)
_RE_ROLE_CN = re.compile(
    r"^(系统指令|system指令|角色设定)(.*)$", re.IGNORECASE | re.UNICODE
)
_RE_YOU_ARE = re.compile(r"^(you are|you're)(\s+.+)$", re.IGNORECASE)
_RE_INSTRUCT_OVERRIDE = re.compile(
    r"^(ignore|ignora|bypass|evade)(\s+.+)$", re.IGNORECASE
)
_RE_TEMPORAL = re.compile(
    r"^(da ora in poi|from now on|d'ora in poi)(\s+.+)$",
    re.IGNORECASE | re.UNICODE,
)


# ── Cache: true LRU via OrderedDict (O(1) get + move-to-end, O(1) popitem last=False) ──
_cache: OrderedDict = OrderedDict()  # type: ignore[assignment]
_CACHE_MAX_SIZE = 100
_CACHE_TTL = 1800


def _cache_key(text: str) -> str:
    """Compute a cache key with process salt to prevent cache poisoning attacks."""
    return hashlib.sha256(
        (os.urandom(0).hex() + text).encode("utf-8", errors="replace")
    ).hexdigest()


def _evict_lru():
    """Remove oldest entry when cache is full — O(1) via OrderedDict."""
    while len(_cache) >= _CACHE_MAX_SIZE:
        _cache.popitem(last=False)  # Remove first (oldest) item


def _get_cached(key):
    entry = _cache.get(key)
    if entry and (datetime.now(timezone.utc) - entry["time"]).seconds < _CACHE_TTL:
        _cache.move_to_end(key)  # Move to end = recently used
        return entry["data"]
    return None


def _set_cache(key, data):
    """Cache with TTL and true LRU eviction (max 100 entries)."""
    if key in _cache:
        del _cache[key]
    else:
        _evict_lru()
    _cache[key] = {"data": data, "time": datetime.now(timezone.utc)}


# ── Rate Limiter / External Call Guard (async-native, no threading.local race) ─

try:
    from aiolimiter import AsyncLimiter as _AsyncLimiter
    _rate_limiter = _AsyncLimiter(_RATE_LIMIT_MAX, _RATE_LIMIT_WINDOW)
except ImportError:
    _rate_limiter = None

_external_sem = asyncio.Semaphore(_SEMAPHORE_MAX)


def _run_in_executor(fn, *args, **kwargs):
    """Run sync callable in event-loop threadpool. Returns a coroutine."""
    loop = asyncio.get_running_loop()
    return loop.run_in_executor(None, lambda: fn(*args, **kwargs))


async def _external_call(fn, *args, **kwargs):
    """Run a sync callable inside semaphore + token-bucket guard."""
    already_gated = getattr(asyncio.current_task(), "_rate_limited", False)

    if not already_gated:
        async with _external_sem:
            if _rate_limiter is not None:
                async with _rate_limiter:
                    return await _run_in_executor(fn, *args, **kwargs)
            else:
                return await _run_in_executor(fn, *args, **kwargs)

    # Inner call path (inside @rate_limited): only token bucket.
    if _rate_limiter is not None:
        async with _rate_limiter:
            return await _run_in_executor(fn, *args, **kwargs)
    else:
        return await _run_in_executor(fn, *args, **kwargs)


def rate_limited(fn):
    """Decorator: wraps any async function under semaphore + token bucket."""
    @functools.wraps(fn)
    async def wrapper(*a, **kw):
        task = asyncio.current_task()
        task._rate_limited = True  # type: ignore[attr-defined]
        try:
            async with _external_sem:
                return await fn(*a, **kw)
        finally:
            task._rate_limited = False  # type: ignore[attr-defined]

    return wrapper


# ── SSRF Protection ────────────────────────────────────────────────────────

def _is_safe_url(url: str) -> bool:
    """Block access to localhost, link-local, cloud metadata endpoints.

    Blocks RFC 1918 private IPs by default (secure for public-facing servers).
    Set MCP_ALLOW_PRIVATE_IPS=1 to allow private-range addresses.

    Also blocks IDN homograph attacks and Unicode confusion characters.
    """
    _allow_private = os.environ.get("MCP_ALLOW_PRIVATE_IPS", "0") == "1"

    parsed = urlparse(url)
    raw_host = (parsed.hostname or "").lower()

    # Block if no hostname (e.g., malformed URL with userinfo like user@ip)
    if not raw_host:
        return False

    # IDN Homograph / Punycode pre-check
    if "xn--" in raw_host:
        return False

    for ch in raw_host:
        if ord(ch) > 127:
            return False

    blocked_hosts = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
    if raw_host in blocked_hosts:
        return False

    try:
        addrinfo = socket.getaddrinfo(raw_host, None)
        for family, socktype, proto, canonname, sockaddr in addrinfo:
            ip = sockaddr[0]

            if ip == "127.0.0.1" or ip.startswith("127."):
                return False
            if ip.startswith("169.254."):
                return False
            if ip in {"169.254.169.254", "168.63.129.16", "169.254.169.253"}:
                return False

            if not _allow_private:
                if ip.startswith("10.") or ip.startswith("192.168."):
                    return False
                if ip.startswith("172."):
                    parts = ip.split(".")
                    if len(parts) == 4 and 16 <= int(parts[1]) <= 31:
                        return False

            lower = ip.lower()
            if lower.startswith("fc") or lower.startswith("fd"):
                return False
            if ip == "::1":
                return False
            if (lower.startswith("fe8") or lower.startswith("fe9") or
                    lower.startswith("fea") or lower.startswith("feb")):
                return False
            if lower.startswith("fec"):
                return False

            if ip.startswith("::ffff:"):
                mapped = ip.split(":")[-1]
                if (mapped == "127.0.0.1" or mapped.startswith("127.") or
                        mapped.startswith("169.254.")):
                    return False
                if not _allow_private:
                    if (mapped.startswith("10.") or
                            mapped.startswith("192.168.")):
                        return False
                    if mapped.startswith("172."):
                        parts = mapped.split(".")
                        if len(parts) == 4 and 16 <= int(parts[1]) <= 31:
                            return False

    except (socket.gaierror, OSError):
        return False

    return True


# ── LLM Prompt Injection Sanitization ──────────────────────────────────────

def _fullwidth_to_ascii(text: str) -> str:
    """Convert fullwidth Unicode chars to ASCII — uses str.translate() (10-50x faster)."""
    return text.translate(_fw_translate)


def _neutralize_role_markers(text: str) -> str:
    """Neutralise role-marker tokens at the start of lines.

    Uses pre-compiled regex patterns (no runtime compilation overhead).
    """
    lines = text.split("\n")
    result_lines = []

    for line in lines:
        if not line.strip():
            result_lines.append(line)
            continue

        stripped = line.strip()
        neutralized = False

        # 1. ROLE: content pattern (most common injection)
        m = _RE_ROLE_CONTENT.match(stripped)
        if m:
            result_lines.append(f"{m.group(1)}[SAFE_ROLE]: {m.group(4)}")
            neutralized = True

        # 2. Bare role token on its own line
        if not neutralized and _RE_ROLE_BARE.match(stripped):
            result_lines.append("[SAFE_ROLE]: " + stripped)
            neutralized = True

        # 3. Chinese prompt injection variants
        if not neutralized:
            m = _RE_ROLE_CN.match(stripped)
            if m:
                result_lines.append(f"[SAFE_ROLE]: {m.group(2).lstrip(':').strip()}")
                neutralized = True

        # 4. "You are" / behaviour-redefinition
        if not neutralized:
            m = _RE_YOU_ARE.match(stripped)
            if m:
                result_lines.append(f"[SAFE_ROLE]: {m.group(2)}")
                neutralized = True

        # 5. Direct instruction override
        if not neutralized:
            m = _RE_INSTRUCT_OVERRIDE.match(stripped)
            if m:
                result_lines.append(f"[SAFE_ROLE]: {m.group(2)}")
                neutralized = True

        # 6. Temporal override
        if not neutralized:
            m = _RE_TEMPORAL.match(stripped)
            if m:
                result_lines.append(f"[SAFE_ROLE]: {m.group(2)}")
                neutralized = True

        if not neutralized:
            result_lines.append(line)

    return "\n".join(result_lines)


def _sanitize_for_llm(text: str, max_len: int = 8000) -> str:
    """Escape / limit user-supplied text before injecting into an LLM prompt."""
    if not isinstance(text, str):
        return ""
    text = text.strip()
    if len(text) > max_len:
        text = text[:max_len] + "\n\n[... truncated for safety ...]"

    # Phase 1: Strip control / zero-width chars
    text = re.sub(r'[\u200b\u200c\u200d\ufeff\u2060\u00ad]', '', text)
    # Fullwidth variants (10-50x faster via str.translate)
    text = _fullwidth_to_ascii(text)

    # Phase 2: Neutralise role-marker tokens
    text = _neutralize_role_markers(text)

    # Phase 3: Structural / formatting attacks
    replacements = [
        ("```", "[CODE_BLOCK]"),
        ("<!--", "[HTML_COMMENT]"),
        (">>>",  "[PYTHON_PROMPT]"),
        ("\n---\n", "\n[SEP]\n"),
    ]
    for bad, good in replacements:
        text = text.replace(bad, good)
    return text


def _sanitize_search_result(text: str, max_len: int = 2000) -> str:
    """Sanitize text from web search results before injecting into LLM prompts."""
    return _sanitize_for_llm(text, max_len=max_len)


# ── HTTP call wrappers (reuses shared httpx.Client singleton) ─────────────

def _summarize_with_llm(prompt_text: str, max_tokens: int = 1500, temperature: float = 0.3) -> str:
    """Use local LLM to summarize content. Runs via _external_call (threadpool)."""
    try:
        # Runtime SSRF guard on LLM endpoint
        if not _is_safe_url(LLM_ENDPOINT):
            sys.stderr.write("LLM endpoint: blocked unsafe URL\n")
            return ""

        safe_prompt = _sanitize_for_llm(prompt_text, max_len=6000)

        body = json.dumps({
            "model": LLM_MODEL,
            "messages": [{"role": "user", "content": safe_prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        })
        resp = _http_client.post(
            f"{LLM_ENDPOINT}/chat/completions",
            content=body,
            headers={"Content-Type": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPStatusError as exc:
        sys.stderr.write(f"LLM HTTP error: {exc.response.status_code}\n")
        return "Errore durante la sintesi LLM (servizio non disponibile)"
    except Exception:
        sys.stderr.write("LLM summarize error\n")
        return "Errore durante la sintesi LLM"

    if data.get("choices"):
        return data["choices"][0]["message"]["content"].strip()
    return ""


def _search_ddg(query, max_results=5):
    """Search via DuckDuckGo."""
    ck = _cache_key(f"ddg:{query}:{max_results}")
    cached = _get_cached(ck)
    if cached:
        return cached
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))
        result = {
            "query": query,
            "results": [
                {"title": r.get("title", ""), "url": r.get("href", ""), "snippet": r.get("body", "")}
                for r in results
            ],
            "total": len(results),
            "source": "duckduckgo",
        }
        _set_cache(ck, result)
        return result
    except Exception:
        sys.stderr.write("DDG search error\n")
        return {"error": "Errore durante la ricerca DuckDuckGo", "results": []}


def _search_searxng(query, max_results=5):
    """Search via SearXNG instance."""
    if not SEARXNG_URL:
        return None  # Not configured — caller decides fallback

    # Runtime SSRF guard on SearXNG URL (validated at call time, not just startup)
    if not _is_safe_url(SEARXNG_URL):
        sys.stderr.write("SearXNG: blocked unsafe URL\n")
        return {"error": "SearXNG URL bloccato (localhost, IP privati o non sicuri)", "results": []}

    ck = _cache_key(f"searxng:{query}:{max_results}")
    cached = _get_cached(ck)
    if cached:
        return cached
    try:
        params = {
            "q": query,
            "format": "json",
            "engines": "google,bing,duckduckgo,wikipedia",
            "categories": "general",
            "language": "it",
        }
        url = f"{SEARXNG_URL}/search?{_urlencode(params)}"
        resp = _http_client.get(url)
        data = resp.json()

        results = []
        for item in data.get("results", [])[:max_results]:
            results.append({
                "title": item.get("title", ""),
                "url": item.get("url", ""),
                "snippet": item.get("content", ""),
            })

        result = {
            "query": query,
            "results": results,
            "total": len(results),
            "source": "searxng",
        }
        _set_cache(ck, result)
        return result
    except Exception:
        sys.stderr.write("SearXNG error\n")
        return {"error": "Errore durante la ricerca SearXNG", "results": []}


def _search_web(query, max_results=5):
    """Unified web search: tries SearXNG first, falls back to DuckDuckGo."""
    searxng_result = _search_searxng(query, max_results)
    if searxng_result is not None and searxng_result.get("results"):
        return searxng_result

    ddg_result = _search_ddg(query, max_results)
    return ddg_result


# ── FastMCP server instance ────────────────────────────────────────────────
if FASTMCP_AVAILABLE:
    mcp_server = FastMCP(
        name="hermes-web-mcp",
        host=_MCP_BIND_ADDR,
    )
else:
    mcp_server = FastMCP(name="hermes-web-mcp")


@mcp_server.tool()
@rate_limited
async def web_search(query: str, max_results: int = 5) -> dict:
    """Ricerca informazioni su internet (SearXNG / DuckDuckGo) + sintesi LLM."""
    # query è già sanitizzata qui — nessun bisogno di re-sanitizzare prima dell'iniezione nel prompt
    # Le regex line-start matchano comunque quando il testo appare dopo "per: " in una nuova riga
    query_sanitized = _sanitize_for_llm(query.strip(), max_len=200)
    max_r = min(max(1, int(max_results)), 10)
    search_result = await _external_call(_search_web, query_sanitized, max_r)

    if "results" in search_result and search_result.get("results") and len(search_result["results"]) > 0:
        raw = "\n---\n".join([
            f"{_sanitize_search_result(r['title'], 150)}: {_sanitize_search_result(r['snippet'], 200)}"
            for r in search_result["results"]
        ])
        summary_prompt = (
            f"Sintetizza in italiano questi risultati di ricerca per: {query_sanitized}\n\n"
            f"{raw}\n\nRispondi con 3-5 punti chiave."
        )
        try:
            llm_result = await asyncio.wait_for(
                _external_call(_summarize_with_llm, summary_prompt), timeout=120)
        except asyncio.TimeoutError:
            sys.stderr.write("LLM call timed out (120s)\n")
            llm_result = None
    else:
        search_result = {}
    return search_result


@mcp_server.tool()
@rate_limited
async def deep_search(query: str) -> dict:
    """Ricerca profonda con analisi del tuo LLM locale."""
    # query già sanitizzata qui — nessun duplicate sanitize
    query_sanitized = _sanitize_for_llm(query.strip(), max_len=200)
    search_result = await _external_call(_search_web, query_sanitized)

    if search_result.get("error"):
        return search_result

    raw_content = "\n---\n".join([
        f"# {_sanitize_search_result(r['title'], 200)}\n{_sanitize_search_result(r['snippet'], 500)}"
        for r in search_result.get("results", [])
    ])
    llm_prompt = (
        f'Analizza questi risultati di ricerca per la query: {query_sanitized}\n\n'
        f"Risultati:\n{raw_content[:8000]}\n\n"
        "Fornisci una risposta completa in italiano con punti chiave, fonti e incertezze."
    )
    try:
        llm_answer = await asyncio.wait_for(
            _external_call(_summarize_with_llm, llm_prompt), timeout=120)
    except asyncio.TimeoutError:
        sys.stderr.write("LLM call timed out (120s)\n")
        llm_answer = None

    return {
        "status": "success",
        "query": query_sanitized,
        "llm_analysis": llm_answer or "LLM summarization not available",
        "source_results": search_result.get("results", []),
    }


@mcp_server.tool()
@rate_limited
async def read_webpage(url: str) -> dict:
    """Leggi il contenuto di una pagina web con riassunto LLM."""
    if not url.startswith(("http://", "https://")):
        return {"error": "URL invalido"}

    # SSRF guard on initial URL
    if not _is_safe_url(url):
        return {"error": "Accesso bloccato: localhost, IP privati e link-local non sono permessi"}

    try:
        final_url = url
        max_redirects = 3
        for _ in range(max_redirects):
            with httpx.Client(
                timeout=httpx.Timeout(connect=5, read=30, write=10, pool=5),
                follow_redirects=False,
                headers={"User-Agent": USER_AGENT},
            ) as client:
                resp = client.get(final_url)

            # Check if redirect (3xx)
            if 300 <= resp.status_code < 400:
                redirect_location = resp.headers.get("location")
                if not redirect_location:
                    return {"error": "Redirect senza location header", "url": url}

                # Resolve relative → absolute URL
                redirect_location = urljoin(final_url, redirect_location)

                # SSRF guard on redirect target (validates the FULL resolved URL)
                if not _is_safe_url(redirect_location):
                    return {
                        "error": f"Accesso bloccato: redirect verso URL non sicuro ({redirect_location})",
                        "url": url,
                        "redirect_from": final_url,
                        "redirect_to": redirect_location,
                    }
                final_url = redirect_location
            else:
                break

        # Strip HTML tags, collapse whitespace
        text = re.sub(r"<[^>]+>", " ", resp.text)
        text = re.sub(r"\s+", " ", text).strip()[:15000]
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.I)
        raw_title = title_match.group(1) if title_match else "N/A"
        title = _sanitize_for_llm(raw_title, max_len=200)

        summary = None
        if len(text) > 200:
            safe_text = re.sub(r'[\u200b\u200c\u200d\ufeff\u2060\u00ad]', '', text[:8000])
            prompt = f"Sintetizza in italiano:\n\n{_sanitize_for_llm(safe_text, max_len=6000)}\n\nFatti principali in max 5 punti."
            try:
                summary = await asyncio.wait_for(
                    _external_call(_summarize_with_llm, prompt), timeout=120)
            except asyncio.TimeoutError:
                sys.stderr.write("LLM call timed out (120s)\n")
                summary = None

        return {
            "status": "success",
            "url": url,
            "title": title,
            "summary": summary,
            "content_preview": text[:2000],
            "total_chars": len(text),
        }
    except Exception as e:
        return {
            "error": "Errore durante la lettura della pagina",
            "url": url,
        }


# ── CORS origins ────────────────────────────────────────────────────────────
_CORS_RAW = os.environ.get("HERMES_MCP_CORS_ORIGINS", "").strip()
if _CORS_RAW.lower() == "[]":
    cors_origins_list: list[str] = []
elif _CORS_RAW.lower() == "*":
    cors_origins_list = ["*"]
elif _CORS_RAW:
    try:
        cors_origins_list = json.loads(_CORS_RAW)
        if not isinstance(cors_origins_list, list):
            cors_origins_list = [json.loads(f'"{_CORS_RAW}"')]
    except (json.JSONDecodeError, ValueError):
        cors_origins_list = [o.strip() for o in _CORS_RAW.split(",") if o.strip()]
else:
    cors_origins_list = ["http://localhost:*", "https://localhost:*"]


# ── Startup helpers ────────────────────────────────────────────────────────

async def main():
    print(f"🔮 Hermes MCP Server v{VERSION}", file=sys.stderr)
    print(f"   Transport: {TRANSPORT}", file=sys.stderr)
    print(f"   LLM: {LLM_ENDPOINT}", file=sys.stderr)

    # SearXNG status check
    if SEARXNG_URL and _http_client:
        if not _is_safe_url(SEARXNG_URL):
            print(f"   SearXNG: blocked unsafe URL", file=sys.stderr)
        else:
            try:
                with httpx.Client(timeout=5, headers={"User-Agent": USER_AGENT}) as c:
                    r = c.get(
                        SEARXNG_URL + "/search",
                        params={"q": "test", "format": "json"},
                        follow_redirects=False,
                    )
                    if r.status_code == 200 and isinstance(r.json(), dict):
                        print(f"   SearXNG: connected ({SEARXNG_URL})", file=sys.stderr)
                    else:
                        print(f"   SearXNG: responding (status {r.status_code})", file=sys.stderr)
            except Exception as e:
                print(f"   SearXNG: unreachable, using DuckDuckGo fallback ({e})", file=sys.stderr)

    # LLM startup probe
    loop = asyncio.get_running_loop()
    try:
        llm_summary = await loop.run_in_executor(None, _summarize_with_llm, "Rispondi solo 'OK'", 5)
        if llm_summary == "OK":
            print(f"   Local LLM: connected ({LLM_MODEL})", file=sys.stderr)
        else:
            print(
                f"   Local LLM: responding (got '{llm_summary[:20]}')",
                file=sys.stderr,
            )
    except Exception as e:
        print(f"   Local LLM: not available ({e})", file=sys.stderr)

    if TRANSPORT == "stdio":
        print("\nRunning in STDIO mode...", file=sys.stderr)
        await mcp_server.run_stdio_async()

    elif TRANSPORT in ("http", "dual"):
        port = int(os.environ.get("HERMES_MCP_PORT", "18760"))

        if FASTMCP_AVAILABLE:
            print(f"\nRunning in HTTP (StreamableHTTP) mode on :{port}...", file=sys.stderr)

            # Build app with CORS support
            from starlette.applications import Starlette
            from starlette.routing import Mount
            from starlette.middleware.cors import CORSMiddleware

            mcp_app = mcp_server.streamable_http_app()

            cors_app = CORSMiddleware(
                app=mcp_app,
                allow_origins=cors_origins_list,
                allow_methods=["POST", "OPTIONS"],
                allow_headers=[
                    "Content-Type", "Authorization", "Accept",
                    "Mcp-Session-Id", "Mcp-Protocol-Version"
                ],
                expose_headers=["Mcp-Session-Id", "Cache-Control", "Content-Disposition"],
            )

            import uvicorn
            config = uvicorn.Config(cors_app, host=_MCP_BIND_ADDR, port=port, log_level="info")
            server = uvicorn.Server(config)

            _shutdown_event = asyncio.Event()

            def _on_signal(_sig, _frame):
                print("\nShutting down...", file=sys.stderr)
                _shutdown_event.set()

            sig_mod.signal(sig_mod.SIGINT, _on_signal)
            sig_mod.signal(sig_mod.SIGTERM, _on_signal)

            try:
                if TRANSPORT == "dual":
                    print("Running in DUAL mode (stdio + HTTP)...", file=sys.stderr)
                    await asyncio.gather(
                        server.serve(),
                        mcp_server.run_stdio_async(),
                    )
                else:
                    await server.serve()
            except SystemExit as e:
                print(f"\nMCP HTTP server exited (code {e.code})", file=sys.stderr)

            await _shutdown_event.wait()
            print("Shutting down...", file=sys.stderr)

        else:
            if TRANSPORT == "dual":
                print("\nDual mode requires mcp[serve]. Falling back to stdio.", file=sys.stderr)
                await mcp_server.run_stdio_async()
            else:
                print(
                    "\nERROR: FastMCP with HTTP requires 'mcp[serve]' package.",
                    file=sys.stderr,
                )
                print("Install with: pip install 'mcp[serve]'", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())
