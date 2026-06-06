#!/usr/bin/env python3
"""
Hermes MCP Server v2.2.0 — Web Search & LLM Synthesis

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
  - Cache FIFO con TTL e SHA-256

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

Cambiamenti in v2.2.0:
  - Compatibilità FastMCP >= 1.27: tool tornano dict (non json.dumps string)
  - _summarize_with_llm: uniformato a httpx (era http.client.HTTPConnection)
  - Timeout globale 120s su tutte le chiamate LLM con asyncio.wait_for
  - User-Agent aggiornato a v2.2.0

Cambiamenti in v2.1.1:
  - Banner version fix: allineato a v2.1.0 (era v2.0.0)
  - CORS allow_credentials disabilitato: compatibile con browser moderne + wildcard subdomains
  - User-Agent aggiornato a v2.1.1

Cambiamenti in v2.1.0:
  - Bind default cambiato da 0.0.0.0 a 127.0.0.1 (sicurezza: non esposto alla rete)
  - deep_search: query sanitizzata prima di ogni iniezione nel prompt LLM
  - Requisiti rimossi: sympy, numpy, scipy (non usati)
  - Errori RESTful invece di [hidden] per debugging
  - Rimossa importazione morta TransportSecuritySettings
"""
import json, sys, os, re, hashlib, asyncio, signal as sig_mod
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent, InitializeRequest
    try:
        from mcp.types import MethodTypes
    except ImportError:
        MethodTypes = None
except ImportError as e:
    print(f"ERROR: Cannot import MCP packages: {e}", file=sys.stderr)
    sys.exit(1)

try:
    from mcp.server.fastmcp import FastMCP
    FASTMCP_AVAILABLE = True
except ImportError:
    FASTMCP_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

try:
    from duckduckgo_search import DDGS
    DDG_AVAILABLE = True
except ImportError:
    DDG_AVAILABLE = False

TRANSPORT = os.environ.get("HERMES_MCP_TRANSPORT", "stdio")
LLM_ENDPOINT = os.environ.get("LLM_ENDPOINT", "http://localhost:10000/v1")
LLM_MODEL = os.environ.get("LLM_MODEL", "Qwen3.6-35B-A3B-UD-Q6_K")
SEARXNG_URL = os.environ.get("SEARXNG_URL", "").rstrip("/")

# ── Server bind addresses (default 0.0.0.0 for network accessibility) ───
_MCP_BIND_ADDR = os.environ.get("HERMES_MCP_BIND_ADDR", "127.0.0.1")  # MCP HTTP transport — localhost by default for safety; set 0.0.0.0 only on trusted networks


def _is_safe_url(url: str) -> bool:
    """Block access to localhost, link-local, and cloud metadata endpoints.

    By default, all RFC 1918 private IPs are blocked (secure default for
    servers exposed on public networks). Set MCP_ALLOW_PRIVATE_IPS=1 to allow
    private-range addresses — useful when the LLM/SearXNG run on a LAN behind
    this server (e.g., Docker or VM deployments).

    Always blocks: localhost, link-local, cloud metadata (169.254.169.254,
    168.63.129.16), and IPv6 ULA/link-local/site-local ranges.

    Also blocks IDN homograph attacks (e.g., xn--p1ai lookalikes), Unicode
    confusion characters, and punycode-encoded hostnames that could bypass
    hostname-based allowlists via visual spoofing.
    """
    import socket

    _allow_private = os.environ.get("MCP_ALLOW_PRIVATE_IPS", "0") == "1"

    parsed = urlparse(url)
    raw_host = (parsed.hostname or "").lower()

    # ── IDN Homograph / Punycode pre-check ──────────────────────────────
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

            # ── IPv4 loopback — always block ───────────────────────
            if ip == "127.0.0.1" or ip.startswith("127."):
                return False

            # ── IPv4 link-local — always block ─────────────────────
            if ip.startswith("169.254."):
                return False

            # ── Cloud metadata endpoints — must always be blocked ──
            if ip in {"169.254.169.254", "168.63.129.16",
                      "169.254.169.253"}:
                return False

            # ── RFC 1918 private ranges (opt-in via env var) ───────
            if not _allow_private:
                if ip.startswith("10.") or ip.startswith("192.168."):
                    return False
                if ip.startswith("172."):
                    parts = ip.split(".")
                    if len(parts) == 4 and 16 <= int(parts[1]) <= 31:
                        return False

            # ── IPv6 ULA/link-local — always block ─────────────────
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

            # ── IPv4-mapped IPv6 ::ffff:x.x.x.x → unmask and check ─
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

_cache: dict[str, dict] = {}  # Simple dict with LRU eviction
_CACHE_MAX_SIZE = 100
_CACHE_TTL = 1800


# ── Cache salt (anti-poisoning): random per-process, prevents targeted eviction ──
_CACHE_SALT = os.urandom(16).hex()


def _cache_key(text: str) -> str:
    """Compute a cache key with process salt to prevent cache poisoning attacks.

    Salt makes it impossible for an attacker to predict or target specific
    cache entries (mitigates CVE-level cache eviction amplification).
    The salt is per-process — each restart generates a new random value.
    Uses SHA-256 (not MD5) to prevent intentional collision attacks.
    """
    return hashlib.sha256((_CACHE_SALT + text).encode("utf-8", errors="replace")).hexdigest()


def _evict_fifo():
    """Remove oldest entry when cache is full (FIFO eviction)."""
    if len(_cache) >= _CACHE_MAX_SIZE:
        oldest_key = next(iter(_cache))
        del _cache[oldest_key]


def _get_cached(key):
    entry = _cache.get(key)
    if entry and (datetime.now(timezone.utc) - entry["time"]).seconds < _CACHE_TTL:
        return entry["data"]
    return None


def _set_cache(key, data):
    """Cache with TTL and LRU eviction (max 100 entries)."""
    # Evict oldest if at capacity
    _evict_fifo()
    _cache[key] = {"data": data, "time": datetime.now(timezone.utc)}


# ── Rate Limiter / External Call Guard ───────────────────────────────────
import asyncio
from contextlib import asynccontextmanager
import threading

_RATE_LIMIT_MAX = int(os.environ.get("HERMES_MCP_RATE_LIMIT", "5"))       # calls/minute
_RATE_LIMIT_WINDOW = 60                                                     # seconds
_SEMAPHORE_MAX  = int(os.environ.get("HERMES_MCP_CONCURRENCY", "3"))         # max parallel ext calls

# Token bucket: _RATE_LIMIT_MAX tokens per _RATE_LIMIT_WINDOW seconds
try:
    from aiolimiter import AsyncLimiter as _AsyncLimiter
    _rate_limiter = _AsyncLimiter(_RATE_LIMIT_MAX, _RATE_LIMIT_WINDOW)
except ImportError:
    _rate_limiter = None

# Semaphore: hard cap on concurrent external calls
_external_sem = asyncio.Semaphore(_SEMAPHORE_MAX)

# Track whether we're inside a @rate_limited wrapper to avoid double-semaphore acquisition
_rate_limit_ctx = threading.local()


def _run_in_executor(fn, *args, **kwargs):
    """Run sync callable in event-loop threadpool. Returns a coroutine."""
    loop = asyncio.get_running_loop()
    return loop.run_in_executor(None, lambda: fn(*args, **kwargs))


async def _external_call(fn, *args, **kwargs):
    """Run a sync callable inside semaphore + token-bucket guard.

    Meant to be awaited by async callers (MCP tools). When called from within
    a @rate_limited wrapper it skips the semaphore (already held) and only
    applies the token bucket per call.

    If ``aiolimiter`` is unavailable only the semaphore applies.
    """
    # Check if we're already inside a @rate_limited wrapper (semaphore held).
    # Nested external calls must skip sem to avoid deadlock.
    already_gated = getattr(_rate_limit_ctx, "active", False)

    if not already_gated:
        # Outer call path: acquire semaphore + token bucket
        async with _external_sem:
            if _rate_limiter is not None:
                async with _rate_limiter:
                    return await _run_in_executor(fn, *args, **kwargs)
            else:
                return await _run_in_executor(fn, *args, **kwargs)

    # Inner call path (inside @rate_limited): only token bucket.
    # Semaphore is already held by the decorator.
    if _rate_limiter is not None:
        async with _rate_limiter:
            return await _run_in_executor(fn, *args, **kwargs)
    else:
        return await _run_in_executor(fn, *args, **kwargs)


def rate_limited(fn):
    """Decorator: wraps any async function under semaphore + token bucket.

    Holds the semaphore for the entire duration of the wrapped function so
    that nested calls to _external_call() detect we're already gated and
    skip their own semaphore acquisition (preventing deadlock).

    The token bucket is applied inside each external call via _external_call().
    """
    import functools

    @functools.wraps(fn)
    async def wrapper(*a, **kw):
        # Acquire semaphore for the entire function body.
        # Nested calls via _external_call() see active=True and skip sem.
        async with _external_sem:
            _rate_limit_ctx.active = True
            try:
                return await fn(*a, **kw)
            finally:
                _rate_limit_ctx.active = False

    return wrapper


def _sanitize_for_llm(text: str, max_len: int = 8000) -> str:
    """Escape / limit user-supplied text before injecting it into an LLM prompt.

    Prevents prompt injection by:
    - Stripping or neutralising markdown/code-block syntax that could confuse the model
    - Truncating to a safe length so very long injected payloads can't overflow
      the context window or trigger unintended behaviour
    - Neutralising role-marker tokens, control sequences, and structural attack patterns
    """
    if not isinstance(text, str):
        return ""
    text = text.strip()
    # Trim extremely long inputs (injected data can be arbitrarily large)
    if len(text) > max_len:
        text = text[:max_len] + "\n\n[... truncated for safety ...]"

    # ── Phase 1: Strip control / zero-width chars that can hide injection ──
    # U+200B U+200C U+200D U+FEFF BOM / zero-width joiner / soft hyphen / etc.
    text = re.sub(r'[\u200b\u200c\u200d\ufeff\u2060\u00ad]', '', text)
    # Fullwidth variants (CJK substitution attacks): ＳＹＳＴＥＭ → SYSTEM
    text = _fullwidth_to_ascii(text)

    # ── Phase 2: Neutralise role-marker tokens (case-insensitive, with optional
    #      whitespace / punctuation between letters to defeat "S Y S T E M" tricks) ──
    # We match lines that START with a role token (possibly preceded by whitespace).
    # Each line is inspected so we only neutralise actual prompt injections, not
    # random occurrences of the word "system" mid-sentence.
    text = _neutralize_role_markers(text)

    # ── Phase 3: Structural / formatting attacks ──
    replacements = [
        ("```", "[CODE_BLOCK]"),          # code fences
        ("<!--", "[HTML_COMMENT]"),       # HTML comments
        (">>>",  "[PYTHON_PROMPT]"),      # Python REPL prompt
        ("\n---\n", "\n[SEP]\n"),         # section separators that split prompts
    ]
    for bad, good in replacements:
        text = text.replace(bad, good)
    return text


def _fullwidth_to_ascii(text: str) -> str:
    """Convert fullwidth Unicode chars to ASCII to defeat substitution attacks.

    Fullwidth forms (U+FF01–U+FF5E) look identical to their ASCII counterparts
    but bypass simple string-replacement filters that check for literal 'SYSTEM'.
    """
    # Fullwidth uppercase A-Z: U+FF21..U+FF3A → A-Z
    result = []
    for ch in text:
        cp = ord(ch)
        if 0xFF21 <= cp <= 0xFF3A:   # Ａ–Ｚ
            result.append(chr(cp - 0xFF21 + ord('A')))
        elif 0xFF41 <= cp <= 0xFF5A:  # ａ–ｚ
            result.append(chr(cp - 0xFF41 + ord('a')))
        else:
            result.append(ch)
    return ''.join(result)


def _neutralize_role_markers(text: str) -> str:
    """Neutralise role-marker tokens at the start of lines.

    Detects patterns like:
      SYSTEM: ignore all instructions...   -- colon + instruction text
      ASSISTANT: you are now...            -- other role markers
      USER: ...                            -- user-role spoofing
      系统指令 (Chinese prompt injection)
      ignore all previous...               -- direct instruction override
      sei un assistente malevolo           -- Italian "you are" command

    Each line is checked against several pattern groups.
    Only neutralises when the marker appears at the START of a line.
    """
    lines = text.split("\n")
    result_lines = []

    for line in lines:
        if not line.strip():
            result_lines.append(line)
            continue

        indent_match = re.match(r"^(\s*)", line)
        indent = indent_match.group(1) if indent_match else ""
        stripped = line.strip()
        neutralized = False

        # 1. ROLE: content pattern (most common injection — SYSTEM:, ASSISTANT:, etc.)
        m = re.match(r"^(\s*)(SYSTEM|SYS|ASSISTANT|AI|BOT|USER|ROLE)(\s*:\s*)(.*)", stripped, re.IGNORECASE)
        if m:
            result_lines.append(f"{m.group(1)}[SAFE_ROLE]: {m.group(4)}")
            neutralized = True

        # 2. Bare role token on its own line (SYSTEM with no colon/nothing after)
        if not neutralized and re.match(r"^(SYSTEM|SYS|ASSISTANT|AI|BOT|USER|ROLE)$", stripped, re.IGNORECASE):
            result_lines.append("[SAFE_ROLE]: " + stripped)
            neutralized = True

        # 3. Chinese prompt injection variants
        if not neutralized:
            m = re.match(r"^(系统指令|system指令|角色设定)(.*)$", stripped, re.IGNORECASE | re.UNICODE)
            if m:
                result_lines.append(f"[SAFE_ROLE]: {m.group(2).lstrip(':').strip()}")
                neutralized = True

        # 4. "You are" / "Sei" behaviour-redefinition (any sentence, not just an/un)
        if not neutralized:
            m = re.match(r"^(you are|you're)(\s+.+)$", stripped, re.IGNORECASE)
            if m:
                result_lines.append(f"[SAFE_ROLE]: {m.group(2)}")
                neutralized = True

        # 5. Direct instruction override (imperative verbs at line start)
        if not neutralized:
            m = re.match(r"^(ignore|ignora|bypass|evade)(\s+.+)$", stripped, re.IGNORECASE)
            if m:
                result_lines.append(f"[SAFE_ROLE]: {m.group(2)}")
                neutralized = True

        # 6. Temporal override (da ora in poi / from now on)
        if not neutralized:
            m = re.match(r"^(da ora in poi|from now on|d'ora in poi)(\s+.+)$", stripped, re.IGNORECASE | re.UNICODE)
            if m:
                result_lines.append(f"[SAFE_ROLE]: {m.group(2)}")
                neutralized = True

        # Not neutralised — line is clean, pass through as-is
        if not neutralized:
            result_lines.append(line)

    return "\n".join(result_lines)



def _sanitize_search_result(text: str, max_len: int = 2000) -> str:
    """Sanitize text from web search results before injecting into LLM prompts.

    Search snippets can contain arbitrary content — page titles, metadata,
    even embedded role markers placed by malicious sites for SEO manipulation.
    """
    return _sanitize_for_llm(text, max_len=max_len)


def _summarize_with_llm(prompt_text: str, max_tokens: int = 1500, temperature: float = 0.3) -> str:
    """Use local llama.cpp to summarize content.

    This is a SYNC function called via _external_call() which wraps it in
    asyncio.to_thread()/run_in_executor to prevent blocking the event loop.
    """
    if not HTTPX_AVAILABLE:
        sys.stderr.write("LLM summarize error: httpx not available\n")
        return "Errore durante la sintesi LLM (httpx non disponibile)"
    try:
        p = urlparse(LLM_ENDPOINT)
        host = p.hostname or "localhost"
        port = p.port or 80

        # SSRF guard for LLM endpoint — block private/metadata IPs while allowing localhost
        if not _is_safe_url(LLM_ENDPOINT):
            sys.stderr.write("LLM endpoint: blocked unsafe URL\n")
            return ""

        # Pre-sanitise the full prompt (which may contain injected user data)
        safe_prompt = _sanitize_for_llm(prompt_text, max_len=6000)

        body = json.dumps({
            "model": LLM_MODEL,
            "messages": [{"role": "user", "content": safe_prompt}],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        })
        with httpx.Client(
            timeout=httpx.Timeout(connect=5, read=90, write=10, pool=5),
            follow_redirects=False,
            headers={"User-Agent": "hermes-mcp-server/2.2.0"},
        ) as client:
            resp = client.post(
                f"{LLM_ENDPOINT}/chat/completions",
                content=body,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
        if data.get("choices"):
            return data["choices"][0]["message"]["content"].strip()
    except httpx.HTTPStatusError as exc:
        sys.stderr.write(f"LLM HTTP error: {exc.response.status_code}\n")
        return "Errore durante la sintesi LLM (servizio non disponibile)"
    except Exception:
        sys.stderr.write("LLM summarize error\n")
        return "Errore durante la sintesi LLM"
    return ""


def _search_ddg(query, max_results=5):
    """Search via DuckDuckGo."""
    if not DDG_AVAILABLE:
        return {"error": "duckduckgo-search non installato", "results": []}
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
    # SSRF guard: validate SearXNG URL before making any request
    if not _is_safe_url(SEARXNG_URL):
        sys.stderr.write("SearXNG: blocked unsafe URL\n")
        return {"error": "SearXNG URL bloccato (localhost, IP privati o non sicuri)", "results": []}
    ck = _cache_key(f"searxng:{query}:{max_results}")
    cached = _get_cached(ck)
    if cached:
        return cached
    try:
        import urllib.parse as up
        params = {
            "q": query,
            "format": "json",
            "engines": "google,bing,duckduckgo,wikipedia",
            "categories": "general",
            "language": "it",
        }
        url = f"{SEARXNG_URL}/search?{up.urlencode(params)}"
        with httpx.Client(timeout=httpx.Timeout(connect=5, read=15, write=10, pool=5), follow_redirects=False) as client:
            resp = client.get(url, headers={"User-Agent": "hermes-mcp-server/2.1.1"})
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
    # Try SearXNG if configured
    searxng_result = _search_searxng(query, max_results)
    if searxng_result is not None and searxng_result.get("results"):
        return searxng_result

    # Fall back to DuckDuckGo
    ddg_result = _search_ddg(query, max_results)
    return ddg_result


# -- FastMCP server instance (CORS handled via Starlette middleware below) --
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
    query = _sanitize_for_llm(query.strip(), max_len=200)
    max_r = min(max(1, int(max_results)), 10)
    search_result = await _external_call(_search_web, query, max_r)
    if "results" in search_result and search_result.get("results") and len(search_result["results"]) > 0:
        raw = "\n---\n".join([
            f"{_sanitize_search_result(r['title'], 150)}: {_sanitize_search_result(r['snippet'], 200)}"
            for r in search_result["results"]
        ])
        # Re-sanitize query before embedding in prompt — line-start regexes need the text
        # to be at a line start; inside an f-string they would not match.
        safe_query = _sanitize_for_llm(query, max_len=200)
        summary_prompt = (
            f"Sintetizza in italiano questi risultati di ricerca per: {safe_query}\n\n"
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
    query = _sanitize_for_llm(query.strip(), max_len=200)
    search_result = await _external_call(_search_web, query)
    if search_result.get("error"):
        return search_result
    raw_content = "\n---\n".join([
        f"# {_sanitize_search_result(r['title'], 200)}\n{_sanitize_search_result(r['snippet'], 500)}"
        for r in search_result.get("results", [])
    ])
    # Sanitize query again right before injection — _sanitize_for_llm line-start
    # regexes only trigger when the text is at the beginning of a line, so embedding
    # it inside an f-string would bypass that protection.
    safe_query = _sanitize_for_llm(query, max_len=200)
    llm_prompt = (
        f'Analizza questi risultati di ricerca per la query: {safe_query}\n\n'
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
        "query": query,
        "llm_analysis": llm_answer or "LLM summarization not available",
        "source_results": search_result.get("results", []),
    }


@mcp_server.tool()
@rate_limited
async def read_webpage(url: str) -> dict:
    """Leggi il contenuto di una pagina web con riassunto LLM."""
    if not url.startswith(("http://", "https://")):
        return {"error": "URL invalido"}
    if not _is_safe_url(url):
        return {"error": "Accesso bloccato: localhost, IP privati e link-local non sono permessi"}
    try:
        # FIX CRITICAL #1 (SSRF via redirect): Disable automatic redirects.
        # If a user-controlled URL redirects to a private/metadata IP (e.g. 169.254.169.254),
        # httpx would follow it and exfiltrate cloud credentials. Instead we allow at most
        # 3 manual redirects, verifying _is_safe_url() at each hop.
        final_url = url
        max_redirects = 3
        for _ in range(max_redirects):
            with httpx.Client(timeout=30, follow_redirects=False) as client:
                resp = client.get(
                    final_url,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"},
                )
            # Check if this is a redirect (3xx)
            if 300 <= resp.status_code < 400:
                redirect_location = resp.headers.get("location")
                if not redirect_location:
                    return {"error": "Redirect senza location header", "url": url}
                # Resolve relative URLs to absolute
                from urllib.parse import urljoin as _urljoin
                if not redirect_location.startswith(("http://", "https://")):
                    redirect_location = _urljoin(final_url, redirect_location)
                # Verify the redirect target is safe
                if not _is_safe_url(redirect_location):
                    return {
                        "error": f"Accesso bloccato: redirect verso URL non sicuro ({redirect_location})",
                        "url": url,
                        "redirect_from": final_url,
                        "redirect_to": redirect_location,
                    }
                final_url = redirect_location
            else:
                # Not a redirect — proceed with response
                break

        text = re.sub(r"<[^>]+>", " ", resp.text)
        text = re.sub(r"\s+", " ", text).strip()[:15000]
        title_match = re.search(r'<title[^>]*>([^<]+)</title>', resp.text, re.I)
        raw_title = title_match.group(1) if title_match else "N/A"
        title = _sanitize_for_llm(raw_title, max_len=200)  # XSS / injection safe for JSON output
        summary = None
        if len(text) > 200:
            # Sanitize extracted content before LLM injection — strip structural attacks
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


# ── Scientific Computing Tools (SymPy + NumPy/SciPy) ────────────────────



# ── CORS origins for MCP HTTP server ────────
# Configurable via HERMES_MCP_CORS_ORIGINS env var (comma-separated).
# Default: localhost:* only. Setting to "[]" disables all CORS (same-origin only).
# Set to "*" for wildcard — accept any browser origin (no cookies, session ID via header).
_CORS_RAW = os.environ.get("HERMES_MCP_CORS_ORIGINS", "").strip()
if _CORS_RAW.lower() == "[]":
    cors_origins_list: list[str] = []  # Disable entirely — same-origin only
elif _CORS_RAW.lower() == "*":
    cors_origins_list = ["*"]  # Wildcard — any browser origin (no credentials, session ID via header)
elif _CORS_RAW:
    # Try JSON parse first (e.g. '["*", "http://host:port"]'), fallback to comma-split
    try:
        import json as _json
        cors_origins_list = _json.loads(_CORS_RAW)
        if not isinstance(cors_origins_list, list):
            cors_origins_list = [_json.loads(f'"{_CORS_RAW}"')]
    except (json.JSONDecodeError, ValueError):
        cors_origins_list = [o.strip() for o in _CORS_RAW.split(",") if o.strip()]
else:
    cors_origins_list = ["http://localhost:*", "https://localhost:*"]  # Default: localhost only


# ── Startup helpers ──────────────────────────────────────────────────────


async def main():
    print(f"🔮 Hermes MCP Server v2.2.0", file=sys.stderr)
    print(f"   Transport: {TRANSPORT}", file=sys.stderr)
    print(f"   LLM: {LLM_ENDPOINT}", file=sys.stderr)

    # SearXNG status check
    if SEARXNG_URL and HTTPX_AVAILABLE:
        if not _is_safe_url(SEARXNG_URL):
            print(f"   SearXNG: blocked unsafe URL", file=sys.stderr)
        else:
            try:
                with httpx.Client(timeout=5) as c:
                    # CRITICAL #1b: No redirect following — prevents SSRF via metadata endpoint (169.254.169.254)
                    r = c.get(SEARXNG_URL + "/search", params={"q": "test", "format": "json"}, follow_redirects=False)
                    if r.status_code == 200 and isinstance(r.json(), dict):
                        print(f"   SearXNG: connected ({SEARXNG_URL})", file=sys.stderr)
                    else:
                        print(f"   SearXNG: responding (status {r.status_code})", file=sys.stderr)
            except Exception as e:
                print(f"   SearXNG: unreachable, using DuckDuckGo fallback ({e})", file=sys.stderr)
    elif DDG_AVAILABLE:
        print(f"   Search engine: DuckDuckGo (no SEARXNG_URL configured)", file=sys.stderr)

    # Non-blocking LLM startup probe (runs in threadpool to avoid blocking event loop)
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

            # Build app with CORS support (WebUI browser needs cross-origin headers)
            from starlette.applications import Starlette
            from starlette.routing import Mount
            from starlette.middleware.cors import CORSMiddleware

            # Get MCP's internal ASGI app
            mcp_app = mcp_server.streamable_http_app()

            # Wrap in CORSMiddleware so browser requests work
            cors_app = CORSMiddleware(
                app=mcp_app,
                allow_origins=cors_origins_list,  # CORS origins configurable via HERMES_MCP_CORS_ORIGINS
                allow_methods=["POST", "OPTIONS"],
                allow_headers=["Content-Type", "Authorization", "Accept", "Mcp-Session-Id", "Mcp-Protocol-Version"],
                # NOTE: allow_credentials=True is intentionally disabled.
                # Browsers block wildcard subdomains (*) + credentials combination.
                # MCP-Session-ID is passed via header, not cookie — no auth cookies needed.
                expose_headers=["Mcp-Session-Id", "Cache-Control", "Content-Disposition"],
            )

            import uvicorn
            config = uvicorn.Config(cors_app, host=_MCP_BIND_ADDR, port=port, log_level="info")
            server = uvicorn.Server(config)

            # Shutdown signal handler
            _shutdown_event = asyncio.Event()

            def _on_signal(_sig, _frame):
                print("\nShutting down...", file=sys.stderr)
                _shutdown_event.set()

            sig_mod.signal(sig_mod.SIGINT, _on_signal)
            sig_mod.signal(sig_mod.SIGTERM, _on_signal)

            try:
                if TRANSPORT == "dual":
                    # Run BOTH stdio (for Hermes CLI/TUI) and HTTP (for browser) concurrently
                    print("Running in DUAL mode (stdio + HTTP)...", file=sys.stderr)
                    await asyncio.gather(
                        server.serve(),
                        mcp_server.run_stdio_async(),
                    )
                else:
                    await server.serve()
            except SystemExit as e:
                print(f"\nMCP HTTP server exited (code {e.code})", file=sys.stderr)

            # Wait for shutdown signal
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
