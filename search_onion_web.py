#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
onion-osint-mcp: Universal Tor (.onion) OSINT & Threat Intelligence Tool for Agentic AI.

Compatible with:
  - MCP (Model Context Protocol): Claude Desktop, Claude Code, Cursor, Windsurf, Antigravity, OpenCode, Cline
  - Python Agent Frameworks: LangChain, LangGraph, CrewAI, AutoGen, LlamaIndex, SmolAgents, OpenAI SDK, Anthropic SDK
  - Standalone CLI for Bash/Terminal Agents (OpenHands, SWE-agent, Aider)

Core capabilities:
  - search_onion_web(query: str, max_results: int = 20, days: int | None = None, local_only: bool = False) -> dict
  - read_onion_page(url: str, max_chars: int = 8000) -> dict
  - check_tor_status() -> dict
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from typing import Any

import requests
from bs4 import BeautifulSoup

__version__ = "1.1.0"

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("ONION_INDEX_DB", str(BASE_DIR / "onion_index.db")))
TOR_DATA_DIR = Path(
    os.environ.get(
        "TOR_DATA_DIR",
        os.path.join(tempfile.gettempdir(), "tor-osint-agent-data"),
    )
)

AHMIA_ONION_BASE = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
AHMIA_CLEAR_BASE = "https://ahmia.fi"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0"
ONION_V3_REGEX = re.compile(r"\b([a-z2-7]{56}\.onion)\b", re.IGNORECASE)


# ============================================================================
# ESQUEMAS UNIVERSALES PARA FRAMEWORKS DE IA AGÉNTICA (OpenAI / Anthropic / MCP)
# ============================================================================

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "search_onion_web",
        "description": (
            "Busca información pública, foros, documentación, actores de amenaza o menciones "
            "en servicios ocultos (.onion) de la red Tor a través de un proxy SOCKS5h seguro "
            "(motores indexadores .onion como Ahmia + base de datos indexada local SQLite). "
            "Distingue explícitamente en 'status' entre búsqueda en vivo completada ('completed'), "
            "consulta solo al índice local ('local_only') y fallo de conexión ('connection_failed')."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Término de búsqueda, actor de amenaza, CVE, dominio o IoC a consultar en la red Tor (.onion).",
                },
                "max_results": {
                    "type": "integer",
                    "description": "Número máximo de resultados a devolver (1-50, por defecto 20).",
                    "default": 20,
                },
                "days": {
                    "type": "integer",
                    "description": "Filtro opcional de antigüedad máxima en días (ej. 7 o 30).",
                },
                "local_only": {
                    "type": "boolean",
                    "description": "Si es true, consulta únicamente la base de datos SQLite indexada local sin conectar a Tor.",
                    "default": False,
                },
            },
            "required": ["query"],
        },
    },
    {
        "name": "read_onion_page",
        "description": (
            "Realiza una lectura estrictamente pasiva (HTTP GET) de una URL .onion a través del proxy "
            "SOCKS5h de Tor. Elimina scripts, iframes y formularios de credenciales por seguridad OSINT."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL completa http://<direccion_v3>.onion/...",
                },
                "max_chars": {
                    "type": "integer",
                    "description": "Longitud máxima del texto extraído (por defecto 8000).",
                    "default": 8000,
                },
            },
            "required": ["url"],
        },
    },
]


def get_openai_tools() -> list[dict[str, Any]]:
    """Devuelve las definiciones de herramientas en formato OpenAI Function Calling / Agents SDK."""
    return [{"type": "function", "function": t} for t in TOOL_DEFINITIONS]


def get_anthropic_tools() -> list[dict[str, Any]]:
    """Devuelve las definiciones de herramientas en formato Anthropic Claude Tool Use."""
    return [
        {
            "name": t["name"],
            "description": t["description"],
            "input_schema": t["parameters"],
        }
        for t in TOOL_DEFINITIONS
    ]


# ============================================================================
# BASE DE DATOS INDEXADA LOCAL (SQLite)
# ============================================================================

def _init_db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS onion_records (
            onion_url TEXT PRIMARY KEY,
            onion_domain TEXT NOT NULL,
            title TEXT,
            snippet TEXT,
            last_seen TEXT,
            source_engine TEXT,
            last_query TEXT,
            indexed_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_onion_domain ON onion_records(onion_domain)"
    )
    conn.commit()
    return conn


def _save_to_local_index(results: list[dict[str, Any]], query: str) -> None:
    if not results:
        return
    conn = _init_db()
    now_iso = dt.datetime.now(dt.timezone.utc).isoformat()
    with conn:
        for r in results:
            conn.execute(
                """
                INSERT INTO onion_records (
                    onion_url, onion_domain, title, snippet, last_seen,
                    source_engine, last_query, indexed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(onion_url) DO UPDATE SET
                    title = COALESCE(excluded.title, onion_records.title),
                    snippet = COALESCE(excluded.snippet, onion_records.snippet),
                    last_seen = COALESCE(excluded.last_seen, onion_records.last_seen),
                    source_engine = excluded.source_engine,
                    last_query = excluded.last_query,
                    indexed_at = excluded.indexed_at
                """,
                (
                    r.get("onion_url"),
                    r.get("onion_domain", ""),
                    r.get("title", ""),
                    r.get("snippet", ""),
                    r.get("last_seen", ""),
                    r.get("source_engine", "local"),
                    query,
                    now_iso,
                ),
            )
    conn.close()


def _search_local_index(query: str, limit: int = 20) -> list[dict[str, Any]]:
    conn = _init_db()
    terms = [t.strip() for t in query.split() if t.strip()]
    if not terms:
        conn.close()
        return []

    clauses = []
    params: list[Any] = []
    for term in terms:
        clauses.append("(title LIKE ? OR snippet LIKE ? OR onion_url LIKE ? OR last_query LIKE ?)")
        like_val = f"%{term}%"
        params.extend([like_val, like_val, like_val, like_val])

    where_sql = " AND ".join(clauses)
    sql = f"""
        SELECT onion_url, onion_domain, title, snippet, last_seen, source_engine, indexed_at
        FROM onion_records
        WHERE {where_sql}
        ORDER BY indexed_at DESC
        LIMIT ?
    """
    params.append(limit)
    rows = conn.execute(sql, params).fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append(
            {
                "title": row["title"],
                "onion_url": row["onion_url"],
                "onion_domain": row["onion_domain"],
                "snippet": row["snippet"],
                "last_seen": row["last_seen"],
                "source_engine": f"local_db ({row['source_engine']})",
                "indexed_at": row["indexed_at"],
                "reliability": _assess_reliability(
                    row["title"], row["snippet"], row["last_seen"], row["onion_domain"]
                ),
            }
        )
    return results


# ============================================================================
# DESCUBRIMIENTO Y GESTIÓN MULTIPLATAFORMA DEL PROXY TOR (SOCKS5h)
# ============================================================================

def _is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _create_tor_session(proxy_url: str) -> requests.Session:
    """
    Crea una sesión HTTP estrictamente aislada del entorno:
      - `session.trust_env = False` impide que `requests` priorice variables de entorno
        (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`) o el proxy del sistema/registro
        de Windows por encima de `session.proxies`.
      - Fuerza `socks5h://` para tanto `http` como `https` evitando fugas DNS.
    """
    session = requests.Session()
    session.trust_env = False
    session.proxies = {"http": proxy_url, "https": proxy_url}
    session.headers.update({"User-Agent": USER_AGENT})
    return session


def _resolve_effective_proxy(session: requests.Session, test_url: str = AHMIA_ONION_BASE) -> str | None:
    """Devuelve el proxy efectivo que `requests` utilizará realmente para `test_url`."""
    merged = session.merge_environment_settings(test_url, {}, None, None, None)
    proxies = merged.get("proxies") or {}
    scheme = urllib.parse.urlparse(test_url).scheme or "http"
    return proxies.get(scheme) or proxies.get("all")


def find_tor_executable() -> Path | None:
    """
    Busca el binario de Tor de forma multiplataforma (Windows, Linux, macOS).
    Respeta la variable de entorno TOR_EXE_PATH si está definida.
    """
    env_path = os.environ.get("TOR_EXE_PATH")
    if env_path and Path(env_path).is_file():
        return Path(env_path)

    which_tor = shutil.which("tor") or shutil.which("tor.exe")
    if which_tor:
        return Path(which_tor)

    home = Path.home()
    candidates = [
        # Linux / macOS
        Path("/usr/bin/tor"),
        Path("/usr/sbin/tor"),
        Path("/usr/local/bin/tor"),
        Path("/opt/homebrew/bin/tor"),
        Path("/Applications/Tor Browser.app/Contents/MacOS/Tor/tor.real"),
        Path("/Applications/Tor Browser.app/Contents/MacOS/Tor/tor"),
        # Windows ubicaciones habituales de Tor Browser / Expert Bundle
        home / "Desktop" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        home / "Desktop" / "proyectos" / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Tor Browser" / "Browser" / "TorBrowser" / "Tor" / "tor.exe",
        Path(r"C:\Program Files\Tor Browser\Browser\TorBrowser\Tor\tor.exe"),
        Path(r"C:\Program Files (x86)\Tor Browser\Browser\TorBrowser\Tor\tor.exe"),
    ]
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


_TOR_PROC: subprocess.Popen | None = None


def ensure_tor_proxy(timeout_sec: int = 45) -> tuple[str, bool]:
    """
    Devuelve (proxy_url_socks5h, iniciado_por_nosotros).
    1. Si TOR_PROXY_URL está definido, lo utiliza directamente.
    2. Si hay un servicio escuchando en 127.0.0.1:9050 o 9150, lo reutiliza.
    3. Si no, busca el ejecutable `tor` y levanta una instancia temporal en 9050.
    """
    global _TOR_PROC

    custom_proxy = os.environ.get("TOR_PROXY_URL")
    if custom_proxy:
        return custom_proxy, False

    socks_host = os.environ.get("TOR_SOCKS_HOST", "127.0.0.1")
    custom_port = os.environ.get("TOR_SOCKS_PORT")
    ports_to_check = [int(custom_port)] if custom_port else [9050, 9150]

    for port in ports_to_check:
        if _is_port_open(socks_host, port):
            return f"socks5h://{socks_host}:{port}", False

    tor_exe = find_tor_executable()
    if not tor_exe:
        raise FileNotFoundError(
            "No se detectó proxy SOCKS5 activo en 127.0.0.1:9050/9150 ni el binario 'tor'. "
            "Instala Tor (apt install tor / brew install tor / Tor Browser) o define TOR_EXE_PATH / TOR_PROXY_URL."
        )

    TOR_DATA_DIR.mkdir(parents=True, exist_ok=True)
    creationflags = 0
    if sys.platform == "win32":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

    target_port = ports_to_check[0]
    _TOR_PROC = subprocess.Popen(
        [
            str(tor_exe),
            "--SocksPort",
            str(target_port),
            "--DataDirectory",
            str(TOR_DATA_DIR),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        creationflags=creationflags,
    )

    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        if _TOR_PROC.poll() is not None:
            break
        line = _TOR_PROC.stdout.readline() if _TOR_PROC.stdout else ""
        if "Bootstrapped 100%" in line:
            return f"socks5h://127.0.0.1:{target_port}", True
        if _is_port_open("127.0.0.1", target_port) and "Bootstrapped" in line and any(
            pct in line for pct in ("80%", "85%", "90%", "95%", "100%")
        ):
            time.sleep(1.0)
            return f"socks5h://127.0.0.1:{target_port}", True

    if _is_port_open("127.0.0.1", target_port):
        return f"socks5h://127.0.0.1:{target_port}", True

    raise RuntimeError(f"Timeout esperando bootstrap de Tor en 127.0.0.1:{target_port}")


def _cleanup_tor_if_spawned(spawned: bool) -> None:
    global _TOR_PROC
    if spawned and _TOR_PROC is not None:
        try:
            _TOR_PROC.terminate()
            _TOR_PROC.wait(timeout=3)
        except Exception:
            pass
        _TOR_PROC = None


def check_tor_status() -> dict[str, Any]:
    """Verifica conectividad con la red Tor usando sesión aislada (`trust_env=False`)."""
    spawned = False
    try:
        proxy_url, spawned = ensure_tor_proxy(timeout_sec=45)
        session = _create_tor_session(proxy_url)
        effective_proxy = _resolve_effective_proxy(session, "https://check.torproject.org/api/ip")
        resp = session.get("https://check.torproject.org/api/ip", timeout=20)
        resp.raise_for_status()
        data = resp.json()
        return {
            "ok": True,
            "status": "connected" if data.get("IsTor") else "not_tor",
            "proxy": effective_proxy,
            "is_tor": data.get("IsTor", False),
            "exit_ip": data.get("IP"),
            "tor_binary": str(find_tor_executable() or "external_daemon"),
        }
    except Exception as e:
        return {"ok": False, "status": "connection_failed", "error": str(e)}
    finally:
        _cleanup_tor_if_spawned(spawned)


# ============================================================================
# HEURÍSTICA DE FIABILIDAD Y MOTORES DE BÚSQUEDA .ONION
# ============================================================================

def _assess_reliability(
    title: str, snippet: str, last_seen: str, onion_domain: str
) -> dict[str, Any]:
    is_v3 = bool(ONION_V3_REGEX.search(onion_domain or ""))
    freshness = "desconocida"
    ls_lower = (last_seen or "").lower()
    if any(u in ls_lower for u in ("month", "mes", "year", "año")):
        freshness = "baja (antiguo)"
    elif any(u in ls_lower for u in ("day", "día", "week", "semana")):
        freshness = "media (reciente)"
    elif any(u in ls_lower for u in ("minute", "hour", "minuto", "hora", "just now")):
        freshness = "alta (<24h)"

    words = [w.lower() for w in re.findall(r"\w+", title or "") if len(w) > 3]
    spam_indicator = False
    if len(words) >= 6:
        most_common = max(words.count(w) for w in set(words))
        if most_common >= 4 or (most_common / len(words)) > 0.45:
            spam_indicator = True

    scam_keywords = ("hire a hacker", "buy ransomware", "double your bitcoin", "fixed matches")
    combined_lower = f"{title} {snippet}".lower()
    if any(k in combined_lower for k in scam_keywords):
        spam_indicator = True

    confidence = "media"
    note = "Servicio oculto v3 indexado."
    if spam_indicator:
        confidence = "baja (posible clon/keyword-stuffing/scam)"
        note = "Detectado patrón de repetición de palabras clave o gancho comercial típico de directorios clonados."
    elif freshness.startswith("alta") and is_v3:
        confidence = "alta (activo recientemente)"
        note = "Nodo v3 con actividad reciente verificada por el indexador."

    return {
        "v3_onion": is_v3,
        "freshness": freshness,
        "confidence": confidence,
        "SpamOrCloneSuspected": spam_indicator,
        "note": note,
    }


def _extract_html_Text(html: str, current_url: str, max_chars: int = 8000) -> dict[str, Any]:
    """
    Extrae texto visible y enlaces de un documento HTML eliminando scripts, iframes y formularios.
    Separado como función pura para facilitar pruebas sin red con HTML simulado.
    """
    soup = BeautifulSoup(html, "html.parser")
    forms_detected = len(soup.find_all("form"))
    password_inputs = len(soup.select("input[type=password]"))

    for tag in soup(["script", "style", "noscript", "iframe", "svg", "form"]):
        tag.decompose()

    title = soup.title.get_text(" ", strip=True) if soup.title else "Sin título"
    text_content = re.sub(r"\s+", " ", soup.get_text(" ", strip=True)).strip()

    links = []
    for a in soup.select("a[href]")[:40]:
        href = urllib.parse.urljoin(current_url, a["href"])
        lbl = a.get_text(" ", strip=True)[:80]
        if lbl or ".onion" in href:
            links.append({"text": lbl, "href": href})

    return {
        "title": title,
        "security_meta": {
            "passive_mode": True,
            "forms_stripped": forms_detected,
            "credential_prompt_detected": password_inputs > 0,
        },
        "text_excerpt": text_content[:max_chars],
        "links_sample": links[:25],
    }


def _query_ahmia(
    session: requests.Session,
    base_url: str,
    source_label: str,
    query: str,
    max_results: int = 20,
    days: int | None = None,
) -> list[dict[str, Any]]:
    home_resp = session.get(f"{base_url}/", timeout=22)
    home_resp.raise_for_status()
    soup_home = BeautifulSoup(home_resp.text, "html.parser")

    params: dict[str, Any] = {"q": query}
    for inp in soup_home.select("form#searchForm input[type=hidden]"):
        name = inp.get("name")
        val = inp.get("value")
        if name and val is not None:
            params[name] = val
    if days is not None and days > 0:
        params["d"] = str(days)

    search_resp = session.get(f"{base_url}/search/", params=params, timeout=28)
    search_resp.raise_for_status()
    soup = BeautifulSoup(search_resp.text, "html.parser")

    items = soup.select("li.result")
    parsed: list[dict[str, Any]] = []
    seen_urls: set[str] = set()

    for item in items:
        title_el = item.select_one("h4")
        cite_el = item.select_one("cite")
        desc_el = item.select_one("p")
        seen_el = item.select_one("span.lastSeen")
        a_el = item.select_one("a[href]")

        title = title_el.get_text(" ", strip=True) if title_el else "Sin título"
        cite = cite_el.get_text(strip=True) if cite_el else ""
        snippet = desc_el.get_text(" ", strip=True) if desc_el else ""
        last_seen = (
            seen_el.get_text(" ", strip=True).replace("\xa0", " ") if seen_el else "N/D"
        )

        onion_url = ""
        if a_el and a_el.get("href"):
            href = a_el["href"]
            parsed_href = urllib.parse.urlparse(href)
            qs = urllib.parse.parse_qs(parsed_href.query)
            if "redirect_url" in qs and qs["redirect_url"]:
                onion_url = qs["redirect_url"][0]
            elif ".onion" in href:
                onion_url = href

        if not onion_url and cite:
            onion_url = cite if cite.startswith("http") else f"http://{cite}"

        m = ONION_V3_REGEX.search(onion_url) or ONION_V3_REGEX.search(cite)
        onion_domain = m.group(1).lower() if m else cite.split("/")[0].lower()

        if not onion_url or onion_url in seen_urls:
            continue
        seen_urls.add(onion_url)

        parsed.append(
            {
                "title": title,
                "onion_url": onion_url,
                "onion_domain": onion_domain,
                "snippet": snippet,
                "last_seen": last_seen,
                "source_engine": source_label,
                "reliability": _assess_reliability(title, snippet, last_seen, onion_domain),
            }
        )
        if len(parsed) >= max_results:
            break

    return parsed


def _annotate_mirror_clusters(results: list[dict[str, Any]]) -> None:
    """Detecta y etiqueta clusters de dominios .onion espejo en un lote de resultados."""
    sig_counts: dict[str, int] = {}
    for r in results:
        parsed_u = urllib.parse.urlparse(r.get("onion_url", ""))
        sig = f"{(r.get('title') or '').strip().lower()}|{parsed_u.path}|{parsed_u.query}"
        r["_sig"] = sig
        sig_counts[sig] = sig_counts.get(sig, 0) + 1

    for r in results:
        sig = r.pop("_sig", "")
        mirrors = sig_counts.get(sig, 1)
        if mirrors > 1 and "reliability" in r and isinstance(r["reliability"], dict):
            r["reliability"]["mirror_count_in_batch"] = mirrors
            r["reliability"]["SpamOrCloneSuspected"] = True
            r["reliability"]["confidence"] = "baja (red de espejos/clones detectada)"
            r["reliability"]["note"] = (
                f"Detectados {mirrors} dominios .onion distintos sirviendo exactamente la misma ruta y título (cluster de espejos)."
            )


def search_onion_web(
    query: str,
    max_results: int = 20,
    days: int | None = None,
    local_only: bool = False,
) -> dict[str, Any]:
    """
    Busca términos, actores o IoCs en servicios ocultos (.onion) mediante proxy SOCKS5h de Tor
    y en la base de datos indexada local SQLite.

    Estados de retorno (`status`):
      - `"completed"` (`ok: True`, `live_tor_reached: True`):
          La consulta en vivo a través de Tor se completó correctamente (con N o 0 resultados).
      - `"local_only"` (`ok: True`, `live_tor_reached: False`):
          Consulta servida exclusivamente desde la base de datos local SQLite (`onion_index.db`),
          ya sea por `local_only=True` o como degradación controlada cuando Tor falló pero existen
          registros locales cacheados (`degraded: True`).
      - `"connection_failed"` (`ok: False`, `live_tor_reached: False`):
          Falló la conexión/búsqueda en vivo por Tor y no hay resultados locales de respaldo.
    """
    query = (query or "").strip()
    if not query:
        return {
            "ok": False,
            "status": "invalid_query",
            "live_tor_reached": False,
            "error": "El parámetro 'query' no puede estar vacío.",
        }

    started_at = time.time()
    errors: list[str] = []
    results: list[dict[str, Any]] = []
    used_engine = "none"
    effective_proxy: str | None = None
    live_tor_reached = False
    spawned = False

    if not local_only:
        try:
            proxy_url, spawned = ensure_tor_proxy(timeout_sec=45)
            session = _create_tor_session(proxy_url)
            effective_proxy = _resolve_effective_proxy(session, AHMIA_ONION_BASE)

            # 1. Intentar servicio oculto .onion v3 nativo de Ahmia
            try:
                results = _query_ahmia(
                    session,
                    AHMIA_ONION_BASE,
                    "ahmia_onion_v3",
                    query,
                    max_results=max_results,
                    days=days,
                )
                live_tor_reached = True
                used_engine = "ahmia_onion_v3 (SOCKS5h -> .onion)"
            except Exception as e_onion:
                errors.append(f"Ahmia .onion error: {e_onion}")

            # 2. Fallback a pasarela Ahmia saliendo por nodo Tor (solo si falló el intento 1 o dio 0)
            if not live_tor_reached or not results:
                try:
                    clear_results = _query_ahmia(
                        session,
                        AHMIA_CLEAR_BASE,
                        "ahmia_tor_exit",
                        query,
                        max_results=max_results,
                        days=days,
                    )
                    live_tor_reached = True
                    if not results:
                        results = clear_results
                        used_engine = "ahmia_tor_exit (SOCKS5h -> clearnet gateway)"
                except Exception as e_clear:
                    errors.append(f"Ahmia Tor exit error: {e_clear}")

        except Exception as e_tor:
            errors.append(f"Tor SOCKS5 proxy error: {e_tor}")
        finally:
            _cleanup_tor_if_spawned(spawned)

    # Persistir nuevos hallazgos en el índice local SQLite
    if results:
        try:
            _save_to_local_index(results, query)
        except Exception as e_db:
            errors.append(f"Advertencia al guardar en índice local: {e_db}")

    # Consultar índice local SQLite (como fuente exclusiva en local_only, o complemento/respaldo)
    local_matches: list[dict[str, Any]] = []
    try:
        local_matches = _search_local_index(query, limit=max_results)
    except Exception as e_local:
        errors.append(f"Error consultando índice local: {e_local}")

    existing_urls = {r["onion_url"] for r in results}
    for lm in local_matches:
        if lm["onion_url"] not in existing_urls and len(results) < max_results:
            results.append(lm)
            existing_urls.add(lm["onion_url"])

    _annotate_mirror_clusters(results)
    elapsed = round(time.time() - started_at, 2)
    unique_domains = sorted({r["onion_domain"] for r in results if r.get("onion_domain")})

    # Clasificación explícita de los 3 estados de respuesta
    if local_only:
        return {
            "ok": True,
            "status": "local_only",
            "degraded": False,
            "live_tor_reached": False,
            "query": query,
            "proxy": "none (local_only)",
            "engine_used": "local_sqlite_index",
            "elapsed_seconds": elapsed,
            "total_results": len(results),
            "unique_onion_domains": len(unique_domains),
            "results": results,
            "warnings": errors if errors else None,
        }

    if live_tor_reached:
        return {
            "ok": True,
            "status": "completed",
            "degraded": False,
            "live_tor_reached": True,
            "query": query,
            "proxy": effective_proxy,
            "engine_used": used_engine,
            "elapsed_seconds": elapsed,
            "total_results": len(results),
            "unique_onion_domains": len(unique_domains),
            "results": results,
            "warnings": errors if errors else None,
        }

    # Si Tor falló pero la base de datos local tenía resultados cacheados para esta consulta
    if results:
        return {
            "ok": True,
            "status": "local_only",
            "degraded": True,
            "live_tor_reached": False,
            "query": query,
            "proxy": effective_proxy or "unavailable",
            "engine_used": "local_sqlite_index (fallback)",
            "elapsed_seconds": elapsed,
            "total_results": len(results),
            "unique_onion_domains": len(unique_domains),
            "results": results,
            "error": "No se pudo conectar a los motores en vivo de Tor; se devuelven coincidencias del índice local.",
            "warnings": errors if errors else None,
        }

    # Fallo total de conexión a Tor y sin resultados en índice local: NO simular búsqueda vacía exitosa
    return {
        "ok": False,
        "status": "connection_failed",
        "degraded": True,
        "live_tor_reached": False,
        "query": query,
        "proxy": effective_proxy or "unavailable",
        "engine_used": "none",
        "elapsed_seconds": elapsed,
        "total_results": 0,
        "unique_onion_domains": 0,
        "results": [],
        "error": "Fallo al consultar la red Tor y no existen registros previos en el índice local.",
        "warnings": errors if errors else None,
    }


def read_onion_page(url: str, max_chars: int = 8000) -> dict[str, Any]:
    """
    Realiza una lectura pasiva (HTTP GET) de una URL .onion a través del proxy SOCKS5h de Tor.
    Elimina scripts, estilos y formularios por seguridad operativa (OSINT pasivo).
    """
    url = (url or "").strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or not parsed.hostname.endswith(".onion"):
        return {
            "ok": False,
            "status": "invalid_url",
            "error": "Por seguridad, read_onion_page solo acepta URLs http(s)://*.onion válidas.",
        }

    started_at = time.time()
    spawned = False
    effective_proxy: str | None = None
    try:
        proxy_url, spawned = ensure_tor_proxy(timeout_sec=45)
        session = _create_tor_session(proxy_url)
        effective_proxy = _resolve_effective_proxy(session, url)

        resp = session.get(url, timeout=35, allow_redirects=True)
        extracted = _extract_html_Text(resp.text, resp.url, max_chars=max_chars)

        return {
            "ok": True,
            "status": "completed",
            "proxy": effective_proxy,
            "requested_url": url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "title": extracted["title"],
            "elapsed_seconds": round(time.time() - started_at, 2),
            "security_meta": extracted["security_meta"],
            "text_excerpt": extracted["text_excerpt"],
            "links_sample": extracted["links_sample"],
        }
    except Exception as e:
        return {
            "ok": False,
            "status": "connection_failed",
            "proxy": effective_proxy or "unavailable",
            "requested_url": url,
            "elapsed_seconds": round(time.time() - started_at, 2),
            "error": str(e),
        }
    finally:
        _cleanup_tor_if_spawned(spawned)


# ============================================================================
# SERVIDOR MCP NATIVO EN PYTHON (JSON-RPC 2.0 sobre STDIO - Sin requerir Node.js)
# ============================================================================

def run_native_python_mcp_server() -> None:
    """
    Servidor MCP (Model Context Protocol) ligero en Python puro sobre stdio.
    """
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        msg_id = msg.get("id")
        method = msg.get("method", "")
        params = msg.get("params") or {}

        if method == "initialize":
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "onion-osint", "version": __version__},
                },
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        elif method == "notifications/initialized":
            continue

        elif method == "tools/list":
            mcp_tools = [
                {
                    "name": t["name"],
                    "description": t["description"],
                    "inputSchema": t["parameters"],
                }
                for t in TOOL_DEFINITIONS
            ]
            resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": mcp_tools}}
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        elif method == "tools/call":
            tool_name = params.get("name")
            args = params.get("arguments") or {}
            try:
                if tool_name == "search_onion_web":
                    data = search_onion_web(
                        query=str(args.get("query", "")),
                        max_results=int(args.get("max_results", 20)),
                        days=int(args["days"]) if args.get("days") is not None else None,
                        local_only=bool(args.get("local_only", False)),
                    )
                elif tool_name == "read_onion_page":
                    data = read_onion_page(
                        url=str(args.get("url", "")),
                        max_chars=int(args.get("max_chars", 8000)),
                    )
                else:
                    raise ValueError(f"Herramienta desconocida: {tool_name}")

                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(data, ensure_ascii=False, indent=2),
                            }
                        ],
                        "isError": not data.get("ok", True),
                    },
                }
            except Exception as err:
                resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {"ok": False, "status": "error", "error": str(err)},
                                    ensure_ascii=False,
                                ),
                            }
                        ],
                        "isError": True,
                    },
                }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()

        elif msg_id is not None:
            resp = {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            }
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Universal Tor (.onion) OSINT & CTI Tool for Agentic AI"
    )
    sub = parser.add_subparsers(dest="cmd")

    p_search = sub.add_parser("search", help="Buscar en indexadores .onion y base local")
    p_search.add_argument("query", help="Término de búsqueda o IoC")
    p_search.add_argument("--max-results", type=int, default=20)
    p_search.add_argument("--days", type=int, default=None)
    p_search.add_argument(
        "--local-only",
        action="store_true",
        help="Consultar únicamente la base de datos SQLite indexada local",
    )

    p_read = sub.add_parser("read", help="Lectura pasiva de una URL .onion")
    p_read.add_argument("url", help="URL http://<v3>.onion/...")
    p_read.add_argument("--max-chars", type=int, default=8000)

    sub.add_parser("status", help="Verificar conexión con proxy SOCKS5 de Tor")
    sub.add_parser("mcp", help="Iniciar servidor MCP (Model Context Protocol) sobre stdio")
    sub.add_parser("schemas", help="Exportar esquemas JSON para OpenAI / Anthropic / MCP")

    args = parser.parse_args()
    if args.cmd == "mcp":
        run_native_python_mcp_server()
        return

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    if args.cmd == "read":
        out = read_onion_page(args.url, max_chars=args.max_chars)
    elif args.cmd == "search":
        out = search_onion_web(
            args.query,
            max_results=args.max_results,
            days=args.days,
            local_only=args.local_only,
        )
    elif args.cmd == "status":
        out = check_tor_status()
    elif args.cmd == "schemas":
        out = {
            "openai_tools": get_openai_tools(),
            "anthropic_tools": get_anthropic_tools(),
        }
    else:
        parser.print_help()
        sys.exit(1)

    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
