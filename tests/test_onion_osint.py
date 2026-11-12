#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pruebas unitarias sin red para onion-osint-mcp:
  1. Prioridad del proxy Tor (`trust_env = False`) frente a HTTP_PROXY / HTTPS_PROXY / NO_PROXY del entorno.
  2. Distinción explícita entre los 3 estados de búsqueda:
     - 'completed' (búsqueda en vivo por Tor completada, con o sin resultados)
     - 'local_only' (consulta explícita o fallback degradado al índice SQLite local)
     - 'connection_failed' (fallo de red sin resultados locales: ok=False)
  3. Sanitización HTML en `read_onion_page` (eliminación de scripts/formularios y detección de contraseñas).
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import search_onion_web as oom


class TestOnionOsint(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.orig_db = oom.DB_PATH
        oom.DB_PATH = Path(self.tmp_dir.name) / "test_onion_index.db"

    def tearDown(self) -> None:
        oom.DB_PATH = self.orig_db
        self.tmp_dir.cleanup()

    def test_tor_proxy_overrides_environment_proxies(self) -> None:
        """Verifica que HTTP_PROXY/HTTPS_PROXY/NO_PROXY del entorno nunca pisen el proxy SOCKS5h de Tor."""
        env_overrides = {
            "HTTP_PROXY": "http://127.0.0.1:8888",
            "HTTPS_PROXY": "http://127.0.0.1:8888",
            "ALL_PROXY": "http://127.0.0.1:8888",
            "NO_PROXY": "*",
            "http_proxy": "http://127.0.0.1:8888",
            "https_proxy": "http://127.0.0.1:8888",
        }
        with patch.dict(os.environ, env_overrides, clear=False):
            session = oom._create_tor_session("socks5h://127.0.0.1:9050")
            self.assertFalse(session.trust_env)
            eff_onion = oom._resolve_effective_proxy(
                session, "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/"
            )
            eff_https = oom._resolve_effective_proxy(session, "https://ahmia.fi/search/?q=tor")
            self.assertEqual(eff_onion, "socks5h://127.0.0.1:9050")
            self.assertEqual(eff_https, "socks5h://127.0.0.1:9050")

    def test_connection_failure_returns_ok_false_and_connection_failed_status(self) -> None:
        """Un fallo de red sin resultados locales NO debe devolverse como ok=True con 0 resultados."""
        with patch.object(oom, "ensure_tor_proxy", return_value=("socks5h://127.0.0.1:9050", False)), \
             patch.object(oom, "_query_ahmia", side_effect=RuntimeError("SOCKS5 connection refused")):
            res = oom.search_onion_web("Tor Project")
            self.assertFalse(res["ok"])
            self.assertEqual(res["status"], "connection_failed")
            self.assertFalse(res["live_tor_reached"])
            self.assertTrue(res["degraded"])
            self.assertEqual(res["total_results"], 0)
            self.assertIn("error", res)
            self.assertTrue(len(res["warnings"]) >= 2)

    def test_local_only_and_degraded_fallback_states(self) -> None:
        """Distingue consulta local explícita (local_only) y fallback degradado cuando Tor cae."""
        sample_record = [
            {
                "title": "Tor Project Official Mirror",
                "onion_url": "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/",
                "onion_domain": "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion",
                "snippet": "Defend yourself against tracking and surveillance.",
                "last_seen": "2 hours",
                "source_engine": "ahmia_onion_v3",
            }
        ]
        oom._save_to_local_index(sample_record, "Tor Project")

        # 1. Modo explícito local_only=True
        res_explicit = oom.search_onion_web("Tor Project", local_only=True)
        self.assertTrue(res_explicit["ok"])
        self.assertEqual(res_explicit["status"], "local_only")
        self.assertFalse(res_explicit["degraded"])
        self.assertFalse(res_explicit["live_tor_reached"])
        self.assertEqual(res_explicit["total_results"], 1)

        # 2. Fallback degradado cuando Tor falla pero hay datos en el índice local
        with patch.object(oom, "ensure_tor_proxy", side_effect=RuntimeError("Tor daemon unreachable")):
            res_fallback = oom.search_onion_web("Tor Project", local_only=False)
            self.assertTrue(res_fallback["ok"])
            self.assertEqual(res_fallback["status"], "local_only")
            self.assertTrue(res_fallback["degraded"])
            self.assertFalse(res_fallback["live_tor_reached"])
            self.assertEqual(res_fallback["engine_used"], "local_sqlite_index (fallback)")
            self.assertEqual(res_fallback["total_results"], 1)
            self.assertIn("error", res_fallback)

    def test_live_tor_completed_state_even_with_zero_results(self) -> None:
        """Cuando Tor responde sin errores (incluso con 0 coincidencias), status debe ser 'completed'."""
        with patch.object(oom, "ensure_tor_proxy", return_value=("socks5h://127.0.0.1:9050", False)), \
             patch.object(oom, "_query_ahmia", return_value=[]):
            res = oom.search_onion_web("nonexistent_term_xyz_999")
            self.assertTrue(res["ok"])
            self.assertEqual(res["status"], "completed")
            self.assertFalse(res["degraded"])
            self.assertTrue(res["live_tor_reached"])
            self.assertEqual(res["proxy"], "socks5h://127.0.0.1:9050")
            self.assertEqual(res["total_results"], 0)

    def test_read_onion_page_html_sanitization_and_password_detection(self) -> None:
        """Verifica que el lector extrae texto, elimina scripts/formularios y detecta campos password."""
        simulated_html = """
        <html>
          <head>
            <title>DarkForum Portal</title>
            <script>alert('xss');</script>
            <style>body { color: red; }</style>
          </head>
          <body>
            <h1>Public Threat Intel Post</h1>
            <p>Observed indicator in sector 7.</p>
            <a href="/thread/42">Read Thread</a>
            <form action="/login" method="POST">
              <input type="text" name="user" />
              <input type="password" name="pass" />
            </form>
          </body>
        </html>
        """
        onion_url = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/index.html"
        parsed = oom._extract_html_Text(simulated_html, onion_url)
        self.assertEqual(parsed["title"], "DarkForum Portal")
        self.assertIn("Public Threat Intel Post", parsed["text_excerpt"])
        self.assertNotIn("alert", parsed["text_excerpt"])
        self.assertEqual(parsed["security_meta"]["forms_stripped"], 1)
        self.assertTrue(parsed["security_meta"]["credential_prompt_detected"])
        self.assertEqual(len(parsed["links_sample"]), 1)

    def test_utf8_html_without_http_charset_does_not_produce_mojibake(self) -> None:
        """
        Reproduce el fallo de RFC 2616 en requests donde 'Content-Type: text/html' sin charset
        fuerza ISO-8859-1 y convierte 'Español' en 'EspaÃ±ol'.
        """
        raw_utf8_html = (
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Tor Project | Privacidad</title></head>"
            "<body><p>Idiomas disponibles: Español, Français, Deutsch, Русский, 日本語</p>"
            "<a href=\"/es/\">Español</a></body></html>"
        ).encode("utf-8")

        onion_url = "http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/"
        parsed = oom._extract_html_Text(
            raw_utf8_html,
            onion_url,
            content_type_header="text/html",
        )
        self.assertEqual(parsed["encoding"], "utf-8")
        self.assertIn("Español", parsed["text_excerpt"])
        self.assertNotIn("EspaÃ±ol", parsed["text_excerpt"])
        self.assertEqual(parsed["links_sample"][0]["text"], "Español")

    def test_read_onion_page_reports_tls_error_and_timeout_separately(self) -> None:
        """
        Verifica que read_onion_page distingue un certificado autofirmado ('tls_error')
        y un timeout ('timeout') de un fallo general de conexión ('connection_failed').
        """
        import requests

        dread_url = "http://g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion/d/OpSec"

        mock_session_tls = MagicMock()
        mock_session_tls.merge_environment_settings.return_value = {
            "proxies": {"http": "socks5h://127.0.0.1:9050"}
        }
        mock_session_tls.get.side_effect = requests.exceptions.SSLError(
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate"
        )

        with patch.object(oom, "ensure_tor_proxy", return_value=("socks5h://127.0.0.1:9050", False)), \
             patch.object(oom, "_create_tor_session", return_value=mock_session_tls):
            res_tls = oom.read_onion_page(dread_url)
            self.assertFalse(res_tls["ok"])
            self.assertEqual(res_tls["status"], "tls_error")
            self.assertEqual(res_tls["error_type"], "ssl_certificate_error")
            self.assertIn("verify_tls=False", res_tls.get("hint", ""))

        mock_session_timeout = MagicMock()
        mock_session_timeout.merge_environment_settings.return_value = {
            "proxies": {"http": "socks5h://127.0.0.1:9050"}
        }
        mock_session_timeout.get.side_effect = requests.exceptions.ReadTimeout("Read timed out")

        with patch.object(oom, "ensure_tor_proxy", return_value=("socks5h://127.0.0.1:9050", False)), \
             patch.object(oom, "_create_tor_session", return_value=mock_session_timeout):
            res_to = oom.read_onion_page(dread_url)
            self.assertFalse(res_to["ok"])
            self.assertEqual(res_to["status"], "timeout")
            self.assertEqual(res_to["error_type"], "timeout")

    def test_read_onion_page_verify_tls_false_for_self_signed_https_onion(self) -> None:
        """Verifica que verify_tls=False pasa verify=False a requests y registra tls_verified=False."""
        dread_url = "https://g66ol3eb5ujdckzqqfmjsbpdjufmjd5nsgdipvxmsh7rckzlhywlzlqd.onion/d/OpSec"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.url = dread_url
        mock_resp.headers = {"Content-Type": "text/html"}
        mock_resp.content = b"<html><head><title>Dread /d/OpSec</title></head><body>OpSec Thread</body></html>"

        mock_session = MagicMock()
        mock_session.merge_environment_settings.return_value = {
            "proxies": {"https": "socks5h://127.0.0.1:9050"}
        }
        mock_session.get.return_value = mock_resp

        with patch.object(oom, "ensure_tor_proxy", return_value=("socks5h://127.0.0.1:9050", False)), \
             patch.object(oom, "_create_tor_session", return_value=mock_session):
            res = oom.read_onion_page(dread_url, verify_tls=False)
            self.assertTrue(res["ok"])
            self.assertEqual(res["status"], "completed")
            self.assertFalse(res["security_meta"]["tls_verified"])
            mock_session.get.assert_called_once_with(
                dread_url, timeout=35, allow_redirects=True, verify=False
            )


if __name__ == "__main__":
    unittest.main()

