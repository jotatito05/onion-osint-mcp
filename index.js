import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT_PATH = path.join(__dirname, "search_onion_web.py");

function resolvePythonExecutable() {
  if (process.env.PYTHON_EXE && fs.existsSync(process.env.PYTHON_EXE)) {
    return process.env.PYTHON_EXE;
  }

  const candidates = ["python3", "python"];
  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local");
    for (const ver of ["Python313", "Python312", "Python311", "Python310"]) {
      candidates.unshift(path.join(localAppData, "Programs", "Python", ver, "python.exe"));
    }
  }

  for (const bin of candidates) {
    try {
      execFileSync(bin, ["-c", "import requests, socks, bs4"], {
        stdio: "ignore",
        timeout: 4000,
        windowsHide: true,
      });
      return bin;
    } catch {
      // Siguiente candidato
    }
  }
  return process.platform === "win32" ? "python" : "python3";
}

const PYTHON_EXE = resolvePythonExecutable();

const server = new McpServer({
  name: "onion-osint",
  version: "1.1.0",
});

async function runPythonTool(args) {
  try {
    const { stdout } = await execFileAsync(PYTHON_EXE, [SCRIPT_PATH, ...args], {
      timeout: 90000,
      maxBuffer: 10 * 1024 * 1024,
      encoding: "utf8",
      env: { ...process.env, PYTHONIOENCODING: "utf-8", PYTHONUTF8: "1" },
      windowsHide: true,
    });
    const trimmed = stdout.trim();
    let isError = false;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && parsed.ok === false) {
        isError = true;
      }
    } catch {
      // Si la salida no es JSON válido, conservar texto
    }
    return {
      isError,
      content: [{ type: "text", text: trimmed }],
    };
  } catch (err) {
    return {
      isError: true,
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              ok: false,
              status: "connection_failed",
              error: String(err.message || err),
              stderr: err.stderr ? String(err.stderr) : undefined,
            },
            null,
            2
          ),
        },
      ],
    };
  }
}

server.tool(
  "search_onion_web",
  "Busca información pública, foros, documentación o menciones en servicios ocultos (.onion) de la red Tor a través de proxy SOCKS5h (Ahmia .onion + base de datos indexada local SQLite). Distingue en 'status' entre 'completed', 'local_only' y 'connection_failed'.",
  {
    query: z.string().describe("Término de búsqueda, actor de amenaza, CVE o IoC a consultar en la red Tor (.onion)"),
    max_results: z.number().int().min(1).max(50).optional().describe("Número máximo de resultados a devolver (por defecto 20)"),
    days: z.number().int().min(1).max(365).optional().describe("Filtro opcional de antigüedad máxima en días (ej. 7 o 30)"),
    local_only: z.boolean().optional().describe("Si es true, consulta únicamente la base de datos SQLite indexada local sin conectar a Tor"),
  },
  async ({ query, max_results, days, local_only }) => {
    const cliArgs = ["search", query, "--max-results", String(max_results || 20)];
    if (days) {
      cliArgs.push("--days", String(days));
    }
    if (local_only) {
      cliArgs.push("--local-only");
    }
    return runPythonTool(cliArgs);
  }
);

server.tool(
  "read_onion_page",
  "Realiza una lectura pasiva (HTTP GET) de una URL .onion a través del proxy SOCKS5h de Tor, eliminando scripts y formularios de credenciales por seguridad OSINT.",
  {
    url: z.string().describe("URL completa http://<v3_address>.onion/..."),
    max_chars: z.number().int().min(500).max(25000).optional().describe("Longitud máxima del texto extraído (por defecto 8000)"),
  },
  async ({ url, max_chars }) => {
    const cliArgs = ["read", url, "--max-chars", String(max_chars || 8000)];
    return runPythonTool(cliArgs);
  }
);

await server.connect(new StdioServerTransport());
