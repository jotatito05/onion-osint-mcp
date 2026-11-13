#!/usr/bin/env node
// Lanzador Node.js del servidor MCP.
//
// El servidor MCP real es `search_onion_web.py mcp` (Python puro, JSON-RPC sobre stdio). Este
// script solo localiza un intérprete de Python que tenga las dependencias instaladas y lo
// arranca conectándolo directamente a la entrada/salida del cliente MCP. Así las herramientas
// se definen en un único sitio y el proceso de Python vive toda la sesión, que es lo que
// permite mantener abierto el navegador entre llamadas (onion_browser_*).
import { spawn, execFileSync } from "node:child_process";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SCRIPT_PATH = path.join(__dirname, "search_onion_web.py");

function resolvePythonExecutable() {
  if (process.env.PYTHON_EXE && fs.existsSync(process.env.PYTHON_EXE)) {
    return process.env.PYTHON_EXE;
  }

  const candidates = ["python3", "python"];
  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local");
    for (const ver of ["Python310", "Python311", "Python312", "Python313", "Python314"]) {
      candidates.unshift(path.join(localAppData, "Programs", "Python", ver, "python.exe"));
    }
  }

  // Se elige el primer intérprete que realmente tenga las dependencias instaladas.
  for (const bin of candidates) {
    try {
      execFileSync(bin, ["-c", "import requests, socks, bs4"], {
        stdio: "ignore",
        timeout: 8000,
        windowsHide: true,
      });
      return bin;
    } catch {
      // Siguiente candidato
    }
  }
  return null;
}

const pythonExe = resolvePythonExecutable();
if (!pythonExe) {
  // stdout está reservado al protocolo MCP: los diagnósticos van siempre por stderr.
  console.error(
    "onion-osint-mcp: no se encontró un intérprete de Python con requests, PySocks y beautifulsoup4.\n" +
      "Instala las dependencias (pip install -r requirements.txt) o define PYTHON_EXE con la ruta del intérprete."
  );
  process.exit(1);
}

const child = spawn(pythonExe, [SCRIPT_PATH, "mcp"], {
  stdio: "inherit",
  env: { ...process.env, PYTHONIOENCODING: "utf-8", PYTHONUTF8: "1" },
  windowsHide: true,
});

child.on("error", (err) => {
  console.error(`onion-osint-mcp: no se pudo iniciar Python (${pythonExe}): ${err.message}`);
  process.exit(1);
});
child.on("exit", (code, signal) => {
  process.exit(signal ? 1 : code ?? 0);
});
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => child.kill(sig));
}
