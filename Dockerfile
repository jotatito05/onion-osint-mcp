FROM python:3.12-slim

LABEL maintainer="JotaTito05"
LABEL description="Universal Tor (.onion) OSINT & CTI MCP Server for Agentic AI"

RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Usuario sin privilegios: ni Tor ni el lector de páginas necesitan root.
RUN useradd --create-home --uid 10001 osint \
    && mkdir -p /data \
    && chown osint:osint /data

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY search_onion_web.py SKILL.md AGENTS.md ./

# /data guarda el índice SQLite y el estado de Tor; móntalo como volumen para conservarlos
# entre ejecuciones (docker run -i --rm -v onion-osint-data:/data onion-osint-mcp).
ENV ONION_INDEX_DB=/data/onion_index.db \
    TOR_DATA_DIR=/data/tor \
    PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1

USER osint
VOLUME ["/data"]

# La imagen cubre búsqueda y lectura pasiva. El modo navegador (onion_browser_*) no se incluye:
# el traspaso al usuario necesita una ventana en su escritorio.
# Por defecto inicia el servidor MCP sobre stdio (levanta Tor automáticamente en 9050)
ENTRYPOINT ["python", "search_onion_web.py"]
CMD ["mcp"]
