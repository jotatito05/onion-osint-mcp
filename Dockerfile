FROM python:3.12-slim

LABEL maintainer="JotaTito05"
LABEL description="Universal Tor (.onion) OSINT & CTI MCP Server for Agentic AI"

RUN apt-get update && apt-get install -y --no-install-recommends \
    tor \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY search_onion_web.py .
COPY SKILL.md .
COPY AGENTS.md .

# Por defecto inicia el servidor MCP sobre stdio (levanta Tor automáticamente en 9050)
ENTRYPOINT ["python", "search_onion_web.py"]
CMD ["mcp"]
