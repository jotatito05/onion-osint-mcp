#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ejemplos de integración de `search_onion_web` con los principales frameworks de IA Agéntica:
  1. OpenAI SDK / Function Calling
  2. Anthropic Claude Tool Use
  3. LangChain / LangGraph
  4. CrewAI / SmolAgents / Uso directo
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from search_onion_web import (
    get_anthropic_tools,
    get_openai_tools,
    read_onion_page,
    search_onion_web,
)

SYSTEM_PROMPT = """Eres un Agente de Ciberinteligencia y OSINT especializado en la navegación, análisis y extracción de información de la red Tor (servicios ocultos .onion).
Tu objetivo es asistir en la búsqueda de información pública, foros, documentación o menciones dentro de los límites legales y éticos de la investigación de ciberseguridad defensiva y Threat Intelligence.
Sé preciso, técnico y directo. Destaca URLs .onion encontradas, resumen de hallazgos y evaluación de fiabilidad/frescura."""


# =====================================================================
# 1. Integración con OpenAI SDK (o clientes compatibles: Groq, Ollama, vLLM, DeepSeek)
# =====================================================================
def example_openai_agent(user_query: str) -> None:
    from openai import OpenAI

    client = OpenAI()
    tools = get_openai_tools()
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_query},
    ]

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        tools=tools,
        tool_choice="auto",
    )
    msg = response.choices[0].message

    if msg.tool_calls:
        messages.append(msg)
        for tc in msg.tool_calls:
            args = json.loads(tc.function.arguments)
            if tc.function.name == "search_onion_web":
                res = search_onion_web(**args)
            elif tc.function.name == "read_onion_page":
                res = read_onion_page(**args)
            else:
                res = {"error": "Unknown tool"}

            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(res, ensure_ascii=False),
                }
            )

        final = client.chat.completions.create(model="gpt-4o", messages=messages)
        print(final.choices[0].message.content)


# =====================================================================
# 2. Integración con LangChain / LangGraph
# =====================================================================
def get_langchain_tools():
    from langchain_core.tools import StructuredTool

    return [
        StructuredTool.from_function(
            func=search_onion_web,
            name="search_onion_web",
            description="Busca información en servicios ocultos (.onion) de la red Tor vía proxy SOCKS5h.",
        ),
        StructuredTool.from_function(
            func=read_onion_page,
            name="read_onion_page",
            description="Lectura pasiva (HTTP GET) de una página .onion eliminando scripts y formularios.",
        ),
    ]


if __name__ == "__main__":
    print("Esquemas OpenAI listos:", len(get_openai_tools()), "herramientas")
    print("Esquemas Anthropic listos:", len(get_anthropic_tools()), "herramientas")

