"""Draw the VulnTriage-AI architecture diagram with matplotlib.

Usage: uv run python docs/make_architecture.py [en|es] [output.png]
Default: English, docs/figures/architecture.png
"""

from __future__ import annotations

import sys
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

PALETTE = {
    "lab": "#E8EEF7", "l1": "#FDEBD3", "l2": "#DCEFE3", "l3": "#EADCF5",
    "intel": "#F2F2F2", "llm": "#FFF6CC", "out": "#E3F1F8", "edge": "#4A5568",
}

TEXT = {
    "en": {
        "title": "VulnTriage-AI architecture",
        "lab": "Isolated lab (Docker)\nInternal network, no internet\nDVWA, Juice Shop, Apache 2.4.49,\nTomcat 8.5.19, Drupal 8.5.0, Samba,\nJenkins 2.46.1, Elasticsearch 1.4.2",
        "scan": "Scanners\nNmap -sV (XML)\nNuclei CVE templates (JSONL)\nIPs anonymized",
        "l1": "Level 1: n8n workflow (24 nodes)\nWebhook > Parse > NVD / EPSS / KEV\n> Gemini summary + ATT&CK (Groq fallback)\n> IF critical (KEV or CVSS >= 9)",
        "l2": "Level 2: LangChain ReAct agent (LangGraph)\nChatPromptTemplate + 7 tools\nRAG: FAISS over OWASP WSTG, CWE, ATT&CK\nPydantic report + saved reasoning trace",
        "l3": "Level 3: fuzzy engine (scikit-fuzzy)\nCVSS, EPSS, exposure, criticality\n22 Mamdani rules, centroid\ntool prioritize_risk(), cites fired rules",
        "intel": "Threat intelligence (disk cache)\nNVD API 2.0, FIRST EPSS,\nCISA KEV, MITRE ATT&CK",
        "llm": "LLM providers (config switch)\nGemini 3.5 Flash (primary)\nGroq gpt-oss-20b, Ollama qwen2.5:14b (GPU)",
        "out": "Outputs\nTelegram alerts\nPostgres findings log\nMarkdown pentest report",
        "eval": "Evaluation: CVSS vs fuzzy vs fuzzy\nwithout EPSS, ground truth CISA KEV",
    },
    "es": {
        "title": "Arquitectura de VulnTriage-AI",
        "lab": "Laboratorio aislado (Docker)\nRed interna, sin internet\nDVWA, Juice Shop, Apache 2.4.49,\nTomcat 8.5.19, Drupal 8.5.0, Samba,\nJenkins 2.46.1, Elasticsearch 1.4.2",
        "scan": "Escáneres\nNmap -sV (XML)\nPlantillas CVE de Nuclei (JSONL)\nIPs anonimizadas",
        "l1": "Nivel 1: flujo n8n (24 nodos)\nWebhook > Parseo > NVD / EPSS / KEV\n> resumen Gemini + ATT&CK (respaldo Groq)\n> IF crítico (KEV o CVSS >= 9)",
        "l2": "Nivel 2: agente ReAct LangChain (LangGraph)\nChatPromptTemplate + 7 herramientas\nRAG: FAISS sobre OWASP WSTG, CWE, ATT&CK\nReporte Pydantic + traza de razonamiento",
        "l3": "Nivel 3: motor difuso (scikit-fuzzy)\nCVSS, EPSS, exposición, criticidad\n22 reglas Mamdani, centroide\nherramienta prioritize_risk(), cita reglas",
        "intel": "Inteligencia de amenazas (caché)\nNVD API 2.0, FIRST EPSS,\nCISA KEV, MITRE ATT&CK",
        "llm": "Proveedores LLM (configurable)\nGemini 3.5 Flash (principal)\nGroq gpt-oss-20b, Ollama qwen2.5:14b (GPU)",
        "out": "Salidas\nAlertas Telegram\nRegistro en Postgres\nReporte de pentest en Markdown",
        "eval": "Evaluación: CVSS vs difuso vs difuso\nsin EPSS, verdad base CISA KEV",
    },
}


def box(ax, x, y, w, h, text, color, bold_first=True, size=8.5):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08",
                                fc=color, ec="#5A6475", lw=1.1))
    lines = text.split("\n")
    ax.text(x + w / 2, y + h - 0.16, lines[0], ha="center", va="top", fontsize=size + 0.5,
            fontweight="bold" if bold_first else "normal", color="#1A202C")
    ax.text(x + w / 2, y + h - 0.45, "\n".join(lines[1:]), ha="center", va="top",
            fontsize=size, color="#2D3748", linespacing=1.35)


def arrow(ax, a, b, style="-|>", dashed=False):
    ax.add_patch(FancyArrowPatch(a, b, arrowstyle=style, mutation_scale=12, lw=1.2,
                                 color=PALETTE["edge"], linestyle="--" if dashed else "-",
                                 connectionstyle="arc3,rad=0"))


def draw(lang: str, out: Path) -> None:
    t = TEXT[lang]
    plt.rcParams["font.family"] = "DejaVu Sans"
    fig, ax = plt.subplots(figsize=(13, 7.2), dpi=160)
    ax.set_xlim(0, 13)
    ax.set_ylim(0, 7.2)
    ax.axis("off")
    ax.text(6.5, 7.0, t["title"], ha="center", va="top", fontsize=15, fontweight="bold")

    box(ax, 0.2, 3.95, 2.9, 2.0, t["lab"], PALETTE["lab"])
    box(ax, 0.2, 1.7, 2.9, 1.6, t["scan"], PALETTE["lab"])
    box(ax, 3.8, 4.75, 4.3, 1.55, t["l1"], PALETTE["l1"])
    box(ax, 3.8, 2.75, 4.3, 1.55, t["l2"], PALETTE["l2"])
    box(ax, 3.8, 0.55, 4.3, 1.55, t["l3"], PALETTE["l3"])
    box(ax, 8.9, 5.0, 3.9, 1.3, t["intel"], PALETTE["intel"])
    box(ax, 8.9, 3.25, 3.9, 1.3, t["llm"], PALETTE["llm"])
    box(ax, 8.9, 1.5, 3.9, 1.3, t["out"], PALETTE["out"])
    box(ax, 8.9, 0.25, 3.9, 0.95, t["eval"], PALETTE["l3"], size=8)

    arrow(ax, (1.65, 3.95), (1.65, 3.3))           # lab -> scanners
    arrow(ax, (3.1, 2.7), (3.8, 5.4))             # scans -> n8n
    arrow(ax, (3.1, 2.5), (3.8, 3.5))             # scans -> agent
    arrow(ax, (5.95, 2.1), (5.95, 2.75), style="<|-|>")  # fuzzy <-> agent tool
    arrow(ax, (8.1, 5.6), (8.9, 5.6), style="<|-|>")     # n8n <-> intel
    arrow(ax, (8.1, 3.7), (8.9, 5.1), style="<|-|>")     # agent <-> intel
    arrow(ax, (8.1, 5.1), (8.9, 4.0), style="<|-|>")     # n8n <-> llm
    arrow(ax, (8.1, 3.4), (8.9, 3.7), style="<|-|>")     # agent <-> llm
    arrow(ax, (8.1, 4.9), (8.9, 2.3))             # n8n -> outputs
    arrow(ax, (8.1, 3.0), (8.9, 2.0))             # agent -> outputs
    arrow(ax, (8.1, 1.0), (8.9, 0.75), dashed=True)  # fuzzy -> evaluation

    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out, bbox_inches="tight", facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    language = sys.argv[1] if len(sys.argv) > 1 else "en"
    target = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("docs/figures/architecture.png")
    draw(language, target)
    print(f"wrote {target}")
