"""Build the FAISS knowledge index used by the search_knowledge tool.

Sources (all public):
  * OWASP Web Security Testing Guide (WSTG), markdown from the GitHub archive.
  * MITRE CWE catalog (cwec_latest.xml.zip), one document per weakness.
  * MITRE ATT&CK enterprise techniques (vulntriage.intel.attack_techniques()).

Embeddings: local fastembed (BAAI/bge-small-en-v1.5, 384 dims, ONNX on CPU).
Why not Gemini embeddings: the API does list gemini-embedding-001 and
gemini-embedding-2, but the free tier has a low requests-per-minute quota and
the corpus is several thousand chunks, so indexing would be slow and rate
limited. Local embeddings need no key, no quota and keep the index reproducible.

Usage: uv run python -m langchain_agent.rag_index [--rebuild]
"""

from __future__ import annotations

import argparse
import re
import tarfile
import time
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

import requests
from langchain_core.documents import Document
from langchain_core.embeddings import Embeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

from vulntriage.config import CACHE_DIR, ROOT
from vulntriage.intel import attack_techniques

INDEX_DIR = ROOT / "langchain_agent" / "index"
RAG_CACHE = CACHE_DIR / "rag"
EMBED_MODEL = "BAAI/bge-small-en-v1.5"
WSTG_URL = "https://github.com/OWASP/wstg/archive/refs/heads/master.tar.gz"
WSTG_PREFIX = "document/"  # testing categories are the 05-... to 1x-... folders
WSTG_WEB = "https://owasp.org/www-project-web-security-testing-guide/latest/"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
UA = {"User-Agent": "vulntriage-ai/0.1 (academic project)"}


class FastEmbedEmbeddings(Embeddings):
    """Minimal LangChain wrapper around fastembed (local, no network after download)."""

    def __init__(self, model: str = EMBED_MODEL) -> None:
        from fastembed import TextEmbedding

        self._model = TextEmbedding(model_name=model)

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [v.tolist() for v in self._model.embed(texts, batch_size=64)]

    def embed_query(self, text: str) -> list[float]:
        return next(iter(self._model.query_embed(text))).tolist()


def _download(url: str, name: str) -> Path:
    path = RAG_CACHE / name
    if not path.exists():
        RAG_CACHE.mkdir(parents=True, exist_ok=True)
        resp = requests.get(url, headers=UA, timeout=300)
        resp.raise_for_status()
        path.write_bytes(resp.content)
    return path


# ---------------------------------------------------------------- loaders


def load_wstg() -> list[Document]:
    path = _download(WSTG_URL, "wstg-master.tar.gz")
    docs = []
    with tarfile.open(path) as tar:
        for member in tar.getmembers():
            if not member.isfile() or not member.name.endswith(".md"):
                continue
            rel = member.name.split("/", 1)[-1]
            if not re.match(rf"{WSTG_PREFIX}(0[5-9]|1\d)-", rel):  # testing categories only
                continue
            text = tar.extractfile(member).read().decode("utf-8", "replace")
            heading = re.search(r"^#\s+(.+)$", text, re.M)
            title = heading.group(1) if heading else Path(rel).stem
            code = re.search(r"WSTG-[A-Z]+-\d+", text)
            if code:
                title = f"{code.group(0)} {title}"
            url = WSTG_WEB + rel.removeprefix(WSTG_PREFIX).removesuffix(".md")
            docs.append(Document(page_content=text, metadata={
                "source": "OWASP WSTG", "title": title, "url": url}))
    return docs


def _text(el: ET.Element | None) -> str:
    return " ".join("".join(el.itertext()).split()) if el is not None else ""


def load_cwe() -> list[Document]:
    path = _download(CWE_URL, "cwec_latest.xml.zip")
    with zipfile.ZipFile(path) as zf:
        xml_name = next(n for n in zf.namelist() if n.endswith(".xml"))
        root = ET.fromstring(zf.read(xml_name))
    ns = {"c": root.tag.split("}")[0].strip("{")}
    docs = []
    for w in root.findall(".//c:Weaknesses/c:Weakness", ns):
        if w.get("Status") in ("Deprecated",):
            continue
        cwe_id, name = f"CWE-{w.get('ID')}", w.get("Name")
        parts = [f"{cwe_id}: {name}", _text(w.find("c:Description", ns)),
                 _text(w.find("c:ExtendedDescription", ns))]
        mitigations = [_text(m.find("c:Description", ns))
                       for m in w.findall("c:Potential_Mitigations/c:Mitigation", ns)]
        if mitigations:
            parts.append("Mitigations: " + " | ".join(m for m in mitigations if m))
        docs.append(Document(page_content="\n".join(p for p in parts if p), metadata={
            "source": "MITRE CWE", "title": f"{cwe_id} {name}",
            "url": f"https://cwe.mitre.org/data/definitions/{w.get('ID')}.html"}))
    return docs


def load_attack() -> list[Document]:
    return [Document(
        page_content=f"{t['id']} {t['name']} (tactics: {', '.join(t['tactics'])}). "
                     f"{t['description']}",
        metadata={"source": "MITRE ATT&CK", "title": f"{t['id']} {t['name']}",
                  "url": t.get("url") or ""}) for t in attack_techniques()]


# ---------------------------------------------------------------- index


def build_index() -> dict:
    from langchain_community.vectorstores import FAISS

    start = time.time()
    sources = {"wstg": load_wstg(), "cwe": load_cwe(), "attack": load_attack()}
    splitter = RecursiveCharacterTextSplitter(chunk_size=1200, chunk_overlap=150)
    chunks = splitter.split_documents([d for ds in sources.values() for d in ds])
    for c in chunks:  # keep the title in every chunk so short sections stay retrievable
        if not c.page_content.startswith(c.metadata["title"][:20]):
            c.page_content = f"{c.metadata['title']}\n{c.page_content}"
    store = FAISS.from_documents(chunks, FastEmbedEmbeddings())
    INDEX_DIR.mkdir(parents=True, exist_ok=True)
    store.save_local(str(INDEX_DIR))
    stats = {"documents": {k: len(v) for k, v in sources.items()}, "chunks": len(chunks),
             "embedding_model": EMBED_MODEL, "seconds": round(time.time() - start, 1)}
    (INDEX_DIR / "stats.txt").write_text(str(stats))
    return stats


def load_index():
    """Load the saved FAISS index (build it first with this module)."""
    from langchain_community.vectorstores import FAISS

    if not (INDEX_DIR / "index.faiss").exists():
        raise FileNotFoundError(
            "RAG index missing: run `uv run python -m langchain_agent.rag_index`")
    return FAISS.load_local(str(INDEX_DIR), FastEmbedEmbeddings(),
                            allow_dangerous_deserialization=True)  # our own local file


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rebuild", action="store_true", help="rebuild even if an index exists")
    args = ap.parse_args()
    if (INDEX_DIR / "index.faiss").exists() and not args.rebuild:
        print("index exists; use --rebuild to rebuild")
    else:
        print(build_index())
