"""Knowledge base ingestion pipeline.

Reads Markdown files from the ``knowledge/`` directory, splits them into
chunks, embeds them with OpenAI, and stores them in ChromaDB.

Usage (from project root)::

    uv run python scripts/ingest_knowledge.py
"""

from __future__ import annotations

import logging
from pathlib import Path

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

from app.rag.vectorstore import create_vectorstore

logger = logging.getLogger(__name__)

KNOWLEDGE_DIR = Path(__file__).parent.parent.parent / "knowledge"

SPLITTER = RecursiveCharacterTextSplitter(
    chunk_size=800,
    chunk_overlap=100,
    separators=["\n## ", "\n### ", "\n\n", "\n", " "],
)


def _load_markdown_files(base_dir: Path) -> list[Document]:
    """Recursively load all ``.md`` files under *base_dir* as Documents."""
    docs: list[Document] = []
    md_files = sorted(base_dir.rglob("*.md"))
    if not md_files:
        raise FileNotFoundError(f"No Markdown files found under {base_dir}")

    for path in md_files:
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(base_dir)
        docs.append(
            Document(
                page_content=text,
                metadata={
                    "source": str(relative),
                    "category": relative.parts[0],  # owasp | cwe | cvss
                },
            )
        )
        logger.debug("Loaded %s (%d chars)", relative, len(text))

    logger.info("Loaded %d knowledge files.", len(docs))
    return docs


def run_ingestion(knowledge_dir: Path = KNOWLEDGE_DIR) -> int:
    """Run the full ingestion pipeline.

    Returns:
        Number of document chunks stored.
    """
    logger.info("Starting knowledge base ingestion from %s", knowledge_dir)
    raw_docs = _load_markdown_files(knowledge_dir)
    chunks = SPLITTER.split_documents(raw_docs)
    logger.info("Split into %d chunks.", len(chunks))
    create_vectorstore(chunks)
    logger.info("Ingestion complete: %d chunks stored.", len(chunks))
    return len(chunks)
