#!/usr/bin/env python3
"""Knowledge base ingestion script.

Run this once (and whenever the knowledge files change) to populate the
ChromaDB vector store used by the RAG pipeline:

    uv run python scripts/ingest_knowledge.py

The application server does NOT need to be running.
The server does NOT auto-ingest on startup — you must run this script first.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

# Ensure the project root is on sys.path when running as a standalone script
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import configure_logging, get_settings  # noqa: E402
from app.rag.ingest import run_ingestion  # noqa: E402


def main() -> None:
    configure_logging()
    logger = logging.getLogger(__name__)

    settings = get_settings()
    logger.info("Ingestion starting …")
    logger.info("  Embedding model        : %s", settings.embedding_model)
    logger.info("  Chroma directory       : %s", settings.chroma_persist_directory)

    try:
        count = run_ingestion()
        logger.info("✅  Ingestion complete — %d chunks stored.", count)
        print(
            f"\n✅  Knowledge base ready: {count} chunks stored in {settings.chroma_persist_directory}"
        )
    except FileNotFoundError as exc:
        logger.error("❌  Knowledge files not found: %s", exc)
        sys.exit(1)
    except Exception as exc:
        logger.exception("❌  Ingestion failed: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
