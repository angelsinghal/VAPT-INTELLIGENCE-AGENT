"""ChromaDB vector store management.

The application starts successfully even if the knowledge base has not been
ingested.  Callers check ``is_ready()`` before attempting retrieval.
"""

from __future__ import annotations

import logging
from pathlib import Path

from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings

from app.config import get_settings

logger = logging.getLogger(__name__)

_COLLECTION_NAME = "vapt_knowledge"
_vectorstore: Chroma | None = None


def _get_embeddings() -> HuggingFaceEmbeddings:
    settings = get_settings()
    return HuggingFaceEmbeddings(model_name=settings.embedding_model)


def get_vectorstore(force_reload: bool = False) -> Chroma | None:
    """Return the Chroma vector store, or ``None`` if not initialised.

    The store is lazily loaded and cached in-process.  Pass
    ``force_reload=True`` to discard the cache (e.g. after ingestion).
    """
    global _vectorstore

    if _vectorstore is not None and not force_reload:
        return _vectorstore

    settings = get_settings()
    persist_dir = Path(settings.chroma_persist_directory)

    if not persist_dir.exists():
        logger.warning(
            "Chroma persist directory %s does not exist. "
            "Run scripts/ingest_knowledge.py to initialise the knowledge base.",
            persist_dir,
        )
        return None

    try:
        store = Chroma(
            collection_name=_COLLECTION_NAME,
            embedding_function=_get_embeddings(),
            persist_directory=str(persist_dir),
        )
        # Verify the collection actually contains documents
        count = store._collection.count()  # type: ignore[attr-defined]
        if count == 0:
            logger.warning(
                "Chroma collection '%s' exists but is empty. "
                "Run scripts/ingest_knowledge.py to populate it.",
                _COLLECTION_NAME,
            )
            return None
        logger.info("Chroma vector store loaded (%d documents).", count)
        _vectorstore = store
        return _vectorstore
    except Exception:
        logger.exception("Failed to load Chroma vector store.")
        return None


def is_ready() -> bool:
    """Return ``True`` if the vector store is loaded and non-empty."""
    return get_vectorstore() is not None


def create_vectorstore(documents: list) -> Chroma:
    """Create (or overwrite) the vector store from the supplied documents.

    Called exclusively by the ingestion script.
    """
    global _vectorstore
    settings = get_settings()
    persist_dir = Path(settings.chroma_persist_directory)
    persist_dir.mkdir(parents=True, exist_ok=True)

    store = Chroma.from_documents(
        documents=documents,
        embedding=_get_embeddings(),
        collection_name=_COLLECTION_NAME,
        persist_directory=str(persist_dir),
    )
    _vectorstore = store
    logger.info("Chroma vector store created with %d documents.", len(documents))
    return store
