"""RAG retriever interface."""

from __future__ import annotations

import logging

from langchain_core.vectorstores import VectorStoreRetriever

from app.rag.vectorstore import get_vectorstore

logger = logging.getLogger(__name__)

_DEFAULT_K = 4


def get_retriever(k: int = _DEFAULT_K) -> VectorStoreRetriever | None:
    """Return a similarity-search retriever backed by Chroma.

    Returns ``None`` when the knowledge base has not been ingested, allowing
    callers to degrade gracefully.
    """
    store = get_vectorstore()
    if store is None:
        return None
    return store.as_retriever(search_type="similarity", search_kwargs={"k": k})


def retrieve(query: str, k: int = _DEFAULT_K) -> list[str]:
    """Retrieve the top-k relevant passages for *query*.

    Returns an empty list when the knowledge base is unavailable so that the
    graph can continue with empty context rather than crashing.
    """
    retriever = get_retriever(k=k)
    if retriever is None:
        logger.warning("RAG retriever not available; returning empty context.")
        return []
    try:
        docs = retriever.invoke(query)
        return [d.page_content for d in docs]
    except Exception:
        logger.exception("RAG retrieval failed for query: %r", query)
        return []
