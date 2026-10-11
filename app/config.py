"""Application configuration loaded from environment variables."""

from __future__ import annotations

import logging
from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Central configuration object.  All values are loaded from the environment
    or from a ``.env`` file in the working directory."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Groq (LLM)
    groq_api_key: str
    groq_model: str = "llama-3.1-8b-instant"
    
    # HuggingFace (Local Embeddings)
    embedding_model: str = "all-MiniLM-L6-v2"

    # ChromaDB
    chroma_persist_directory: str = "./data/chroma"

    # Server
    port: int = 8000
    max_concurrent_analyses: int = 4
    disable_rate_limit: bool = False
    log_level: str = "INFO"
    request_timeout: int = 60

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        valid = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in valid:
            raise ValueError(f"log_level must be one of {valid}")
        return upper


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return a cached Settings singleton."""
    return Settings()


def configure_logging(settings: Settings | None = None) -> None:
    """Configure root logger with JSON-friendly format."""
    cfg = settings or get_settings()
    logging.basicConfig(
        level=getattr(logging, cfg.log_level),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
