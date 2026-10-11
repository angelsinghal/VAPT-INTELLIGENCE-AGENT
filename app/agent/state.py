"""LangGraph state definition for the VAPT Agentic workflow."""
from typing import Annotated, TypedDict
from langgraph.graph.message import add_messages
from langchain_core.messages import AnyMessage
from app.models.vapt import VAPTRequest, VAPTResult

class VAPTState(TypedDict, total=False):
    messages: Annotated[list[AnyMessage], add_messages]
    request: VAPTRequest
    result: VAPTResult | None
    report: str | None
    errors: list[str]
