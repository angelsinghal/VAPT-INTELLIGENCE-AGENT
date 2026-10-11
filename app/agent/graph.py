"""LangGraph workflow definition for the dynamic ReAct architecture."""
import logging
from typing import Literal

from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode

from app.agent.state import VAPTState
from app.agent.nodes import agent_node, generate_report_node, TOOLS
from app.models.vapt import VAPTRequest, VAPTResult

logger = logging.getLogger(__name__)

def route_after_agent(state: VAPTState) -> Literal["tools", "parse_final_report", "__end__"]:
    """Route based on whether the agent called a tool or finished."""
    messages = state.get("messages", [])
    last_message = messages[-1]
    
    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        for call in last_message.tool_calls:
            if call["name"] == "submit_final_report":
                return "parse_final_report"
        return "tools"
    return "__end__"

def parse_final_report(state: VAPTState) -> dict:
    """Extracts the VAPTResult from the tool call and updates the state."""
    messages = state.get("messages", [])
    last_message = messages[-1]
    for call in last_message.tool_calls:
        if call["name"] == "submit_final_report":
            try:
                result = VAPTResult(**call["args"])
                return {"result": result}
            except Exception as e:
                logger.error("Validation error: %s", e)
                return {"errors": [f"Validation error: {e}"]}
    return {"errors": ["Failed to extract final report."]}

def build_graph() -> StateGraph:
    builder = StateGraph(VAPTState)
    
    executable_tools = [t for t in TOOLS if t.name != "submit_final_report"]
    
    builder.add_node("agent", agent_node)
    builder.add_node("tools", ToolNode(executable_tools))
    builder.add_node("parse_final_report", parse_final_report)
    builder.add_node("generate_report_node", generate_report_node)
    
    builder.set_entry_point("agent")
    
    builder.add_conditional_edges("agent", route_after_agent)
    builder.add_edge("tools", "agent")
    builder.add_edge("parse_final_report", "generate_report_node")
    builder.add_edge("generate_report_node", END)
    
    return builder.compile()

graph = build_graph()

async def run_analysis(request: VAPTRequest) -> VAPTState:
    """Execute the dynamic graph."""
    logger.debug("Starting dynamic agent for: %s", request.title)
    initial_state: VAPTState = {"request": request, "messages": [], "errors": []}
    
    try:
        final_state = await graph.ainvoke(initial_state)
        return final_state
    except Exception as exc:
        logger.exception("Graph execution failed.")
        initial_state["errors"] = [str(exc)]
        return initial_state
