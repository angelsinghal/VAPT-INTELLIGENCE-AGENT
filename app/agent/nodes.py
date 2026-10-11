"""Dynamic tools and agent nodes for the ReAct architecture."""
import json
import logging
from typing import Any

from langchain_core.tools import tool
from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage

from app.config import get_settings
from app.models.vapt import VAPTResult
from app.rag.vectorstore import get_vectorstore
from app.tools.owasp import lookup_owasp
from app.tools.cwe import lookup_cwe
from app.tools.severity import assess_severity as calc_severity
from app.services.report import generate_markdown
from app.agent.state import VAPTState

logger = logging.getLogger(__name__)

@tool
def retrieve_knowledge(query: str) -> str:
    """Retrieve official mitigation steps, descriptions, and context from the OWASP knowledge base."""
    store = get_vectorstore()
    if not store:
        return "Knowledge base not available."
    retriever = store.as_retriever(search_kwargs={"k": 4})
    docs = retriever.invoke(query)
    if not docs:
        return "No relevant knowledge found in the database. Rely on your internal knowledge."
    context = [doc.page_content for doc in docs]
    return "\n\n---\n\n".join(context)

@tool
def lookup_security_metadata(vulnerability_name: str) -> dict[str, str]:
    """Look up the exact OWASP category and CWE ID for a given vulnerability."""
    owasp = lookup_owasp([vulnerability_name])
    cwe = lookup_cwe([vulnerability_name])
    return {"owasp": owasp or "Not determined", "cwe": cwe or "Not determined"}

@tool
def assess_severity(exploitability: str, authentication_required: str, confidentiality_impact: str, integrity_impact: str, availability_impact: str, user_interaction: str) -> dict[str, str]:
    """Calculate the deterministic severity of a finding based on 6 impact factors."""
    factors = {
        "exploitability": exploitability,
        "authentication_required": authentication_required,
        "confidentiality_impact": confidentiality_impact,
        "integrity_impact": integrity_impact,
        "availability_impact": availability_impact,
        "user_interaction": user_interaction,
    }
    result = calc_severity(factors)
    return {"severity": result["severity"], "reasoning": result["reason"]}

@tool(args_schema=VAPTResult)
def submit_final_report(**kwargs) -> str:
    """Call this tool ONLY when you have gathered all necessary information and are ready to submit the final structured VAPT result."""
    return "Report submitted."

TOOLS = [retrieve_knowledge, lookup_security_metadata, assess_severity, submit_final_report]

SYSTEM_PROMPT = """You are an autonomous VAPT Intelligence Agent.
Your job is to analyze the following vulnerability finding:
Title: {title}
URL: {url}
Parameter: {parameter}
Evidence: {evidence}
Description: {description}

You have access to tools to search a local knowledge base, look up CWE/OWASP metadata, and calculate severity.
If the user did not provide enough severity factors in the description, do your best to estimate them or just calculate it yourself based on the evidence.
Once you have gathered enough information, you MUST call the `submit_final_report` tool with the required JSON structure to finish your job.
"""

def agent_node(state: VAPTState) -> dict[str, Any]:
    """The core LLM node that decides which tools to call."""
    settings = get_settings()
    llm = ChatGroq(model=settings.groq_model, api_key=settings.groq_api_key, temperature=0.1)
    llm_with_tools = llm.bind_tools(TOOLS, tool_choice="any")
    
    messages = state.get("messages", [])
    if not messages:
        req = state["request"]
        sys_msg = SystemMessage(content=SYSTEM_PROMPT.format(
            title=req.title,
            url=req.url or "Not provided",
            parameter=req.parameter or "Not provided",
            evidence=req.evidence or "Not provided",
            description=req.description or "Not provided"
        ))
        messages = [sys_msg]
    
    response = llm_with_tools.invoke(messages)
    return {"messages": [response]}

def generate_report_node(state: VAPTState) -> dict[str, Any]:
    """Generates the markdown report from the final result."""
    result = state.get("result")
    if result:
        return {"report": generate_markdown(result)}
    return {}
