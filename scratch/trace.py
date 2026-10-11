import asyncio
from app.agent.graph import run_analysis
from app.models.vapt import VAPTRequest

async def main():
    req = VAPTRequest(title='SQL Injection in Login Page', evidence='test')
    state = await run_analysis(req)
    messages = state.get('messages', [])
    if messages:
        last_msg = messages[-1]
        print(f'Last message type: {last_msg.type}')
        print(f'Tool calls: {getattr(last_msg, "tool_calls", None)}')
        print(f'Content length: {len(last_msg.content)}')
        if not getattr(last_msg, "tool_calls", None):
            print(last_msg.content.encode("ascii", "ignore").decode())

asyncio.run(main())
