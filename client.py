import asyncio
from fastmcp import Client, FastMCP

client = Client("main.py")
async def main():
    async with client:
        await client.ping()
        tools = await client.list_tools()
        resources = await client.list_resources()
        prompts = await client.list_prompts()

    

asyncio.run(main())