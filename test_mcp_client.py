import asyncio
from fastmcp import Client

async def test_all_mcp_features():
    client = Client("main.py")
    
    async with client:
        # Test basic connectivity
        await client.ping()
        print(" MCP server responding")

        # Tools
        tools = await client.list_tools()
        print("Total number of tools:", len(tools))

        # Resources
        resources = await client.list_resources()
        print("Total number of resources:", len(resources))

        # Prompts
        prompts = await client.list_prompts()
        print("Total number of prompts:", len(prompts))
        
        # tool test
        try:
            domains = await client.call_tool("get_domains")
            print("BloodHound Server Connection Working")
            print("Domains:", domains)
        except Exception as e:
            print(f"BloodHound Server Connection Failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_all_mcp_features())