import asyncio
from fastmcp import Client

async def test_all_mcp_features():
    client = Client("main.py")
    
    async with client:
        # Test basic connectivity
        await client.ping()
        print(" MCP server responding")
        
        # Test tools
        tools = await client.list_tools()
        print(f" Found {len(tools)} tools")
        
        # Test resources
        resources = await client.list_resources()
        print(f" Found {len(resources)} resources")
        for resource in resources:
            content = await client.read_resource(resource)
            print(f"  - {resource}: {len(content)} chars")
        
        # Test prompts
        prompts = await client.list_prompts()
        print(f" Found {len(prompts)} prompts")
        for prompt_name in prompts:
            prompt = await client.get_prompt(prompt_name)
            print(f"  - {prompt_name}: {len(prompt.content)} chars")
        
        # Test actual BloodHound tools
        try:
            domains = await client.call_tool("get_domains")
            print(" BloodHound connection working")
        except Exception as e:
            print(f" BloodHound issue: {e}")

if __name__ == "__main__":
    asyncio.run(test_all_mcp_features())