# Bloodhound Model Context Protocol Server
In an effort to learn about how MCPs function and their use case, I created an MCP to allow for Claude Desktop to work with the Data in Bloodhound Community edition

Video of its Usage

https://youtu.be/eZBT0Iw9CMA

## Requirements
1. uv
2. python3
3. Claude Desktop
4. A Bloodhoud CE instance running somewhere accessible (I ran it in my homelab)
5. Bloodhound dump files loaded into bloodhound (I used an initial dump from GOAD)

## Usage with Claude Desktop
Using the Developer Tools in Settings add the config in [claude.json](./claude.json)
Modify the path to where the bloodhound mcp is located
Save and restart claude desktop

Create a new converation and you should see a little hammer icon\
Start the conversation by asking about the domains


## Notes
This is in its early stages and I have learned a lot about MCPs and how cool they are. I would like to continue working on this, however the current implementation is very very basic. 

The bloodhound ce API is massive and I need to first implement all of the api calls into the [bloodhound_api.py](./lib/bloodhound_api.py). Then functionality to make the MCP use them needs to be added. 

*What it supports*
- questions about the general domain
    - Users
    - Groups
    - OUs
    - Controllers
    - GPOs
    - Computers

*What it does not support*
- Everything else


## Disclaimer
Since this a POC, i used data from Game Of Active Directory (shoutout to https://github.com/Orange-Cyberdefense/GOAD).

This is using Claude Desktop and therefore whatever data is being used is being sent to Anthropic, i highly recommend not using this on production Bloodhound dumps in its current state. There may be a way to get this to work with a Local LLM, however i am GPU poor and cannot run models on my local hosts.



