# Bloodhound Model Context Protocol Server
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

In an effort to learn about how MCPs function and their use case, I created an MCP to allow for Claude Desktop to work with the Data in Bloodhound Community edition

Video of its Usage

https://youtu.be/eZBT0Iw9CMA

## Requirements
1. uv
2. python3
3. Claude Desktop
4. A Bloodhoud CE instance running somewhere accessible (I ran it in my homelab)
5. Bloodhound dump files loaded into bloodhound (I used an initial dump from GOAD)
6. Bloodhound Key and ID for the authentication token

## Usage with Claude Desktop
Using the Developer Tools in Settings add the config in [claude.json](./claude.json)
Modify the path to where the bloodhound mcp is located
Save and restart claude desktop

Create a new converation and you should see a little hammer icon\
Start the conversation by asking about the domains


## Notes
This is in its early stages and I have learned a lot about MCPs and how cool they are. I would like to continue working on this, however the current implementation is very very basic.

UPDATE: I added fullish support for users in the domain, basically just look at the Bloodhound API documentation and it can answer any questions in the /domains and the /users api endpoints.

The bloodhound ce API is massive and I need to first implement all of the api calls into the [bloodhound_api.py](./lib/bloodhound_api.py). Then functionality to make the MCP use them needs to be added. 

*What it supports*
- questions about the general domain
- Questions about specific users
- Questions about Groups
- Questions about Computers
- Questions about Organizational Units
- Questions about Group Policy Objects

*What it does not support*
- Attack Paths
- Cypher Queries
- ADCS 
- Azure

## To do
- [x]  users
- [x] groups
- [x] computers
- [x] OU's
- [x] GPOs
- [x] Graph Search
- [x] ADCS
- [x] Cypher Queries 
    - [ ] some cypher queries work (fixed with MCPResources)
    - [ ] more complex queries fail to work
- [ ] attack paths - Only for enterprise
- [ ] Azure - Need Cypher for This
- [x] Refactor apis into classes to make code a little bit more presentable
- [ ] Refine the prompt engineering for the MCP Tools to improve the LLMs capability
- [ ] Let the LLM interact with BloodHound
    - [ ] Save in successful queries not already in there (Cypher API)
    - [ ] CRUD on Asset Lists (Asset Isolation API)
- [ ] figure out ways to support other LLMs (ollama, OpenAI, etc)
- [ ] Let the LLM act as a user within bloodhound
    - Would be added as a new user
    - would be able to manage the bloodhound server as if it was an admin
    - [ ] Authentication as an individual user
    - [ ] implement bloodhound management apis
        - [ ] upload data
        - [ ] download collectors
        - [ ] run collectors
            - would require a new mcp to run sharphound or bloodhound.py
- [ ] implementation with LLM or privately hosted LLMs



## Disclaimer
Since this a POC, i used data from Game Of Active Directory (shoutout to https://github.com/Orange-Cyberdefense/GOAD).

This is using Claude Desktop and therefore whatever data is being used is being sent to Anthropic, i highly recommend not using this on production Bloodhound dumps in its current state. There may be a way to get this to work with a Local LLM, however i am GPU poor and cannot run models on my local hosts.

## Credits
Orange Cyberdefense for making goad so i can test this
SpecterOps BloodHound for making BloodHound
@jlowin for creating and supporting FastMCP (https://github.com/jlowin/fastmcp)
@xpn for his mythic mcp that made me realize there was a better alternative than fastapi




