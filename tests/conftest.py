"""
Pytest configuration for bloodhound_mcp tests.

Sets dummy environment variables before any test module is collected so that
main.py's module-level BloodhoundAPI() initialisation doesn't fail with a
missing-domain error.  The actual API client is mocked in every test that
calls a tool, so these values are never used in real requests.
"""

import os

os.environ.setdefault("BLOODHOUND_DOMAIN", "test.bloodhound.local")
os.environ.setdefault("BLOODHOUND_TOKEN_ID", "test-token-id")
os.environ.setdefault("BLOODHOUND_TOKEN_KEY", "test-token-key-32-chars-minimum!!")
