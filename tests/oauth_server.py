"""A fastmcp server behind its in-memory OAuth provider. The provider approves every sign-in."""
import sys
from fastmcp import FastMCP
from fastmcp.server.auth.providers.in_memory import InMemoryOAuthProvider
from mcp.server.auth.settings import ClientRegistrationOptions
port = int(sys.argv[1])
auth = InMemoryOAuthProvider(base_url=f"http://127.0.0.1:{port}", client_registration_options=ClientRegistrationOptions(enabled=True))
mcp = FastMCP("crm-behind-oauth", auth=auth)
@mcp.tool
def create_contact(email: str) -> str:
    """Create a contact."""
    return f"created {email}"
mcp.run(transport="http", host="127.0.0.1", port=port, show_banner=False)
