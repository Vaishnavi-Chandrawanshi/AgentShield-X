import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


class MCPIntegrationClient:
    """
    MCP Integration Client for AgentShield-X.
    Handles:
    - Registry loading
    - Tool permission checks
    - MCP server communication
    """

    def __init__(self, registry_path: Optional[str] = None):
        if registry_path:
            self.registry_path = Path(registry_path)
        else:
            self.registry_path = Path(__file__).parent / "registry.json"

        self.registry = self._load_registry()

    def _load_registry(self) -> Dict[str, Any]:
        """Load registry.json."""
        with open(self.registry_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_servers(self) -> Dict[str, Any]:
        return self.registry.get("mcp_servers", {})

    def get_server(self, server_name: str) -> Optional[Dict[str, Any]]:
        return self.get_servers().get(server_name)

    def is_tool_allowed(
        self,
        server_name: str,
        tool_name: str
    ) -> bool:
        server = self.get_server(server_name)

        if not server:
            return False

        if not server.get("enabled", False):
            return False

        if tool_name in server.get("blocked_tools", []):
            return False

        if tool_name not in server.get("allowed_tools", []):
            return False

        return True

    async def health_check(
        self,
        server_name: str
    ) -> bool:
        server = self.get_server(server_name)

        if not server:
            return False

        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(
                    f"{server['endpoint']}/health"
                )
                return response.status_code == 200

        except Exception as exc:
            logger.error(
                f"Health check failed for {server_name}: {exc}"
            )
            return False

    async def discover_tools(
        self,
        server_name: str
    ) -> List[str]:
        server = self.get_server(server_name)

        if not server:
            return []

        return server.get("allowed_tools", [])

    async def execute_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: Dict[str, Any]
    ) -> Dict[str, Any]:

        if not self.is_tool_allowed(
            server_name,
            tool_name
        ):
            raise PermissionError(
                f"Tool '{tool_name}' is not allowed "
                f"for MCP server '{server_name}'."
            )

        server = self.get_server(server_name)

        if not server:
            raise ValueError(
                f"Unknown MCP server '{server_name}'."
            )

        payload = {
            "tool": tool_name,
            "arguments": arguments
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{server['endpoint']}/execute",
                    json=payload
                )

                response.raise_for_status()

                return response.json()

        except Exception as exc:
            logger.exception("Tool execution failed")

            return {
                "success": False,
                "error": str(exc),
                "tool": tool_name,
                "server": server_name
            }