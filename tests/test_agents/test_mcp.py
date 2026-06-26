import pytest
import httpx
from unittest.mock import AsyncMock, patch
from backend.app.mcp.integration import MCPIntegrationClient

def test_mcp_client_registry_load():
    client = MCPIntegrationClient()
    
    # Check that servers are loaded correctly
    servers = client.get_servers()
    assert "local_filesystem" in servers
    assert "web_searcher" in servers
    
    # Check server detailed config
    fs_server = client.get_server("local_filesystem")
    assert fs_server["name"] == "Local Filesystem Utilities"
    assert fs_server["enabled"] is True

def test_mcp_client_tool_allowance():
    client = MCPIntegrationClient()
    
    # Whitelisted tools
    assert client.is_tool_allowed("local_filesystem", "list_dir") is True
    assert client.is_tool_allowed("local_filesystem", "view_file") is True
    
    # Blacklisted tool
    assert client.is_tool_allowed("local_filesystem", "write_to_file") is False
    
    # Non-existent tool
    assert client.is_tool_allowed("local_filesystem", "delete_file") is False
    
    # Tool on disabled or invalid server
    assert client.is_tool_allowed("invalid_server", "list_dir") is False

@pytest.mark.asyncio
async def test_mcp_client_health_check_success():
    client = MCPIntegrationClient()
    
    # Mock httpx AsyncClient get call to return 200
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = httpx.Response(200)
        status = await client.health_check("local_filesystem")
        assert status is True
        mock_get.assert_called_once_with("http://localhost:8001/health")

@pytest.mark.asyncio
async def test_mcp_client_health_check_failure():
    client = MCPIntegrationClient()
    
    # Mock httpx AsyncClient get call to raise Exception
    with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
        mock_get.side_effect = Exception("Connection refused")
        status = await client.health_check("local_filesystem")
        assert status is False

@pytest.mark.asyncio
async def test_mcp_client_execute_tool_success():
    client = MCPIntegrationClient()
    
    # Mock post call
    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = httpx.Response(
            200, 
            json={"success": True, "result": "mock output"},
            request=httpx.Request("POST", "http://localhost:8001/execute")
        )
        res = await client.execute_tool("local_filesystem", "list_dir", {"DirectoryPath": "/workspace"})
        assert res["success"] is True
        assert res["result"] == "mock output"

@pytest.mark.asyncio
async def test_mcp_client_execute_tool_unauthorized():
    client = MCPIntegrationClient()
    
    # Attempt to execute a blacklisted tool -> should raise PermissionError
    with pytest.raises(PermissionError) as exc_info:
        await client.execute_tool("local_filesystem", "write_to_file", {"FilePath": "/test.txt"})
    assert "not allowed" in str(exc_info.value)
