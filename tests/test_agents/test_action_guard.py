import pytest
from backend.app.agents.agent_action_guard import AgentActionGuard, action_guard

def test_action_guard_blocked_tool():
    guard = AgentActionGuard()
    
    # Check blacklisted tool from registry.json
    is_allowed, reason = guard.validate_tool_call_local("write_to_file", {"FilePath": "/test.txt", "Content": "test"})
    assert is_allowed is False
    assert "not authorized" in reason or "explicitly blacklisted" in reason

def test_action_guard_allowed_tool():
    guard = AgentActionGuard()
    
    # Check allowed tool from registry.json
    is_allowed, reason = guard.validate_tool_call_local("list_dir", {"DirectoryPath": "/workspace"})
    assert is_allowed is True

def test_action_guard_destructive_keyword():
    guard = AgentActionGuard()
    
    # Check destructive keyword (rm) in arguments
    is_allowed, reason = guard.validate_tool_call_local("list_dir", {"DirectoryPath": "rm -rf /test"})
    assert is_allowed is False
    assert "Destructive command keyword" in reason

def test_action_guard_unauthorized_domain():
    guard = AgentActionGuard()
    
    # Check domain not in allowed list (allowed: api.github.com, huggingface.co, etc.)
    is_allowed, reason = guard.validate_tool_call_local("read_url_content", {"Url": "https://malicious-site.com/payload"})
    assert is_allowed is False
    assert "not on the firewall allowed domains list" in reason

def test_action_guard_authorized_domain():
    guard = AgentActionGuard()
    
    # Check domain in allowed list
    is_allowed, reason = guard.validate_tool_call_local("read_url_content", {"Url": "https://api.github.com/repos"})
    assert is_allowed is True

def test_action_guard_decorator_enforcement():
    guard = AgentActionGuard()
    
    # Decorate dummy tools
    @action_guard(guard)
    def list_dir(DirectoryPath: str):
        return "directory listing content"
        
    @action_guard(guard)
    def delete_file(FilePath: str):
        return "file deleted"

    # Call allowed tool -> should succeed
    assert list_dir(DirectoryPath="/workspace") == "directory listing content"

    # Call blacklisted tool -> should raise PermissionError
    with pytest.raises(PermissionError) as exc_info:
        delete_file(FilePath="/workspace/file.txt")
    assert "Action Guard" in str(exc_info.value)

    # Call allowed tool with destructive keyword in args -> should raise PermissionError
    with pytest.raises(PermissionError) as exc_info:
        list_dir(DirectoryPath="/workspace; rm -rf /")
    assert "Destructive command keyword" in str(exc_info.value)
