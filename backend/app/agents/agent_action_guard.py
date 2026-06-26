import os
import json
import functools
from urllib.parse import urlparse
from typing import Optional, Dict, Any, Tuple
from pydantic import BaseModel, Field
from backend.app.agents.base import BaseAgent

class ActionGuardVerdict(BaseModel):
    is_allowed: bool = Field(..., description="True if the tool call and arguments comply with security policies")
    explanation: str = Field(..., description="Details regarding policy validation or violation details")
    sanitized_arguments: Optional[Dict[str, Any]] = Field(None, description="Optional sanitized dictionary of arguments if arguments required modification")

class AgentActionGuard(BaseAgent):
    """
    Agent Action Guard Agent.
    Serves as an inline Policy Decision Point (PDP).
    Provides dual-layer validation for tool call invocations:
    1. Heuristic fast checks matching policies from registry.json.
    2. Intelligent semantic scans powered by Gemini 1.5 Pro.
    """
    def __init__(self):
        system_instruction = (
            "You are a tool execution policy evaluator. Your role is to examine a proposed tool call "
            "and its arguments against a set of organizational security policies. "
            "You will be given the tool name, arguments, and a JSON policy block. "
            "Determine if the tool call is safe or violates any policies (e.g. destructive commands, "
            "unauthorized domains, scope leakage). "
            "Return a structured JSON response indicating if the action is allowed, the reasoning, "
            "and optional sanitized arguments if parameter clean-ups can satisfy the policy."
        )
        # Routed to Gemini 1.5 Pro for complex policy auditing
        super().__init__(system_instruction=system_instruction, model_name="gemini-1.5-pro")
        self.registry_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
            "mcp", 
            "registry.json"
        )
        self.policies = self._load_policies()

    def _load_policies(self) -> dict:
        """Loads security policies from registry.json."""
        try:
            if os.path.exists(self.registry_path):
                with open(self.registry_path, "r") as f:
                    return json.load(f)
        except Exception:
            pass
        # Fallback basic default policies
        return {
            "mcp_servers": {},
            "network_policies": {"allowed_domains": [], "block_unknown_domains": True},
            "execution_policies": {
                "block_destructive_operations": True,
                "destructive_operation_keywords": ["rm", "rf", "drop", "delete"]
            }
        }

    def validate_tool_call_local(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Fast heuristic scan against registry policies. Returns (is_allowed, explanation).
        """
        # 1. Check MCP server tool permissions
        mcp_servers = self.policies.get("mcp_servers", {})
        found_in_mcp = False
        allowed_by_mcp = False
        
        for server_name, config in mcp_servers.items():
            # Check if this tool belongs to this server configuration
            all_tools = config.get("allowed_tools", []) + config.get("blocked_tools", [])
            if tool_name in all_tools:
                found_in_mcp = True
                if tool_name in config.get("blocked_tools", []):
                    return False, f"Tool '{tool_name}' is explicitly blacklisted on server '{server_name}'."
                if tool_name in config.get("allowed_tools", []):
                    allowed_by_mcp = True
        
        if found_in_mcp and not allowed_by_mcp:
            return False, f"Tool '{tool_name}' is not authorized under the active MCP policies."

        # 2. Check Execution Policies (destructive operation keywords)
        exec_policies = self.policies.get("execution_policies", {})
        if exec_policies.get("block_destructive_operations", True):
            keywords = exec_policies.get("destructive_operation_keywords", [])
            # Search arguments recursively for keywords
            args_str = json.dumps(arguments).lower()
            for kw in keywords:
                # Add word boundary protection or standard matching
                if kw in args_str:
                    return False, f"Destructive command keyword '{kw}' detected in execution arguments."

        # 3. Check Network Policies (unauthorized domains check)
        net_policies = self.policies.get("network_policies", {})
        if net_policies.get("block_unknown_domains", True):
            allowed_domains = net_policies.get("allowed_domains", [])
            # Extract target url or domain from arguments
            url_args = []
            for k, v in arguments.items():
                if isinstance(v, str) and (v.startswith("http://") or v.startswith("https://") or "." in v):
                    url_args.append(v)
            
            for url in url_args:
                try:
                    # Clean url format for parsing
                    parsed = urlparse(url if "://" in url else f"http://{url}")
                    domain = parsed.netloc or parsed.path
                    domain = domain.split(":")[0] # Remove port if present
                    
                    if domain and allowed_domains:
                        # Check domain matching
                        matched = any(domain == d or domain.endswith(f".{d}") for d in allowed_domains)
                        if not matched:
                            return False, f"Network domain '{domain}' is not on the firewall allowed domains list."
                except Exception:
                    pass

        return True, "Tool call matches active heuristic policy constraints."

    def validate_tool_call_llm(self, tool_name: str, arguments: Dict[str, Any]) -> ActionGuardVerdict:
        """
        Runs semantic audit of tool call parameters using Gemini 1.5 Pro.
        """
        prompt = f"""
Tool Name: {tool_name}
Proposed Arguments: {json.dumps(arguments, indent=2)}
Security Policies: {json.dumps(self.policies, indent=2)}
        """
        return self._generate_structured(
            prompt=prompt,
            schema_cls=ActionGuardVerdict,
            mock_fallback_handler=lambda p: self._mock_action_guard(tool_name, arguments)
        )

    def _mock_action_guard(self, tool_name: str, arguments: Dict[str, Any]) -> ActionGuardVerdict:
        """Fallback mock verdict evaluator for keyless test executions."""
        is_allowed, explanation = self.validate_tool_call_local(tool_name, arguments)
        return ActionGuardVerdict(
            is_allowed=is_allowed,
            explanation=f"Evaluated via local mock handler. {explanation}"
        )

def action_guard(agent_guard_instance: AgentActionGuard):
    """
    Decorator to wrap local tool execution methods.
    Intercepts execution, runs policy checks, and raises PermissionError on violation.
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Resolve tool name from function metadata
            tool_name = func.__name__
            # Extract arguments
            arguments = kwargs.copy()
            # If there are positional arguments, map them to dummy parameter index for auditing
            if len(args) > 0:
                for idx, val in enumerate(args):
                    arguments[f"param_{idx}"] = val
                    
            # 1. Run fast local check
            is_allowed, explanation = agent_guard_instance.validate_tool_call_local(tool_name, arguments)
            if not is_allowed:
                raise PermissionError(f"Action Guard Blocked Execution: {explanation}")
                
            # 2. Run LLM check (non-blocking for testing, or matching verdict)
            verdict = agent_guard_instance.validate_tool_call_llm(tool_name, arguments)
            if not verdict.is_allowed:
                raise PermissionError(f"Action Guard Semantic Block: {verdict.explanation}")
                
            # Apply sanitized arguments if provided
            if verdict.sanitized_arguments:
                for k, v in verdict.sanitized_arguments.items():
                    if k in kwargs:
                        kwargs[k] = v

            return func(*args, **kwargs)
        return wrapper
    return decorator
