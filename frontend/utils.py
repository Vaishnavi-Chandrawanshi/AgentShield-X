import os
import base64
import httpx
from typing import Optional, Dict, Any, List

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000")

def get_auth_token(username: str, password: str) -> Optional[str]:
    """Authenticates with the backend and returns the access token."""
    try:
        response = httpx.post(
            f"{BACKEND_URL}/api/v1/auth/token",
            data={"username": username, "password": password},
            timeout=10.0
        )
        if response.status_code == 200:
            return response.json().get("access_token")
    except Exception:
        pass
    return None

def register_user_api(username: str, email: str, password: str, org_name: str) -> Dict[str, Any]:
    """Sends registration request to backend."""
    payload = {
        "username": username,
        "email": email,
        "password": password,
        "org_name": org_name
    }
    try:
        response = httpx.post(
            f"{BACKEND_URL}/api/v1/auth/register",
            json=payload,
            timeout=10.0
        )
        if response.status_code == 201:
            return {"success": True, "data": response.json()}
        else:
            return {"success": False, "error": response.json().get("detail", "Registration failed.")}
    except Exception as e:
        return {"success": False, "error": str(e)}

def fetch_current_user(token: str) -> Optional[Dict[str, Any]]:
    """Retrieves current user details from profile endpoint."""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = httpx.get(
            f"{BACKEND_URL}/api/v1/auth/me",
            headers=headers,
            timeout=10.0
        )
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return None

def update_profile_api(token: str, email: Optional[str] = None, org_name: Optional[str] = None, new_password: Optional[str] = None) -> Dict[str, Any]:
    """Updates user profile on backend."""
    headers = {"Authorization": f"Bearer {token}"}
    payload = {}
    if email:
        payload["email"] = email
    if org_name:
        payload["org_name"] = org_name
    if new_password:
        payload["new_password"] = new_password
        
    try:
        response = httpx.put(
            f"{BACKEND_URL}/api/v1/auth/profile",
            json=payload,
            headers=headers,
            timeout=10.0
        )
        if response.status_code == 200:
            return {"success": True, "data": response.json()}
        else:
            return {"success": False, "error": response.json().get("detail", "Update failed.")}
    except Exception as e:
        return {"success": False, "error": str(e)}

def change_password_api(token: str, old_password: str, new_password: str) -> Dict[str, Any]:
    """Changes password after verifying old password."""
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "old_password": old_password,
        "new_password": new_password
    }
    try:
        response = httpx.post(
            f"{BACKEND_URL}/api/v1/auth/change-password",
            json=payload,
            headers=headers,
            timeout=10.0
        )
        if response.status_code == 200:
            return {"success": True}
        else:
            return {"success": False, "error": response.json().get("detail", "Password update failed.")}
    except Exception as e:
        return {"success": False, "error": str(e)}

def forgot_password_api(email: str) -> Dict[str, Any]:
    """Initiates password reset sequence."""
    payload = {"email": email}
    try:
        response = httpx.post(
            f"{BACKEND_URL}/api/v1/auth/forgot-password",
            json=payload,
            timeout=10.0
        )
        if response.status_code == 200:
            return {"success": True, "data": response.json()}
        else:
            return {"success": False, "error": response.json().get("detail", "Password reset request failed.")}
    except Exception as e:
        return {"success": False, "error": str(e)}

def reset_password_api(email: str, token: str, new_password: str) -> Dict[str, Any]:
    """Completes password override using reset token."""
    payload = {
        "email": email,
        "token": token,
        "new_password": new_password
    }
    try:
        response = httpx.post(
            f"{BACKEND_URL}/api/v1/auth/reset-password",
            json=payload,
            timeout=10.0
        )
        if response.status_code == 200:
            return {"success": True}
        else:
            return {"success": False, "error": response.json().get("detail", "Reset failed.")}
    except Exception as e:
        return {"success": False, "error": str(e)}

def evaluate_prompt_api(
    prompt: str,
    session_id: str,
    file_bytes: Optional[bytes] = None,
    file_name: Optional[str] = None
) -> Dict[str, Any]:
    """Submits a prompt and optional file to the evaluate gateway endpoint."""
    payload = {
        "session_id": session_id,
        "prompt": prompt
    }
    
    if file_bytes and file_name:
        payload["file_bytes_base64"] = base64.b64encode(file_bytes).decode("utf-8")
        payload["file_name"] = file_name

    try:
        response = httpx.post(
            f"{BACKEND_URL}/api/v1/gateway/evaluate",
            json=payload,
            timeout=30.0
        )
        if response.status_code == 200:
            return response.json()
        else:
            return {"error": f"Backend returned status {response.status_code}", "detail": response.text}
    except Exception as e:
        return {"error": "Connection to security gateway failed.", "detail": str(e)}

def fetch_pending_approvals(token: str) -> List[Dict[str, Any]]:
    """Fetches pending human approvals."""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = httpx.get(
            f"{BACKEND_URL}/api/v1/approval/pending",
            headers=headers,
            timeout=10.0
        )
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return []

def submit_approval_action(
    token: str,
    approval_id: str,
    status: str,
    reviewer_id: str,
    review_notes: str
) -> bool:
    """Submits approved/rejected decision for a ticket."""
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "status": status,
        "reviewer_id": reviewer_id,
        "review_notes": review_notes
    }
    try:
        response = httpx.post(
            f"{BACKEND_URL}/api/v1/approval/{approval_id}/action",
            json=payload,
            headers=headers,
            timeout=10.0
        )
        return response.status_code == 200
    except Exception:
        return False

def fetch_audit_logs(token: str, session_id: Optional[str] = None, policy_action: Optional[str] = None) -> List[Dict[str, Any]]:
    """Queries audit logs."""
    headers = {"Authorization": f"Bearer {token}"}
    params = {}
    if session_id:
        params["session_id"] = session_id
    if policy_action:
        params["policy_action"] = policy_action
        
    try:
        response = httpx.get(
            f"{BACKEND_URL}/api/v1/audit/logs",
            params=params,
            headers=headers,
            timeout=10.0
        )
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return []
