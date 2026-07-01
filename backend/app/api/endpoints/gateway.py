import base64
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.app.api.dependencies import get_db
from backend.app.schemas.request import GatewayPromptRequest
from backend.app.schemas.response import GatewayResponse
from backend.app.agents.orchestrator import OrchestratorAgent

router = APIRouter()


@router.post(
    "/evaluate",
    response_model=GatewayResponse,
    status_code=status.HTTP_200_OK
)
def evaluate_prompt(
    request: GatewayPromptRequest,
    db: Session = Depends(get_db)
):
    """
    Evaluates a user prompt or uploaded document using the AgentShield-X
    multi-agent orchestration pipeline.
    """
    prompt_str = request.prompt or ""
    file_bytes_b64 = request.file_bytes_base64

    # Reject ONLY when both prompt and document are empty.
    if not prompt_str.strip() and not file_bytes_b64:
        from fastapi.responses import PlainTextResponse
        return PlainTextResponse("Please enter a prompt or upload a supported document.", status_code=422)

    file_bytes = None
    if file_bytes_b64:
        try:
            file_bytes = base64.b64decode(file_bytes_b64)
        except Exception:
            pass

    orchestrator = OrchestratorAgent()

    result = orchestrator.run_pipeline(
        prompt=prompt_str,
        session_id=request.session_id,
        db=db,
        file_bytes=file_bytes,
        file_name=request.file_name
    )

    return GatewayResponse(
        log_id=result["log_id"],
        session_id=result["session_id"],
        sanitized_prompt=result["sanitized_prompt"],
        overall_risk_score=result["overall_risk_score"],
        policy_action=result["policy_action"],
        message=result["message"],
        events_triggered=result["events_triggered"],
        all_detector_details=result.get("all_detector_details", [])
    )