# AgentShield-X: Phased Implementation Roadmap
*Kaggle AI Agents Capstone Project*

This document defines the structured, sequential plan to implement AgentShield-X. The architecture has been reviewed and frozen: no new agents, features, databases, or workflow modifications will be introduced. The focus is strictly on building the system according to the specifications in the finalized [architecture_design.md](file:///C:/Users/vaish/.gemini/antigravity-cli/brain/74bebb46-1ccc-4989-9b6d-ca38711798e4/architecture_design.md).

---

## Phase 1: Project Setup and Dependencies
* **Objective**: Configure Python local environment structures, solidify constraints in requirements files, and verify folder paths.
* **Files to Create**: None (folder structure and files are already initialized).
* **Files to Modify**: 
  - [requirements.txt](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/requirements.txt) (Lock version pins)
  - [README.md](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/README.md) (Verify setup commands)
* **Dependencies Required**: `python==3.10+`, `pip`, standard library tools.
* **Estimated Implementation Time**: 1 Hour

---

## Phase 2: Database Layer
* **Objective**: Set up PostgreSQL core database drivers, design SQL tables (audits, events, human reviews, known vectors), enable `pgvector` index engines, and write migration scripts.
* **Files to Create**: None (using existing placeholders):
  - [backend/app/core/database.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/core/database.py) (DB engine configuration)
  - [backend/app/models/audit.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/models/audit.py) (Audit log & event schemas)
  - [backend/app/models/approval.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/models/approval.py) (Human approval schemas)
* **Files to Modify**: 
  - `backend/app/models/__init__.py` (SQLAlchemy registry import hooks)
* **Dependencies Required**: `sqlalchemy>=2.0.0`, `psycopg2-binary>=2.9.9`, `pgvector>=0.2.5`, `alembic>=1.13.1`
* **Estimated Implementation Time**: 4 Hours

---

## Phase 3: FastAPI Backend Services
* **Objective**: Implement FastAPI server initialization, global security and JWT handling, dependencies, request/response validation schemas, and client endpoints.
* **Files to Create**: None (using existing placeholders):
  - [backend/app/main.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/main.py) (FastAPI app configuration)
  - [backend/app/core/config.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/core/config.py) (Pydantic Settings loader)
  - [backend/app/core/security.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/core/security.py) (AES-GCM encryption & JWT utils)
  - `backend/app/api/dependencies.py` (Database session injection)
  - [backend/app/api/endpoints/gateway.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/api/endpoints/gateway.py) (Primary proxy gateway)
  - [backend/app/api/endpoints/approval.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/api/endpoints/approval.py) (Review queue admin routes)
  - [backend/app/api/endpoints/audit.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/api/endpoints/audit.py) (Historical query searches)
  - [backend/app/schemas/request.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/schemas/request.py) (Pydantic validation schemas)
  - [backend/app/schemas/response.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/schemas/response.py) (Clean response models)
* **Files to Modify**: 
  - `backend/app/schemas/__init__.py`
* **Dependencies Required**: `fastapi>=0.110.0`, `uvicorn>=0.28.0`, `pydantic-settings>=2.2.1`, `python-jose[cryptography]>=3.3.0`, `passlib[bcrypt]>=1.7.4`
* **Estimated Implementation Time**: 6 Hours

---

## Phase 4: Google ADK Multi-Agent System
* **Objective**: Configure model credentials, inherit ADK structure to define core base agents, bind model constraints (Gemini 1.5 Flash vs Gemini 1.5 Pro), and write the core multi-step Orchestrator control flow.
* **Files to Create**: None (using existing placeholders):
  - [backend/app/agents/base.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/agents/base.py) (ADK wrapper configuration and tool bindings)
  - [backend/app/agents/orchestrator.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/agents/orchestrator.py) (Core coordinate routing - Gemini 1.5 Pro)
  - [backend/app/agents/prompt_injection.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/agents/prompt_injection.py) (Jailbreak classifier - Gemini 1.5 Flash)
  - [backend/app/agents/pii_detection.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/agents/pii_detection.py) (NER & RegEx masking - Gemini 1.5 Flash)
  - [backend/app/agents/risk_scoring.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/agents/risk_scoring.py) (Aggregation scoring logic - Gemini 1.5 Pro)
  - [backend/app/agents/report_generation.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/agents/report_generation.py) (Compliance document compiler - Gemini 1.5 Pro)
* **Files to Modify**:
  - `backend/app/agents/__init__.py`
* **Dependencies Required**: `google-genai>=0.1.0` (or target ADK libraries depending on the exact Capstone package configurations)
* **Estimated Implementation Time**: 8 Hours

---

## Phase 5: MCP Integration Client
* **Objective**: Develop subprocess handles and connection connectors to read and execute functions exported by local Model Context Protocol (MCP) servers.
* **Files to Create**: None (using existing placeholders):
  - [backend/app/mcp/integration.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/mcp/integration.py) (HTTP/SSE or Stdio MCP connectors)
* **Files to Modify**:
  - [backend/app/mcp/registry.json](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/mcp/registry.json) (Read whitlists during routing initialization)
* **Dependencies Required**: `mcp>=0.1.0`, `httpx>=0.27.0`
* **Estimated Implementation Time**: 4 Hours

---

## Phase 6: Security Engine & Sandboxing
* **Objective**: Build the local python document parser engine integrating YARA macro scans, and create the global `@action_guard` decorator to parse and validate MCP tool inputs dynamically.
* **Files to Create**: None (using existing placeholders):
  - [backend/app/agents/file_security.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/agents/file_security.py) (PDF/Office parser sandbox & YARA scans)
  - [backend/app/agents/agent_action_guard.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/backend/app/agents/agent_action_guard.py) (FastAPI/ADK `@action_guard` decorator logic)
* **Dependencies Required**: `yara-python>=4.5.0`, `pdfminer.six>=20231111`, `python-docx>=1.1.0`, `openpyxl>=3.1.2`
* **Estimated Implementation Time**: 6 Hours

---

## Phase 7: Streamlit Frontend Dashboard
* **Objective**: Implement the front-end user experience, including the simulation playground, historical audit report viewer, and interactive human-in-the-loop review console.
* **Files to Create**: None (using existing placeholders):
  - [frontend/app.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/frontend/app.py) (Streamlit entry layout)
  - [frontend/components/chat_interface.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/frontend/components/chat_interface.py) (Simulated safe chatbot wrapper)
  - [frontend/components/approval_console.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/frontend/components/approval_console.py) (Admin queue UI panels)
  - [frontend/components/security_report.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/frontend/components/security_report.py) (Interactive audit log traces)
* **Dependencies Required**: `streamlit>=1.32.0`, `httpx>=0.27.0`, `pandas>=2.2.1`
* **Estimated Implementation Time**: 6 Hours

---

## Phase 8: Automated Test Suites
* **Objective**: Implement unit tests for individual agents (injection, PII, sandboxing, action guard) and write integration tests for end-to-end FastAPI endpoint logic.
* **Files to Create**:
  - `tests/test_agents/test_injection.py` (Verify prompt injection scoring)
  - `tests/test_agents/test_pii.py` (Verify entity masking)
  - `tests/test_agents/test_sandbox.py` (Verify YARA and parser sandbox files)
  - `tests/test_api/test_endpoints.py` (Validate gateway routing routes)
* **Files to Modify**:
  - [tests/conftest.py](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/tests/conftest.py) (FastAPI TestClient setups)
* **Dependencies Required**: `pytest>=8.1.1`, `pytest-asyncio>=0.23.5`, `anyio>=4.3.0`
* **Estimated Implementation Time**: 4 Hours

---

## Phase 9: Deployment Containerization
* **Objective**: Create production configurations isolating frontend and backend layers, configuration scripts, and networking.
* **Files to Create**:
  - `Dockerfile.backend` (FastAPI production image definition)
  - `Dockerfile.frontend` (Streamlit container image definition)
  - `docker-compose.yml` (Orchestrates PostgreSQL, Redis, backend, and frontend containers)
* **Dependencies Required**: `docker`, `docker-compose`
* **Estimated Implementation Time**: 3 Hours

---

## Phase 10: Kaggle Submission Assets
* **Objective**: Formulate the final notebook submission containing validation steps, performance data, and structured setup summaries required for evaluation.
* **Files to Create**:
  - `reports/walkthrough.md` (Technical walkthrough instructions)
  - `submission_notebook.ipynb` (Capstone Jupyter notebook wrapper)
* **Files to Modify**:
  - [README.md](file:///C:/Users/vaish/Desktop/Projects/AgentShield-X/README.md) (Add final evaluation trace metrics)
* **Dependencies Required**: `jupyter>=1.0.0`
* **Estimated Implementation Time**: 3 Hours

---

## Time Allocation Summary

```mermaid
gantt
    title AgentShield-X Development Gantt
    dateFormat  X
    axisFormat %d hrs
    
    section Foundation
    Phase 1: Setup & Env          :active, p1, 0, 1
    Phase 2: DB Layer             :p2, after p1, 4h
    Phase 3: FastAPI Backend      :p3, after p2, 6h
    
    section Multi-Agent Core
    Phase 4: Google ADK System    :p4, after p3, 8h
    Phase 5: MCP Integration      :p5, after p4, 4h
    Phase 6: Security Sandbox     :p6, after p5, 6h
    
    section UI & Validation
    Phase 7: Streamlit UI         :p7, after p6, 6h
    Phase 8: Test Suites          :p8, after p7, 4h
    Phase 9: Deployment Compose   :p9, after p8, 3h
    Phase 10: Kaggle Submission   :p10, after p9, 3h
```

*Total Estimated Implementation Effort*: **45 Hours**
