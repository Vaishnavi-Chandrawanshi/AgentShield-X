# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.0.0] - 2026-07-01

### Added
- **Queue Engine**: Operational human approval hold workflow for `HUMAN_REVIEW` composite risk verdicts.
- **SIEM Audit History Filters**: Top-level search filters including Date Range picker, Verdict class, Triggered Detector, Min Risk slider, and User Session.
- **Gateway Summary Headers**: High-fidelity metadata summarizing execution times, signatures database build versions, composite risk indexes, and transaction IDs.
- **Enhanced Log Grid**: Displays all 10 mandated auditing columns in the SIEM audit log registry (Transaction ID, Prompt Hash, Timestamp, Verdict, Composite Risk, Execution Time, Triggered Detectors, Matched Evidence, Analyst Action, User).

### Changed
- Refactored backend workflow routing into conceptual namespaces: Detector Engine, Risk Engine, Sandbox Engine, Audit Engine, Policy Engine, and Queue Engine.
- Refined Granular Detector Table cell values: displays `None` when clean, `—` when no signatures match, and highlights active triggers in bold.
- Unified downstream LLM responses to prefix with clear connection statuses (`Gateway forwarded request successfully` vs `Gateway intercepted request before downstream execution`).

---

## [2.0.0] - 2026-06-15

### Added
- **Multi-Scanner Framework**: Integrated 10 specialized detectors including Prompt Injection, Jailbreak, SQL Injection, Command Injection, XSS, Prompt Leakage, Code Execution, Sensitive Data (PII), Malware Signature, and File Sandbox.
- **Dynamic Risk Engine**: Dynamic, deterministic scoring replacing static threat flags and duplicate risk outputs.
- **Document Sandbox Scanner**: Added file attachments parsing, MIME type validations, macro extractors, and YARA signature compilation rules.

### Changed
- Standardized FastAPI endpoint JSON parameters to accept prompt-only, document-only, or multi-modal requests without returning HTTP 422 errors.

---

## [1.0.0] - 2026-05-01

### Added
- Initial release of the AgentShield-X intercepting security gateway.
- Basic proxy middleware intercepting downstream LLM requests.
- Core SQLi, XSS, and PII regular expression signatures.
- Local SQLite persistence for basic request logs.
- Admin dashboard metrics and simple chatbot frontend interface.
