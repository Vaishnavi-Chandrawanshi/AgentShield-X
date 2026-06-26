import pytest
from backend.app.agents.pii_detection import PiiDetectionAgent

def test_pii_scan_no_pii():
    agent = PiiDetectionAgent()
    prompt = "This is a normal query with no sensitive information in it."
    result = agent.scan(prompt)
    assert result.has_pii is False
    assert result.sanitized_prompt == prompt

def test_pii_scan_with_email():
    agent = PiiDetectionAgent()
    prompt = "My contact email address is john.doe@example.com."
    result = agent.scan(prompt)
    assert result.has_pii is True
    assert "[EMAIL REDACTED]" in result.sanitized_prompt
    assert "john.doe@example.com" not in result.sanitized_prompt
    assert "EMAIL" in result.detected_entities

def test_pii_scan_with_ssn():
    agent = PiiDetectionAgent()
    prompt = "Here is my SSN: 000-12-3456."
    result = agent.scan(prompt)
    assert result.has_pii is True
    assert "[SSN REDACTED]" in result.sanitized_prompt
    assert "000-12-3456" not in result.sanitized_prompt
    assert "SSN" in result.detected_entities
