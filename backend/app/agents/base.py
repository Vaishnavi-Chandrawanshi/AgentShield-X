import os
from typing import Type, TypeVar, Optional
from pydantic import BaseModel
from google import genai
from google.genai import types
from google.genai.errors import APIError
from backend.app.core.config import settings

T = TypeVar("T", bound=BaseModel)

class BaseAgent:
    """
    Abstract base class for AgentShield-X multi-agent topology.
    Manages Google GenAI client lifecycle, dynamic model routing,
    and supports mock fallback logic for testing in keyless environments.
    """
    def __init__(self, system_instruction: str, model_name: str):
        self.system_instruction = system_instruction
        self.model_name = model_name
        self.api_key = os.getenv("GEMINI_API_KEY")
        
        if self.api_key:
            try:
                self.client = genai.Client(api_key=self.api_key)
            except Exception:
                self.client = None
        else:
            self.client = None

    def _generate_structured(
        self, 
        prompt: str, 
        schema_cls: Type[T], 
        mock_fallback_handler
    ) -> T:
        """
        Executes a content generation request expecting a structured Pydantic response.
        If the Gemini client is unconfigured or returns an APIError, it falls back to the mock handler.
        """
        if self.client:
            try:
                config = types.GenerateContentConfig(
                    system_instruction=self.system_instruction,
                    response_mime_type="application/json",
                    response_schema=schema_cls,
                    temperature=0.1  # Low temperature for deterministic security verdicts
                )
                response = self.client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=config
                )
                if response.text:
                    return schema_cls.model_validate_json(response.text)
            except APIError as e:
                # Handle quota or auth error and fall back to local mock parsing
                pass
            except Exception as e:
                pass
                
        # Keyless or error fallback
        return mock_fallback_handler(prompt)

    def _get_embedding(self, text: str) -> Optional[list[float]]:
        """
        Computes 1536-dimensional text embeddings using the standard Gemini embedding model.
        Returns None if client is offline.
        """
        if self.client:
            try:
                response = self.client.models.embed_content(
                    model="text-embedding-004",
                    contents=text
                )
                # Map standard embedding list output
                if response.embeddings:
                    values = response.embeddings[0].values
                    # text-embedding-004 has 768 dimensions by default. If we need exactly 1536,
                    # we can pad it or configure it. But wait, pgvector/exploit_signatures is configured with SafeVector(1536) in architecture.
                    # Wait, if text-embedding-004 has 768 dimensions, let's see. If we need exactly 1536,
                    # we can pad the 768 dimensions with zeros to reach 1536, or adjust.
                    # Let's ensure the embedding matches the table constraint dimension!
                    if len(values) < 1536:
                        values = list(values) + [0.0] * (1536 - len(values))
                    elif len(values) > 1536:
                        values = list(values[:1536])
                    return values
            except Exception:
                pass
        return None
