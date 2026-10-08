"""
services/ai/llm_provider.py

LLM Provider Abstraction — P2G

LLMProvider is the abstract interface that decouples SecurityAnalysisService
from any concrete LLM implementation (OpenAI, Gemini, Claude, etc.).

Usage:
    All LLM calls go through LLMProvider.generate().
    SecurityAnalysisService depends on LLMProvider, NOT on any SDK.

This allows:
    - Swapping LLM providers without touching analysis logic
    - Testing with MockLLMProvider (no internet, no API keys, deterministic)
    - Migrating from one provider to another without breaking the service

Protocol for LLMRequest / LLMResponse:
    LLMRequest contains the full prompt context (system + user message).
    LLMResponse contains raw structured text from the provider.
    SecurityAnalysisService is responsible for parsing LLMResponse.content.
"""

from abc import ABC, abstractmethod
from typing import Optional
from pydantic import BaseModel, Field


class LLMRequest(BaseModel):
    """
    Canonical request to any LLM provider.

    The SecurityAnalysisPromptBuilder constructs this from AIAnalysisInput.
    The LLMProvider consumes it verbatim.
    """
    system_prompt: str = Field(
        ...,
        description="System-level instructions for the LLM.",
    )
    user_message: str = Field(
        ...,
        description="The user-facing analysis context and request.",
    )
    max_tokens: int = Field(
        default=4096,
        description="Maximum tokens to generate.",
    )
    temperature: float = Field(
        default=0.1,
        ge=0.0,
        le=2.0,
        description=(
            "LLM temperature. Low values (0.0–0.2) produce more consistent, "
            "deterministic output — preferred for structured security analysis."
        ),
    )
    response_format: str = Field(
        default="json",
        description="Expected response format: 'json' | 'text'. Always 'json' for structured analysis.",
    )


class LLMResponse(BaseModel):
    """
    Canonical response from any LLM provider.
    """
    success: bool = Field(..., description="True if the provider returned a usable response.")
    content: Optional[str] = Field(
        default=None,
        description="Raw response content (JSON string). None on failure.",
    )
    provider: str = Field(
        default="UNKNOWN",
        description="Name of the provider that generated this response.",
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message if success=False.",
    )
    error_type: Optional[str] = Field(
        default=None,
        description=(
            "Machine-readable error type: timeout | network | rate_limit | "
            "invalid_response | context_limit | auth | unknown"
        ),
    )


class LLMProviderError(Exception):
    """Raised by LLMProvider implementations on unrecoverable errors."""
    def __init__(self, message: str, error_type: str = "unknown"):
        super().__init__(message)
        self.error_type = error_type


class LLMProvider(ABC):
    """
    Abstract base class for all LLM provider implementations.

    Implementing a new provider:
        1. Subclass LLMProvider
        2. Implement generate(request) → LLMResponse
        3. Inject into SecurityAnalysisService at construction time

    Never raise exceptions from generate() — always return LLMResponse(success=False, ...).
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name (e.g. 'OpenAI', 'Gemini', 'MockLLMProvider')."""
        ...

    @abstractmethod
    def generate(self, request: LLMRequest) -> LLMResponse:
        """
        Generate a response from the LLM.

        Must:
            - Never raise exceptions (catch and return LLMResponse(success=False))
            - Always return LLMResponse with provider set to provider_name
            - On success: return content as a JSON-parseable string
            - On failure: set success=False, error, error_type

        Args:
            request: LLMRequest with system_prompt, user_message, and parameters.

        Returns:
            LLMResponse — always, never raises.
        """
        ...
