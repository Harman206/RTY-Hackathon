"""Request schemas for the Compliance Copilot API."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, model_validator

MAX_REGULATION_CHARS = 100_000


class RegulationAnalysisRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_REGULATION_CHARS, description="Regulation text to analyze")
    company_state: Optional[Dict[str, Any]] = Field(
        None, description="Company state to check. Defaults to the mock company profile."
    )


class AuditGenerationRequest(BaseModel):
    text: Optional[str] = Field(
        None, min_length=1, max_length=MAX_REGULATION_CHARS,
        description="Regulation text. Analyzed first when `anomalies` is not given.",
    )
    anomalies: Optional[List[Dict[str, Any]]] = Field(
        None, description="Findings from /api/analyze-regulation. Skips a second analysis call."
    )
    company_state: Optional[Dict[str, Any]] = Field(
        None, description="Company state to check. Defaults to the mock company profile."
    )

    @model_validator(mode="after")
    def _text_or_anomalies(self):
        if self.text is None and self.anomalies is None:
            raise ValueError("provide `text` or `anomalies`")
        return self
