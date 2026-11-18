"""FastAPI routes connecting the UI, the mock company state and the AI compliance engine.

Run:  uvicorn main:app --reload
Each request can carry the user's own Anthropic key in the X-Anthropic-Api-Key header;
without it the server's ANTHROPIC_API_KEY is used. The key is never logged or stored.
"""

import logging
from typing import Any, Callable, Optional

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from ai_engine import LLMConfigError, LLMError, analyze_compliance_gap, generate_audit_trail
from mock_db import get_compliance_state
from models import AuditGenerationRequest, RegulationAnalysisRequest

logger = logging.getLogger("api")

app = FastAPI(title="Compliance Copilot API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_KEY_HEADER = "X-Anthropic-Api-Key"


def _call_engine(function: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
    """Run an engine function and map its errors to HTTP status codes."""
    try:
        return function(*args, **kwargs)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail={"error": "INVALID_INPUT", "message": str(exc)})
    except LLMConfigError as exc:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "LLM_AUTH",
                "message": f"{exc}. Send your Anthropic key in the {API_KEY_HEADER} header.",
            },
        )
    except LLMError as exc:
        logger.warning("engine failure: %s", type(exc).__name__)
        raise HTTPException(status_code=502, detail={"error": "LLM_UNAVAILABLE", "message": str(exc)})


def _api_key(header_value: Optional[str]) -> Optional[str]:
    if header_value is None or not header_value.strip():
        return None
    return header_value.strip()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/system-state")
def system_state():
    """Expose the current mock company compliance profile."""
    return get_compliance_state()


@app.post("/api/analyze-regulation")
def analyze_regulation(
    request: RegulationAnalysisRequest,
    x_anthropic_api_key: Optional[str] = Header(None, alias=API_KEY_HEADER),
):
    """Analyze regulation text against the company profile. Returns the list of anomalies."""
    state = request.company_state if request.company_state is not None else get_compliance_state()
    return _call_engine(
        analyze_compliance_gap, request.text, state, api_key=_api_key(x_anthropic_api_key)
    )


@app.post("/api/generate-audit")
def generate_audit_report(
    request: AuditGenerationRequest,
    x_anthropic_api_key: Optional[str] = Header(None, alias=API_KEY_HEADER),
):
    """Generate the Markdown audit log.

    Pass the `anomalies` returned by /api/analyze-regulation to avoid a second analysis;
    otherwise `text` is analyzed first. Returns {"anomalies": [...], "markdown": "..."}.
    """
    key = _api_key(x_anthropic_api_key)
    anomalies = request.anomalies
    if anomalies is None:
        state = request.company_state if request.company_state is not None else get_compliance_state()
        anomalies = _call_engine(analyze_compliance_gap, request.text, state, api_key=key)
    markdown = _call_engine(generate_audit_trail, anomalies, api_key=key)
    return {"anomalies": anomalies, "markdown": markdown}
