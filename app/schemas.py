from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class AccessLog(BaseModel):
    timestamp: datetime
    ip: str = Field(min_length=3, max_length=64)
    method: str = Field(min_length=3, max_length=10)
    path: str = Field(min_length=1, max_length=2048)
    status_code: int = Field(ge=100, le=599)
    response_time_ms: float = Field(ge=0, le=120000)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()


class AnalyzeRequest(BaseModel):
    records: list[AccessLog] = Field(min_length=1, max_length=10000)


class EntityResult(BaseModel):
    ip: str
    threat_detected: bool
    confidence: float = Field(ge=0.0, le=1.0)
    action: Literal["bloquear", "alertar", "ignorar"]
    probable_behavior: str
    indicators: list[str]


class AnalyzeResponse(BaseModel):
    threat_detected: bool
    confidence: float = Field(ge=0.0, le=1.0)
    action: Literal["bloquear", "alertar", "ignorar"]
    records_analyzed: int
    entities_analyzed: int
    results: list[EntityResult]
