"""Pydantic response models for MCP tools."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    code: str
    message: str


class ToolResponse(BaseModel):
    ok: bool = True
    schema_version: str = "1.0"
    data: dict[str, Any] = Field(default_factory=dict)
    error: ErrorDetail | None = None
    warnings: list[str] = Field(default_factory=list)

    @classmethod
    def success(cls, **data: Any) -> ToolResponse:
        return cls(ok=True, data=data)

    @classmethod
    def failure(cls, code: str, message: str, **data: Any) -> ToolResponse:
        return cls(ok=False, data=data, error=ErrorDetail(code=code, message=message))
