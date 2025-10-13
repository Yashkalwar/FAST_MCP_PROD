from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


class AgentClaims(BaseModel):
    sub: str
    tenant: str
    roles: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)
    dataset_class: Optional[str] = None
    safety_tags: List[str] = Field(default_factory=list)
    geo: Optional[str] = None

