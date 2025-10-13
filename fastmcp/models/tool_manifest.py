from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict, List, Optional

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, field_validator


def _validator(schema: Dict[str, Any]) -> Draft202012Validator:
    return Draft202012Validator(schema)


class ToolManifest(BaseModel):
    toolId: str
    name: str
    description: str
    inputs: Dict[str, Any]
    outputs: Dict[str, Any]
    required_scopes: List[str] = Field(default_factory=list)
    safety_tags: List[str] = Field(default_factory=list)
    provider_id: str
    cost_estimate: Dict[str, Any] = Field(default_factory=dict)
    latency_estimate_ms: int
    tenant: str
    examples: List[Dict[str, Any]] = Field(default_factory=list)
    manual_review_required: bool = False
    http_method: Optional[str] = None
    route: Optional[str] = None

    model_config = ConfigDict(extra="ignore")

    @field_validator("inputs", "outputs")
    @classmethod
    def ensure_schema_has_type(cls, schema: Dict[str, Any]) -> Dict[str, Any]:
        if "type" not in schema and "$ref" not in schema:
            raise ValueError("JSON schema must specify `type` or `$ref`")
        return schema

    def validate_input(self, payload: Dict[str, Any]) -> None:
        self._input_validator.validate(payload)

    def validate_output(self, payload: Dict[str, Any]) -> None:
        self._output_validator.validate(payload)

    @property
    def _input_validator(self) -> Draft202012Validator:
        import json

        schema_json = json.dumps(self.inputs, sort_keys=True)
        return _validator_cached(self.toolId, "input", schema_json)

    @property
    def _output_validator(self) -> Draft202012Validator:
        import json

        schema_json = json.dumps(self.outputs, sort_keys=True)
        return _validator_cached(self.toolId, "output", schema_json)


@lru_cache(maxsize=128)
def _validator_cached(tool_id: str, kind: str, schema_json: str) -> Draft202012Validator:
    # schema may not be hashable - convert to frozendict by JSON string.
    import json

    schema = json.loads(schema_json)
    return Draft202012Validator(schema)


ToolManifest.model_rebuild()
