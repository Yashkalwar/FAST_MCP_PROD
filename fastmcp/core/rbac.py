# RBAC Policy Engine - Role-based access control with dynamic policy evaluation
# Main functions: PolicyEngine.allowed() for authorization decisions, scope expansion from roles
# Flow: load policies -> expand user scopes -> check action scopes -> evaluate rules -> allow/deny

from __future__ import annotations

import signal
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import yaml

@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    require_confirmation: bool = False


def _resolve_reference(reference: str, *, claims: Dict[str, Any], resource: Dict[str, Any], context: Dict[str, Any]) -> Any:
    if reference.startswith("subject."):
        path = reference[len("subject.") :]
        value: Any = claims
    elif reference.startswith("resource."):
        path = reference[len("resource.") :]
        value = resource
    elif reference.startswith("context."):
        path = reference[len("context.") :]
        value = context
    else:
        return None

    for part in path.split("."):
        if isinstance(value, dict):
            value = value.get(part)
        else:
            return None
    return value


class PolicyEngine:
    def __init__(self, policy_path: Path):
        self.policy_path = policy_path
        self.version = 0
        self.roles: Dict[str, list[str]] = {}
        self.rules: list[dict[str, Any]] = []
        self.reload()
        self._install_signal_handler()

    def _install_signal_handler(self) -> None:
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, lambda *_: self.reload())

    def reload(self) -> None:
        data = yaml.safe_load(self.policy_path.read_text("utf-8"))
        self.version += 1
        self.roles = data.get("roles", {}) or {}
        self.rules = data.get("rules", []) or []

    def expand_scopes(self, claims: Dict[str, Any]) -> set[str]:
        scopes = set(claims.get("scopes") or [])
        for role in claims.get("roles") or []:
            scopes.update(self.roles.get(role, []))
        return scopes

    def allowed(
        self,
        claims: Dict[str, Any],
        action: str,
        resource: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
        resource = resource or {}
        context = context or {}

        allow_reason: Optional[str] = None
        require_confirmation = False
        subject_scopes = self.expand_scopes(claims)

        # Scope guard: if an action-specific scope is required, expect `<action>` or `<action>:*` pattern.
        if action not in {"catalog:list"}:  # catalog:list is public per policy rules
            scope_matches = {action, f"{action}:write", f"{action}:read"}
            if not subject_scopes.intersection(scope_matches):
                return PolicyDecision(False, reason=f"missing_scope:{action}")

        for rule in self.rules:
            if not self._rule_matches(rule, action, claims, resource, context):
                continue

            effect = rule.get("effect", "deny").lower()
            rule_id = rule.get("id", "unknown")
            if effect == "deny":
                return PolicyDecision(False, reason=rule_id)
            if effect == "allow":
                if rule.get("require_confirmation"):
                    if allow_reason:
                        require_confirmation = True
                    else:
                        # Confirmation rules augment an existing allow; skip if no base allow yet.
                        continue
                if not allow_reason:
                    allow_reason = rule_id

        if allow_reason:
            return PolicyDecision(True, reason=allow_reason, require_confirmation=require_confirmation)
        return PolicyDecision(False, reason="no_matching_policy")

    def _rule_matches(
        self,
        rule: Dict[str, Any],
        action: str,
        claims: Dict[str, Any],
        resource: Dict[str, Any],
        context: Dict[str, Any],
    ) -> bool:
        conditions: Dict[str, Any] = rule.get("when", {}) or {}
        for key, expected in conditions.items():
            if key == "action":
                if action != expected:
                    return False
                continue

            if "!=" in key and expected in (True, None):
                left, right = [part.strip() for part in key.split("!=", 1)]
                left_val = _resolve_reference(left, claims=claims, resource=resource, context=context)
                right_val = _resolve_reference(right, claims=claims, resource=resource, context=context)
                if left_val is None or right_val is None:
                    return False
                if left_val == right_val:
                    return False
                continue

            if key.startswith("subject."):
                value = _resolve_reference(key, claims=claims, resource=resource, context=context)
                if isinstance(expected, list):
                    # Check if user has ANY of the required roles (intersection)
                    if not set(expected).intersection(set(value or [])):
                        return False
                else:
                    if value != expected:
                        return False
                continue

            if key == "resource.safety_tags_any":
                resource_tags = set(resource.get("safety_tags") or [])
                if not resource_tags.intersection(set(expected or [])):
                    return False
                continue

            if key.startswith("resource."):
                value = _resolve_reference(key, claims=claims, resource=resource, context=context)
                if isinstance(expected, list):
                    if value not in expected:
                        return False
                else:
                    if value != expected:
                        return False
                continue

            if key.startswith("context."):
                value = _resolve_reference(key, claims=claims, resource=resource, context=context)
                if value != expected:
                    return False

        return True


_policy_engine = PolicyEngine(Path("fastmcp/policies/policies.yml"))


def allowed(
    claims: Dict[str, Any],
    action: str,
    resource: Optional[Dict[str, Any]] = None,
    context: Optional[Dict[str, Any]] = None,
    ) -> PolicyDecision:
    return _policy_engine.allowed(claims, action, resource, context)


def subject_scopes(claims: Dict[str, Any]) -> set[str]:
    """Return scopes expanded by role membership."""
    return _policy_engine.expand_scopes(claims)
