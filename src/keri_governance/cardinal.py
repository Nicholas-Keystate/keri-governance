# -*- encoding: utf-8 -*-
"""
Cardinal Rules Engine - Artifact governance for GAID lifecycle.

Defines the minimum verification strength required for each operation
on each artifact type. Cardinal rules are the "other half" to KGQL's
query-time governance: while KGQL governs credential graph traversal,
cardinal rules govern artifact lifecycle operations.

GAID = DAID + Governance Rules

Five artifact types:
    - ALG: Algorithms (cryptographic, hashing, KDF)
    - SCH: Schemas (ACDC credential schemas)
    - PRO: Protocols (communication, exchange)
    - PKG: Packages (software supply chain)
    - RUN: Runtimes (execution environments)

Operations:
    - register: First registration of an artifact
    - rotate: Version rotation (new version, same identity)
    - deprecate: Mark artifact as deprecated with successor
    - revoke: Hard revocation (security compromise)
    - verify: Verify artifact integrity and status
    - resolve: Resolve artifact by identifier
    - execute: Execute/use the artifact

Cardinal rules define minimum StrengthLevel per (artifact_type, operation).
The rule: actual_strength >= required_strength.

Example:
    Registering an algorithm requires TEL_ANCHORED (full credential chain).
    Resolving an algorithm only requires SAID_ONLY (content integrity).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from keri_governance.primitives import StrengthLevel, strength_satisfies


class ArtifactType(Enum):
    """
    GAID artifact type codes.

    Each type represents a class of governed artifact in the KERI ecosystem.
    """
    ALG = "alg"   # Algorithms
    SCH = "sch"   # Schemas
    PRO = "pro"   # Protocols
    PKG = "pkg"   # Packages
    RUN = "run"   # Runtimes


class Operation(Enum):
    """
    Artifact lifecycle operations subject to cardinal governance.
    """
    REGISTER = "register"     # First registration
    ROTATE = "rotate"         # Version rotation
    DEPRECATE = "deprecate"   # Deprecation with successor
    REVOKE = "revoke"         # Hard revocation
    VERIFY = "verify"         # Integrity verification
    RESOLVE = "resolve"       # Identifier resolution
    EXECUTE = "execute"       # Use/execution


@dataclass(frozen=True)
class CardinalRule:
    """
    A single cardinal rule: minimum strength for an operation on an artifact type.

    Args:
        artifact_type: The GAID artifact type this rule governs
        operation: The lifecycle operation
        min_strength: Minimum StrengthLevel required
        rationale: Why this strength level is required
    """
    artifact_type: ArtifactType
    operation: Operation
    min_strength: StrengthLevel
    rationale: str = ""


@dataclass
class CardinalCheckResult:
    """Result of a cardinal rule check."""
    allowed: bool = True
    rule: Optional[CardinalRule] = None
    actual_strength: Optional[StrengthLevel] = None
    message: str = ""

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "message": self.message,
            "artifact_type": self.rule.artifact_type.value if self.rule else None,
            "operation": self.rule.operation.value if self.rule else None,
            "min_strength": self.rule.min_strength.name if self.rule else None,
            "actual_strength": self.actual_strength.name if self.actual_strength else None,
        }


class CardinalRuleSet:
    """
    Collection of cardinal rules for one or more artifact types.

    Rules are indexed by (artifact_type, operation) for O(1) lookup.
    """

    def __init__(self, rules: list[CardinalRule] | None = None):
        self._rules: dict[tuple[ArtifactType, Operation], CardinalRule] = {}
        if rules:
            for rule in rules:
                self.add(rule)

    def add(self, rule: CardinalRule) -> None:
        """Add or replace a cardinal rule."""
        self._rules[(rule.artifact_type, rule.operation)] = rule

    def get(
        self,
        artifact_type: ArtifactType,
        operation: Operation,
    ) -> Optional[CardinalRule]:
        """Get the cardinal rule for an artifact type and operation."""
        return self._rules.get((artifact_type, operation))

    def rules_for_type(self, artifact_type: ArtifactType) -> list[CardinalRule]:
        """Get all cardinal rules for an artifact type."""
        return [
            rule for (at, _), rule in self._rules.items()
            if at == artifact_type
        ]

    def all_rules(self) -> list[CardinalRule]:
        """Get all cardinal rules."""
        return list(self._rules.values())

    def __len__(self) -> int:
        return len(self._rules)

    def __contains__(self, key: tuple[ArtifactType, Operation]) -> bool:
        return key in self._rules


class CardinalChecker:
    """
    Evaluates artifact operations against cardinal rules.

    Usage:
        checker = CardinalChecker(default_cardinal_rules())
        result = checker.check(ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED)
        if not result.allowed:
            raise GovernanceViolation(result.message)
    """

    def __init__(self, ruleset: CardinalRuleSet):
        self._ruleset = ruleset

    @property
    def ruleset(self) -> CardinalRuleSet:
        return self._ruleset

    def check(
        self,
        artifact_type: ArtifactType,
        operation: Operation,
        actual_strength: StrengthLevel,
    ) -> CardinalCheckResult:
        """
        Check if an operation meets the cardinal strength requirement.

        Args:
            artifact_type: The artifact type being operated on
            operation: The lifecycle operation being performed
            actual_strength: The verification strength achieved

        Returns:
            CardinalCheckResult indicating whether the operation is allowed
        """
        rule = self._ruleset.get(artifact_type, operation)

        if rule is None:
            # No cardinal rule = allowed (ungoverned operation)
            return CardinalCheckResult(
                allowed=True,
                actual_strength=actual_strength,
                message=f"No cardinal rule for {artifact_type.value}:{operation.value}",
            )

        if strength_satisfies(actual_strength, rule.min_strength):
            return CardinalCheckResult(
                allowed=True,
                rule=rule,
                actual_strength=actual_strength,
                message=f"{operation.value} on {artifact_type.value}: "
                        f"{actual_strength.name} meets {rule.min_strength.name}",
            )
        else:
            return CardinalCheckResult(
                allowed=False,
                rule=rule,
                actual_strength=actual_strength,
                message=f"{operation.value} on {artifact_type.value} requires "
                        f"{rule.min_strength.name} but has {actual_strength.name}",
            )

    def check_all(
        self,
        artifact_type: ArtifactType,
        actual_strength: StrengthLevel,
    ) -> dict[Operation, CardinalCheckResult]:
        """
        Check all operations for an artifact type against a strength level.

        Returns dict mapping each governed operation to its check result.
        """
        results = {}
        for rule in self._ruleset.rules_for_type(artifact_type):
            results[rule.operation] = self.check(
                artifact_type, rule.operation, actual_strength,
            )
        return results


# ── Default Cardinal Rules ────────────────────────────────────────────


def _alg_rules() -> list[CardinalRule]:
    """Cardinal rules for Algorithm artifacts."""
    return [
        CardinalRule(
            ArtifactType.ALG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED,
            "Algorithm registration requires full credential chain for trust root",
        ),
        CardinalRule(
            ArtifactType.ALG, Operation.ROTATE, StrengthLevel.KEL_ANCHORED,
            "Algorithm version rotation requires key-state verified signature",
        ),
        CardinalRule(
            ArtifactType.ALG, Operation.DEPRECATE, StrengthLevel.KEL_ANCHORED,
            "Deprecation requires verifiable authority from algorithm controller",
        ),
        CardinalRule(
            ArtifactType.ALG, Operation.REVOKE, StrengthLevel.TEL_ANCHORED,
            "Revocation requires full credential chain (security-critical)",
        ),
        CardinalRule(
            ArtifactType.ALG, Operation.VERIFY, StrengthLevel.SAID_ONLY,
            "Verification only needs content integrity",
        ),
        CardinalRule(
            ArtifactType.ALG, Operation.RESOLVE, StrengthLevel.ANY,
            "Resolution is a read-only lookup",
        ),
        CardinalRule(
            ArtifactType.ALG, Operation.EXECUTE, StrengthLevel.SAID_ONLY,
            "Execution requires integrity verification of algorithm content",
        ),
    ]


def _sch_rules() -> list[CardinalRule]:
    """Cardinal rules for Schema artifacts."""
    return [
        CardinalRule(
            ArtifactType.SCH, Operation.REGISTER, StrengthLevel.TEL_ANCHORED,
            "Schema registration requires full credential chain for governance",
        ),
        CardinalRule(
            ArtifactType.SCH, Operation.ROTATE, StrengthLevel.TEL_ANCHORED,
            "Schema rotation requires TEL anchoring (breaking changes affect credentials)",
        ),
        CardinalRule(
            ArtifactType.SCH, Operation.DEPRECATE, StrengthLevel.KEL_ANCHORED,
            "Schema deprecation requires verifiable authority",
        ),
        CardinalRule(
            ArtifactType.SCH, Operation.REVOKE, StrengthLevel.TEL_ANCHORED,
            "Schema revocation is credential-critical",
        ),
        CardinalRule(
            ArtifactType.SCH, Operation.VERIFY, StrengthLevel.SAID_ONLY,
            "Schema verification needs content integrity",
        ),
        CardinalRule(
            ArtifactType.SCH, Operation.RESOLVE, StrengthLevel.ANY,
            "Schema resolution is a read-only lookup",
        ),
    ]


def _pro_rules() -> list[CardinalRule]:
    """Cardinal rules for Protocol artifacts."""
    return [
        CardinalRule(
            ArtifactType.PRO, Operation.REGISTER, StrengthLevel.TEL_ANCHORED,
            "Protocol registration requires full credential chain",
        ),
        CardinalRule(
            ArtifactType.PRO, Operation.ROTATE, StrengthLevel.KEL_ANCHORED,
            "Protocol version rotation requires key-state verification",
        ),
        CardinalRule(
            ArtifactType.PRO, Operation.DEPRECATE, StrengthLevel.KEL_ANCHORED,
            "Protocol deprecation requires verifiable authority",
        ),
        CardinalRule(
            ArtifactType.PRO, Operation.REVOKE, StrengthLevel.TEL_ANCHORED,
            "Protocol revocation requires full credential chain",
        ),
        CardinalRule(
            ArtifactType.PRO, Operation.VERIFY, StrengthLevel.SAID_ONLY,
            "Protocol verification needs content integrity",
        ),
        CardinalRule(
            ArtifactType.PRO, Operation.RESOLVE, StrengthLevel.ANY,
            "Protocol resolution is a read-only lookup",
        ),
    ]


def _pkg_rules() -> list[CardinalRule]:
    """Cardinal rules for Package artifacts."""
    return [
        CardinalRule(
            ArtifactType.PKG, Operation.REGISTER, StrengthLevel.TEL_ANCHORED,
            "Package registration requires publisher credential (supply chain)",
        ),
        CardinalRule(
            ArtifactType.PKG, Operation.ROTATE, StrengthLevel.TEL_ANCHORED,
            "Package version requires TEL anchoring (supply chain integrity)",
        ),
        CardinalRule(
            ArtifactType.PKG, Operation.DEPRECATE, StrengthLevel.KEL_ANCHORED,
            "Package deprecation (yank) requires publisher authority",
        ),
        CardinalRule(
            ArtifactType.PKG, Operation.REVOKE, StrengthLevel.TEL_ANCHORED,
            "Package revocation (hijack response) requires full credential chain",
        ),
        CardinalRule(
            ArtifactType.PKG, Operation.VERIFY, StrengthLevel.SAID_ONLY,
            "Package verification needs content integrity (hash check)",
        ),
        CardinalRule(
            ArtifactType.PKG, Operation.RESOLVE, StrengthLevel.ANY,
            "Package resolution is a read-only lookup",
        ),
        CardinalRule(
            ArtifactType.PKG, Operation.EXECUTE, StrengthLevel.KEL_ANCHORED,
            "Package installation requires publisher signature verification",
        ),
    ]


def _run_rules() -> list[CardinalRule]:
    """Cardinal rules for Runtime artifacts."""
    return [
        CardinalRule(
            ArtifactType.RUN, Operation.REGISTER, StrengthLevel.TEL_ANCHORED,
            "Runtime registration requires full credential chain",
        ),
        CardinalRule(
            ArtifactType.RUN, Operation.ROTATE, StrengthLevel.KEL_ANCHORED,
            "Runtime version rotation requires key-state verification",
        ),
        CardinalRule(
            ArtifactType.RUN, Operation.DEPRECATE, StrengthLevel.KEL_ANCHORED,
            "Runtime deprecation requires verifiable authority",
        ),
        CardinalRule(
            ArtifactType.RUN, Operation.REVOKE, StrengthLevel.TEL_ANCHORED,
            "Runtime revocation is security-critical",
        ),
        CardinalRule(
            ArtifactType.RUN, Operation.VERIFY, StrengthLevel.SAID_ONLY,
            "Runtime verification needs content integrity",
        ),
        CardinalRule(
            ArtifactType.RUN, Operation.RESOLVE, StrengthLevel.ANY,
            "Runtime resolution is a read-only lookup",
        ),
        CardinalRule(
            ArtifactType.RUN, Operation.EXECUTE, StrengthLevel.KEL_ANCHORED,
            "Runtime execution requires verified environment",
        ),
    ]


def default_cardinal_rules() -> CardinalRuleSet:
    """
    Build the default cardinal rule set for all artifact types.

    Returns a CardinalRuleSet with rules for ALG, SCH, PRO, PKG, and RUN.
    These represent the baseline governance requirements. Applications
    can override by constructing custom CardinalRuleSets.
    """
    all_rules = (
        _alg_rules()
        + _sch_rules()
        + _pro_rules()
        + _pkg_rules()
        + _run_rules()
    )
    return CardinalRuleSet(all_rules)
