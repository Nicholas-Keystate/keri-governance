# -*- encoding: utf-8 -*-
"""
Governance Constraint Primitives.

Two partial orders for the KERI governance ecosystem:

1. EdgeOperator: Credential graph edge constraints (I2I > DI2I > NI2I > ANY)
   Used by KGQL for query-time governance of credential traversal.

2. StrengthLevel: Artifact verification strength (TEL > KEL > SAID > ANY)
   Used by keri-sec for artifact lifecycle governance.

Both follow the same algebraic pattern: a satisfies b iff strength(a) >= strength(b).
"""

from enum import Enum, IntEnum


class EdgeOperator(Enum):
    """
    Edge constraint operators for KERI property graph queries.

    These operators define the relationship constraints between
    credential issuers and subjects:

    - I2I: Issuer-to-Issuer (child issuer == parent subject)
    - DI2I: Delegated-Issuer-to-Issuer (child issuer in delegation chain)
    - NI2I: No-Issuer-to-Issuer constraint (third-party attestation)
    - ANY: Accept any valid edge (no constraint)
    """
    I2I = "I2I"
    DI2I = "DI2I"
    NI2I = "NI2I"
    ANY = "ANY"


class StrengthLevel(IntEnum):
    """
    Verification strength for artifact operations.

    Partial order: TEL_ANCHORED > KEL_ANCHORED > SAID_ONLY > ANY

    - TEL_ANCHORED: Full credential chain (highest trust)
    - KEL_ANCHORED: Signature + key state verification
    - SAID_ONLY: Content integrity via hash
    - ANY: No verification required
    """
    ANY = 0
    SAID_ONLY = 1
    KEL_ANCHORED = 2
    TEL_ANCHORED = 3


# Operator strength mapping (higher = stronger)
OPERATOR_STRENGTH: dict[EdgeOperator, int] = {
    EdgeOperator.ANY: 0,
    EdgeOperator.NI2I: 1,
    EdgeOperator.DI2I: 2,
    EdgeOperator.I2I: 3,
}


def operator_satisfies(actual: EdgeOperator, required: EdgeOperator) -> bool:
    """
    Check if an actual operator satisfies a required operator.

    The constraint algebra partial order:
        I2I > DI2I > NI2I > ANY

    An operator satisfies a requirement if it is equal or stronger.

    Args:
        actual: The operator present on the edge
        required: The operator the rule requires

    Returns:
        True if actual >= required in the partial order
    """
    return OPERATOR_STRENGTH[actual] >= OPERATOR_STRENGTH[required]


def strength_satisfies(actual: StrengthLevel, required: StrengthLevel) -> bool:
    """
    Check if an actual strength level meets or exceeds a required level.

    The constraint algebra partial order:
        TEL_ANCHORED > KEL_ANCHORED > SAID_ONLY > ANY

    Args:
        actual: The verification strength achieved
        required: The minimum verification strength needed

    Returns:
        True if actual >= required in the partial order
    """
    return actual >= required


def operator_name(op: EdgeOperator) -> str:
    """Human-readable name for an edge operator."""
    _NAMES = {
        EdgeOperator.I2I: "Issuer-to-Issuer",
        EdgeOperator.DI2I: "Delegated-Issuer-to-Issuer",
        EdgeOperator.NI2I: "Non-Issuer-to-Issuer",
        EdgeOperator.ANY: "Any",
    }
    return _NAMES.get(op, op.value)


def strength_name(level: StrengthLevel) -> str:
    """Human-readable name for a strength level."""
    _NAMES = {
        StrengthLevel.ANY: "Any",
        StrengthLevel.SAID_ONLY: "SAID-Only",
        StrengthLevel.KEL_ANCHORED: "KEL-Anchored",
        StrengthLevel.TEL_ANCHORED: "TEL-Anchored",
    }
    return _NAMES.get(level, str(level))
