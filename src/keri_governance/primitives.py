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


# ============================================================================
# Hardman LoA (Level of Assurance) Integration
# ============================================================================
#
# Maps Hardman's progressive assurance ladder to our constraint algebra.
# See: Daniel Hardman, "Org Vet as a Credential Type", May 2025
#
# LoA Ladder: LoA_0 < LoA_1 < LoA_2 < LoA_3 < vLEI
# Each level is cumulative - higher levels assert everything lower levels did.
# ============================================================================


class LoALevel(IntEnum):
    """
    Hardman's Level of Assurance for organizational identity.

    Progressive assurance ladder:
        LoA_0: Identifier Affidavit (LEI exists, org not defunct)
        LoA_1: Bronze Vet (+ domain control, DNS binding)
        LoA_2: Silver Vet (+ legal identity, delegation, 1+ witness)
        LoA_3: Gold Vet (+ DARs/LARs, multisig, no-MITM ceremony)
        vLEI: Full EGF compliance (gold standard)
    """
    LOA_0 = 0  # Identifier Affidavit
    LOA_1 = 1  # Bronze Vet Credential
    LOA_2 = 2  # Silver Vet Credential
    LOA_3 = 3  # Gold Vet Credential
    VLEI = 4   # Full vLEI


# LoA level human-readable names
LOA_NAMES: dict[LoALevel, str] = {
    LoALevel.LOA_0: "Identifier Affidavit (eLEI)",
    LoALevel.LOA_1: "Bronze Vet Credential",
    LoALevel.LOA_2: "Silver Vet Credential",
    LoALevel.LOA_3: "Gold Vet Credential",
    LoALevel.VLEI: "Full vLEI",
}


def loa_satisfies(actual: LoALevel, required: LoALevel) -> bool:
    """
    Check if an actual LoA level satisfies a required level.

    The ratchet is monotonic - higher levels satisfy lower requirements.

    Args:
        actual: The LoA level the credential has
        required: The LoA level that was required

    Returns:
        True if actual >= required
    """
    return actual >= required


def loa_name(level: LoALevel) -> str:
    """Human-readable name for an LoA level."""
    return LOA_NAMES.get(level, f"LoA {level}")


def loa_from_credential(credential: dict) -> LoALevel:
    """
    Extract LoA level from a credential's attributes.

    Looks for 'loa' in the attribute section ($.a.loa).
    If not found, returns LOA_0 (minimum assurance).

    Args:
        credential: Credential dict with attribute section

    Returns:
        LoALevel found in credential, or LOA_0 if not specified
    """
    attrs = credential.get("a", {})
    if isinstance(attrs, dict):
        loa_value = attrs.get("loa")
        if loa_value is not None:
            try:
                return LoALevel(int(loa_value))
            except (ValueError, TypeError):
                pass
    return LoALevel.LOA_0


# Mapping between LoA levels and KERI strength levels
# Higher LoA generally requires stronger cryptographic anchoring
LOA_TO_STRENGTH: dict[LoALevel, StrengthLevel] = {
    LoALevel.LOA_0: StrengthLevel.ANY,
    LoALevel.LOA_1: StrengthLevel.SAID_ONLY,
    LoALevel.LOA_2: StrengthLevel.KEL_ANCHORED,
    LoALevel.LOA_3: StrengthLevel.TEL_ANCHORED,
    LoALevel.VLEI: StrengthLevel.TEL_ANCHORED,
}


def loa_to_strength(loa: LoALevel) -> StrengthLevel:
    """
    Map LoA level to minimum required KERI strength.

    Args:
        loa: Hardman LoA level

    Returns:
        Minimum StrengthLevel required for that LoA
    """
    return LOA_TO_STRENGTH.get(loa, StrengthLevel.ANY)
