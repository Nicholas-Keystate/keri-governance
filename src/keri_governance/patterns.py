# -*- encoding: utf-8 -*-
"""
KERI Constraint Pattern Library - Reusable governance rule templates.

Provides factory functions that produce pre-configured ConstraintRule and
CredentialMatrixEntry sets for common governance scenarios. Each pattern
encodes domain knowledge about typical credential governance requirements.

Patterns:
    1. jurisdiction_match    - Geographic alignment between issuer and subject
    2. delegation_depth      - Maximum chain length for delegated authorization
    3. operator_floor        - Minimum operator strength for edge types
    4. role_action_matrix    - Standard vLEI role-action authorization grid
    5. temporal_validity     - Credential expiration and freshness constraints
    6. chain_integrity       - Trust chain structure requirements

Usage:
    from keri_governance.patterns import jurisdiction_match, delegation_depth

    rules = [
        *jurisdiction_match("iss"),
        *delegation_depth("delegate", max_depth=3),
    ]
    matrix = role_action_matrix(roles=["QVI", "LE"], actions=["issue", "revoke"])
"""

from keri_governance.schema import (
    ConstraintRule,
    CredentialMatrixEntry,
    RuleEnforcement,
)
from keri_governance.primitives import EdgeOperator


# ---------------------------------------------------------------------------
# Pattern 1: Jurisdiction Match
# ---------------------------------------------------------------------------

def jurisdiction_match(
    applies_to: str,
    issuer_field: str = "jurisdiction",
    subject_field: str = "country",
    enforcement: RuleEnforcement = RuleEnforcement.STRICT,
) -> list[ConstraintRule]:
    """
    Require geographic alignment between issuer and subject.

    Common in cross-border regulatory frameworks where a QVI in one
    jurisdiction should only issue credentials for entities in the same
    jurisdiction (or a mapped set).

    Args:
        applies_to: Edge type this rule constrains (e.g., "iss", "QVI->LE")
        issuer_field: Attribute name on the issuer node
        subject_field: Attribute name on the subject node
        enforcement: STRICT (block) or ADVISORY (warn)

    Returns:
        List containing the jurisdiction match constraint rule
    """
    return [
        ConstraintRule(
            name="jurisdiction-match",
            description=(
                f"Issuer {issuer_field} must match subject {subject_field}"
            ),
            applies_to=applies_to,
            required_operator=EdgeOperator.DI2I,
            field_constraints={
                "jurisdiction": (
                    f"$issuer.{issuer_field} == $subject.{subject_field}"
                ),
            },
            enforcement=enforcement,
        ),
    ]


# ---------------------------------------------------------------------------
# Pattern 2: Delegation Depth
# ---------------------------------------------------------------------------

def delegation_depth(
    applies_to: str,
    max_depth: int = 3,
    required_operator: EdgeOperator = EdgeOperator.DI2I,
    enforcement: RuleEnforcement = RuleEnforcement.STRICT,
) -> list[ConstraintRule]:
    """
    Limit delegation chain length to prevent unbounded authority propagation.

    In vLEI, the chain GLEIF -> QVI -> LE -> OOR has depth 3. This pattern
    enforces that delegation chains don't exceed a specified depth,
    preventing authority dilution through excessive re-delegation.

    Args:
        applies_to: Edge type this rule constrains (e.g., "delegate")
        max_depth: Maximum allowed delegation chain length
        required_operator: Minimum operator for delegation edges
        enforcement: STRICT (block) or ADVISORY (warn)

    Returns:
        List containing the delegation depth constraint rule
    """
    return [
        ConstraintRule(
            name="delegation-depth-limit",
            description=(
                f"Delegation chain must not exceed depth {max_depth}"
            ),
            applies_to=applies_to,
            required_operator=required_operator,
            max_delegation_depth=max_depth,
            enforcement=enforcement,
        ),
    ]


# ---------------------------------------------------------------------------
# Pattern 3: Operator Floor
# ---------------------------------------------------------------------------

def operator_floor(
    edge_types: list[str],
    minimum: EdgeOperator = EdgeOperator.DI2I,
    enforcement: RuleEnforcement = RuleEnforcement.STRICT,
) -> list[ConstraintRule]:
    """
    Set a minimum operator strength across multiple edge types.

    Useful when an entire governance domain requires at least DI2I
    (delegated identity-to-identity) or I2I (direct) for all edges,
    preventing weaker NI2I or ANY traversals.

    Args:
        edge_types: List of edge types to constrain
        minimum: Minimum operator strength required
        enforcement: STRICT (block) or ADVISORY (warn)

    Returns:
        List of constraint rules, one per edge type
    """
    return [
        ConstraintRule(
            name=f"operator-floor-{edge_type}",
            description=(
                f"Edge '{edge_type}' requires at least "
                f"@{minimum.value} operator"
            ),
            applies_to=edge_type,
            required_operator=minimum,
            enforcement=enforcement,
        )
        for edge_type in edge_types
    ]


# ---------------------------------------------------------------------------
# Pattern 4: Role-Action Matrix
# ---------------------------------------------------------------------------

def role_action_matrix(
    roles: list[str],
    actions: list[str],
    default_operator: EdgeOperator = EdgeOperator.DI2I,
    denied: dict[tuple[str, str], bool] | None = None,
    overrides: dict[tuple[str, str], EdgeOperator] | None = None,
) -> list[CredentialMatrixEntry]:
    """
    Generate a credential authorization matrix for role-action pairs.

    Produces a CredentialMatrixEntry for every (action, role) combination.
    Override specific cells with higher/lower operators or deny access.

    Args:
        roles: Role names (e.g., ["QVI", "LE", "Agent"])
        actions: Action names (e.g., ["issue", "revoke", "query"])
        default_operator: Default operator for all cells
        denied: Dict of (action, role) -> True for denied combinations
        overrides: Dict of (action, role) -> EdgeOperator for specific cells

    Returns:
        List of CredentialMatrixEntry for all combinations

    Example:
        matrix = role_action_matrix(
            roles=["QVI", "LE"],
            actions=["issue", "revoke", "query"],
            default_operator=EdgeOperator.DI2I,
            denied={("issue", "LE"): True},
            overrides={("revoke", "QVI"): EdgeOperator.I2I},
        )
    """
    denied = denied or {}
    overrides = overrides or {}
    entries = []

    for action in actions:
        for role in roles:
            key = (action, role)
            if denied.get(key, False):
                entries.append(CredentialMatrixEntry(
                    action=action,
                    role=role,
                    required_operator=EdgeOperator.ANY,
                    allowed=False,
                ))
            else:
                entries.append(CredentialMatrixEntry(
                    action=action,
                    role=role,
                    required_operator=overrides.get(key, default_operator),
                    allowed=True,
                ))

    return entries


# ---------------------------------------------------------------------------
# Pattern 5: Temporal Validity
# ---------------------------------------------------------------------------

def temporal_validity(
    applies_to: str,
    freshness_field: str = "issuance_date",
    expiry_field: str = "expiry_date",
    enforcement: RuleEnforcement = RuleEnforcement.STRICT,
) -> list[ConstraintRule]:
    """
    Enforce credential freshness and expiration constraints.

    Generates field constraints that check temporal bounds. The actual
    temporal evaluation happens in the compiler/executor layer which
    resolves $now against credential attributes.

    Args:
        applies_to: Edge type this rule constrains
        freshness_field: Attribute containing issuance timestamp
        expiry_field: Attribute containing expiration timestamp
        enforcement: STRICT (block) or ADVISORY (warn)

    Returns:
        List containing temporal validity constraint rules
    """
    rules = [
        ConstraintRule(
            name="temporal-not-expired",
            description=f"Credential {expiry_field} must be in the future",
            applies_to=applies_to,
            required_operator=EdgeOperator.ANY,
            field_constraints={
                "expiry": f"$subject.{expiry_field} > $now.timestamp",
            },
            enforcement=enforcement,
        ),
        ConstraintRule(
            name="temporal-freshness",
            description=f"Credential {freshness_field} must exist",
            applies_to=applies_to,
            required_operator=EdgeOperator.ANY,
            field_constraints={
                "freshness": f"$subject.{freshness_field} != \"\"",
            },
            enforcement=RuleEnforcement.ADVISORY,
        ),
    ]
    return rules


# ---------------------------------------------------------------------------
# Pattern 6: Chain Integrity
# ---------------------------------------------------------------------------

def chain_integrity(
    chain_edges: list[str],
    root_operator: EdgeOperator = EdgeOperator.I2I,
    intermediate_operator: EdgeOperator = EdgeOperator.DI2I,
    leaf_operator: EdgeOperator = EdgeOperator.NI2I,
) -> list[ConstraintRule]:
    """
    Enforce trust chain structure with decreasing operator requirements.

    Models hierarchical trust chains where the root requires the strongest
    operator and each subsequent level may weaken. Typical for vLEI:
        GLEIF -[@I2I]-> QVI -[@DI2I]-> LE -[@NI2I]-> OOR

    Args:
        chain_edges: Ordered list of edge types from root to leaf
        root_operator: Operator for the first (root) edge
        intermediate_operator: Operator for middle edges
        leaf_operator: Operator for the last (leaf) edge

    Returns:
        List of constraint rules, one per chain edge

    Example:
        rules = chain_integrity(
            chain_edges=["gleif_auth", "qvi_issue", "oor_assign"],
            root_operator=EdgeOperator.I2I,
            intermediate_operator=EdgeOperator.DI2I,
            leaf_operator=EdgeOperator.NI2I,
        )
    """
    if not chain_edges:
        return []

    rules = []
    for i, edge_type in enumerate(chain_edges):
        if i == 0:
            operator = root_operator
            label = "root"
        elif i == len(chain_edges) - 1:
            operator = leaf_operator
            label = "leaf"
        else:
            operator = intermediate_operator
            label = "intermediate"

        rules.append(ConstraintRule(
            name=f"chain-{label}-{edge_type}",
            description=(
                f"Chain {label} edge '{edge_type}' requires "
                f"@{operator.value}"
            ),
            applies_to=edge_type,
            required_operator=operator,
            enforcement=RuleEnforcement.STRICT,
        ))

    return rules


# ---------------------------------------------------------------------------
# Composite: vLEI Standard Framework
# ---------------------------------------------------------------------------

def vlei_standard_framework() -> dict:
    """
    Generate a complete vLEI-style governance framework configuration.

    Composes multiple patterns into a coherent framework suitable for
    vLEI credential ecosystems. Returns a dict with 'rules' and
    'credential_matrix' keys ready for GovernanceFramework construction.

    Returns:
        Dict with:
            rules: List of ConstraintRule from composed patterns
            credential_matrix: List of CredentialMatrixEntry
            authorities: Role -> description mapping

    Example:
        config = vlei_standard_framework()
        framework = GovernanceFramework(
            said="E...",
            name="vLEI Standard",
            rules=config["rules"],
            credential_matrix=config["credential_matrix"],
            authorities=config["authorities"],
        )
    """
    rules = [
        *jurisdiction_match("qvi_issue"),
        *delegation_depth("delegate", max_depth=3),
        *operator_floor(
            ["gleif_auth", "qvi_issue", "le_assign"],
            minimum=EdgeOperator.DI2I,
        ),
        *chain_integrity(
            chain_edges=["gleif_auth", "qvi_issue", "le_assign"],
            root_operator=EdgeOperator.I2I,
            intermediate_operator=EdgeOperator.DI2I,
            leaf_operator=EdgeOperator.NI2I,
        ),
        *temporal_validity("qvi_issue"),
    ]

    matrix = role_action_matrix(
        roles=["GLEIF", "QVI", "LE"],
        actions=["issue", "revoke", "delegate", "query"],
        default_operator=EdgeOperator.DI2I,
        denied={
            ("issue", "LE"): True,
            ("delegate", "LE"): True,
        },
        overrides={
            ("issue", "GLEIF"): EdgeOperator.I2I,
            ("revoke", "GLEIF"): EdgeOperator.I2I,
            ("delegate", "GLEIF"): EdgeOperator.I2I,
            ("query", "LE"): EdgeOperator.NI2I,
        },
    )

    authorities = {
        "GLEIF": ["Root of trust, issues QVI authorizations"],
        "QVI": ["Qualified vLEI Issuers, delegated by GLEIF"],
        "LE": ["Legal Entities, credentialed by QVIs"],
    }

    return {
        "rules": rules,
        "credential_matrix": matrix,
        "authorities": authorities,
    }
