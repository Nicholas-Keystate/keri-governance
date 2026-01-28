# -*- encoding: utf-8 -*-
"""
KERI Governance Systems Registry - Unified governance for all 8 workspace systems.

Each system's governance rules are expressed as GovernanceFramework configurations
using the Constraint Pattern Library. This allows WITHIN FRAMEWORK queries to
enforce rules uniformly across the entire workspace.

Systems:
    1. ClaudemdGovernor     - Sequential chain, append-only, master AID
    2. DAIDManager          - Content rotation, TEL-anchored, controller-gated
    3. SkillDAIDRegistry    - Lifecycle states, controller ownership, tamper detection
    4. ArtifactRegistry     - Federated resolution, dependency verification
    5. DeliberationService  - Emergent consensus, weighted voting
    6. PlanRegistry         - Delegated authority, session binding
    7. KGQLGovernance       - Self-referential, rules-as-credentials
    8. GovernedStack        - Hierarchical delegation, master AID root

Usage:
    from keri_governance.systems import (
        build_claudemd_framework,
        build_all_frameworks,
        SYSTEM_CATALOG,
    )

    # Build a specific system's framework
    fw = build_claudemd_framework(steward_aid="Emaster...")

    # Build all 8 frameworks
    frameworks = build_all_frameworks(steward_aid="Emaster...")
"""

from dataclasses import dataclass
from typing import Optional

from keri_governance.schema import (
    GovernanceFramework,
    ConstraintRule,
    CredentialMatrixEntry,
    FrameworkVersion,
    RuleEnforcement,
)
from keri_governance.patterns import (
    operator_floor,
    delegation_depth,
    role_action_matrix,
    chain_integrity,
    temporal_validity,
)
from keri_governance.resolver import FrameworkResolver
from keri_governance.primitives import EdgeOperator


@dataclass
class SystemEntry:
    """Catalog entry describing a governance system."""
    name: str
    slug: str
    description: str
    governance_mode: str
    authorization_model: str


# ---------------------------------------------------------------------------
# System Catalog
# ---------------------------------------------------------------------------

SYSTEM_CATALOG: dict[str, SystemEntry] = {
    "claudemd": SystemEntry(
        name="ClaudemdGovernor",
        slug="claudemd-governance",
        description="CLAUDE.md document governance with append-only history",
        governance_mode="steward",
        authorization_model="Master AID controls rotations; append-only history section",
    ),
    "daid": SystemEntry(
        name="DAIDManager",
        slug="daid-governance",
        description="Document Autonomic Identifier lifecycle governance",
        governance_mode="delegated",
        authorization_model="Controller AID signs rotations; optional framework constraint gate",
    ),
    "skill": SystemEntry(
        name="SkillDAIDRegistry",
        slug="skill-governance",
        description="Skill lifecycle and content integrity governance",
        governance_mode="steward",
        authorization_model="Controller AID owns; lifecycle: draft→active→deprecated→archived",
    ),
    "artifact": SystemEntry(
        name="ArtifactRegistry",
        slug="artifact-governance",
        description="Cross-artifact dependency and resolution governance",
        governance_mode="federated",
        authorization_model="Per-handler delegation; unified SAID-based resolution",
    ),
    "deliberation": SystemEntry(
        name="DeliberationService",
        slug="deliberation-governance",
        description="Emergent consensus via weighted deliberation",
        governance_mode="deliberative",
        authorization_model="Threshold-based ratification; no single steward",
    ),
    "plan": SystemEntry(
        name="PlanRegistry",
        slug="plan-governance",
        description="Strategic plan lifecycle and session binding governance",
        governance_mode="delegated",
        authorization_model="Master AID delegates to sessions; amendments via deliberation",
    ),
    "kgql": SystemEntry(
        name="KGQLGovernance",
        slug="kgql-governance",
        description="Self-referential governance framework for KGQL itself",
        governance_mode="self-referential",
        authorization_model="Framework credential governs its own evolution via supersession",
    ),
    "stack": SystemEntry(
        name="GovernedStack",
        slug="stack-governance",
        description="Master AID delegation hierarchy and turn attestation",
        governance_mode="hierarchical",
        authorization_model="Master AID → session AIDs → turn attestation chain",
    ),
}


# ---------------------------------------------------------------------------
# Framework Builders
# ---------------------------------------------------------------------------

def _compute_said(name: str, version: str) -> str:
    """Deterministic SAID for framework registration (non-TEL)."""
    import hashlib
    content = f"{name}:{version}".encode()
    digest = hashlib.blake2b(content, digest_size=32).digest()
    import base64
    b64 = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return f"E{b64[:43]}"


def build_claudemd_framework(
    steward_aid: str,
    version: str = "1.0.0",
) -> GovernanceFramework:
    """
    ClaudemdGovernor: Sequential chain, append-only, master AID.

    Rules:
    - Content rotation requires I2I (master AID direct)
    - History section is append-only (no deletion)
    - Only master AID can rotate
    """
    said = _compute_said("claudemd-governance", version)

    rules = [
        *operator_floor(["content_rotation"], minimum=EdgeOperator.I2I),
        ConstraintRule(
            name="append-only-history",
            description="Historical Decisions section is append-only",
            applies_to="content_rotation",
            required_operator=EdgeOperator.I2I,
            enforcement=RuleEnforcement.STRICT,
        ),
    ]

    matrix = role_action_matrix(
        roles=["master", "session", "external"],
        actions=["rotate", "read", "verify"],
        default_operator=EdgeOperator.DI2I,
        denied={
            ("rotate", "session"): True,
            ("rotate", "external"): True,
        },
        overrides={
            ("rotate", "master"): EdgeOperator.I2I,
            ("read", "session"): EdgeOperator.NI2I,
            ("read", "external"): EdgeOperator.NI2I,
            ("verify", "session"): EdgeOperator.NI2I,
            ("verify", "external"): EdgeOperator.NI2I,
        },
    )

    return GovernanceFramework(
        said=said,
        name="CLAUDE.md Governance",
        version_info=FrameworkVersion(
            said=said, version=version, steward_aid=steward_aid,
        ),
        steward=steward_aid,
        rules=rules,
        credential_matrix=matrix,
        authorities={"master": [steward_aid]},
    )


def build_daid_framework(
    steward_aid: str,
    version: str = "1.0.0",
) -> GovernanceFramework:
    """
    DAIDManager: Content rotation, TEL-anchored, controller-gated.

    Rules:
    - Rotation requires at least DI2I
    - Controller is the only authorized rotator
    - Content must have valid SAID
    """
    said = _compute_said("daid-governance", version)

    rules = [
        *operator_floor(["content_rotation"], minimum=EdgeOperator.DI2I),
        *delegation_depth("delegate", max_depth=3),
    ]

    matrix = role_action_matrix(
        roles=["controller", "delegated", "reader"],
        actions=["rotate", "verify", "query"],
        default_operator=EdgeOperator.DI2I,
        denied={("rotate", "reader"): True},
        overrides={
            ("rotate", "controller"): EdgeOperator.DI2I,
            ("verify", "reader"): EdgeOperator.NI2I,
            ("query", "reader"): EdgeOperator.NI2I,
        },
    )

    return GovernanceFramework(
        said=said,
        name="DAID Lifecycle Governance",
        version_info=FrameworkVersion(
            said=said, version=version, steward_aid=steward_aid,
        ),
        steward=steward_aid,
        rules=rules,
        credential_matrix=matrix,
        authorities={"controller": [steward_aid]},
    )


def build_skill_framework(
    steward_aid: str,
    version: str = "1.0.0",
) -> GovernanceFramework:
    """
    SkillDAIDRegistry: Lifecycle states, controller ownership, tamper detection.

    Rules:
    - Only controller can transition lifecycle states
    - Lifecycle is one-directional: draft→active→deprecated→archived
    - Content SAID must match at execution time
    """
    said = _compute_said("skill-governance", version)

    rules = [
        *operator_floor(
            ["lifecycle_transition", "content_update"],
            minimum=EdgeOperator.I2I,
        ),
        ConstraintRule(
            name="lifecycle-direction",
            description="Lifecycle transitions must progress forward: draft→active→deprecated→archived",
            applies_to="lifecycle_transition",
            required_operator=EdgeOperator.I2I,
            enforcement=RuleEnforcement.STRICT,
        ),
    ]

    matrix = role_action_matrix(
        roles=["controller", "executor"],
        actions=["activate", "deprecate", "archive", "execute"],
        default_operator=EdgeOperator.I2I,
        denied={
            ("activate", "executor"): True,
            ("deprecate", "executor"): True,
            ("archive", "executor"): True,
        },
        overrides={
            ("execute", "executor"): EdgeOperator.NI2I,
        },
    )

    return GovernanceFramework(
        said=said,
        name="Skill Lifecycle Governance",
        version_info=FrameworkVersion(
            said=said, version=version, steward_aid=steward_aid,
        ),
        steward=steward_aid,
        rules=rules,
        credential_matrix=matrix,
        authorities={"controller": [steward_aid]},
    )


def build_artifact_framework(
    steward_aid: str,
    version: str = "1.0.0",
) -> GovernanceFramework:
    """
    ArtifactRegistry: Federated resolution, dependency verification.

    Rules:
    - SAID references must resolve to valid artifacts
    - Dependency chains cannot be circular
    - Each handler type enforces its own authorization
    """
    said = _compute_said("artifact-governance", version)

    rules = [
        *operator_floor(
            ["dependency_edge", "resolution"],
            minimum=EdgeOperator.NI2I,
        ),
        ConstraintRule(
            name="no-circular-dependencies",
            description="Artifact dependency graphs must be acyclic",
            applies_to="dependency_edge",
            required_operator=EdgeOperator.NI2I,
            enforcement=RuleEnforcement.STRICT,
        ),
    ]

    matrix = role_action_matrix(
        roles=["handler", "resolver", "consumer"],
        actions=["register", "resolve", "query"],
        default_operator=EdgeOperator.NI2I,
        denied={
            ("register", "consumer"): True,
        },
        overrides={
            ("register", "handler"): EdgeOperator.DI2I,
        },
    )

    return GovernanceFramework(
        said=said,
        name="Artifact Registry Governance",
        version_info=FrameworkVersion(
            said=said, version=version, steward_aid=steward_aid,
        ),
        steward=steward_aid,
        rules=rules,
        credential_matrix=matrix,
        authorities={"handler": [steward_aid]},
    )


def build_deliberation_framework(
    steward_aid: str,
    version: str = "1.0.0",
) -> GovernanceFramework:
    """
    DeliberationService: Emergent consensus, weighted voting.

    Rules:
    - Any AID can propose (NI2I)
    - Support/oppose require DI2I (must be recognized participant)
    - Ratification requires threshold satisfaction
    - Blocking questions halt ratification
    """
    said = _compute_said("deliberation-governance", version)

    rules = [
        ConstraintRule(
            name="proposal-open",
            description="Any recognized AID can submit proposals",
            applies_to="propose",
            required_operator=EdgeOperator.NI2I,
            enforcement=RuleEnforcement.STRICT,
        ),
        ConstraintRule(
            name="position-authenticated",
            description="Support/oppose requires delegated identity",
            applies_to="position",
            required_operator=EdgeOperator.DI2I,
            enforcement=RuleEnforcement.STRICT,
        ),
        ConstraintRule(
            name="ratification-threshold",
            description="Ratification requires threshold satisfaction",
            applies_to="ratify",
            required_operator=EdgeOperator.DI2I,
            enforcement=RuleEnforcement.STRICT,
        ),
    ]

    matrix = role_action_matrix(
        roles=["proposer", "voter", "ratifier"],
        actions=["propose", "support", "oppose", "question", "ratify"],
        default_operator=EdgeOperator.DI2I,
        denied={
            ("ratify", "proposer"): True,  # Proposer cannot self-ratify
        },
        overrides={
            ("propose", "proposer"): EdgeOperator.NI2I,
            ("question", "voter"): EdgeOperator.NI2I,
        },
    )

    return GovernanceFramework(
        said=said,
        name="Deliberation Governance",
        version_info=FrameworkVersion(
            said=said, version=version, steward_aid=steward_aid,
        ),
        steward=steward_aid,
        rules=rules,
        credential_matrix=matrix,
        authorities={"ratifier": [steward_aid]},
    )


def build_plan_framework(
    steward_aid: str,
    version: str = "1.0.0",
) -> GovernanceFramework:
    """
    PlanRegistry: Delegated authority, session binding.

    Rules:
    - Master AID owns plans
    - Sessions bind via delegation chain
    - Amendment requires deliberation when locked
    - Lifecycle: draft→proposed→ratified→active→completed
    """
    said = _compute_said("plan-governance", version)

    rules = [
        *operator_floor(["plan_create", "plan_amend"], minimum=EdgeOperator.DI2I),
        *delegation_depth("session_bind", max_depth=2),
        ConstraintRule(
            name="production-lock",
            description="Active plans require deliberation for amendment",
            applies_to="plan_amend",
            required_operator=EdgeOperator.I2I,
            enforcement=RuleEnforcement.STRICT,
        ),
    ]

    matrix = role_action_matrix(
        roles=["master", "session", "collaborator"],
        actions=["create", "amend", "bind", "complete", "read"],
        default_operator=EdgeOperator.DI2I,
        denied={
            ("create", "collaborator"): True,
            ("complete", "collaborator"): True,
        },
        overrides={
            ("create", "master"): EdgeOperator.I2I,
            ("amend", "master"): EdgeOperator.I2I,
            ("read", "collaborator"): EdgeOperator.NI2I,
            ("bind", "session"): EdgeOperator.DI2I,
        },
    )

    return GovernanceFramework(
        said=said,
        name="Plan Lifecycle Governance",
        version_info=FrameworkVersion(
            said=said, version=version, steward_aid=steward_aid,
        ),
        steward=steward_aid,
        rules=rules,
        credential_matrix=matrix,
        authorities={"master": [steward_aid]},
    )


def build_kgql_framework(
    steward_aid: str,
    version: str = "1.0.0",
) -> GovernanceFramework:
    """
    KGQLGovernance: Self-referential, rules-as-credentials.

    This framework governs its own evolution. The framework credential
    is itself subject to the rules it defines — the quintessential
    self-referential governance pattern.

    Rules:
    - Framework evolution requires I2I (steward direct)
    - Supersession must reference prior via edge
    - Field constraints enforce version monotonicity
    """
    said = _compute_said("kgql-governance", version)

    rules = [
        *operator_floor(["framework_evolution"], minimum=EdgeOperator.I2I),
        ConstraintRule(
            name="supersession-required",
            description="New framework version must have supersedes edge to prior",
            applies_to="framework_evolution",
            required_operator=EdgeOperator.I2I,
            enforcement=RuleEnforcement.STRICT,
        ),
        ConstraintRule(
            name="version-monotonic",
            description="Framework version must increase monotonically",
            applies_to="framework_evolution",
            required_operator=EdgeOperator.I2I,
            field_constraints={
                "version": "$new.version > $current.version",
            },
            enforcement=RuleEnforcement.ADVISORY,
        ),
    ]

    matrix = role_action_matrix(
        roles=["steward", "checker", "querier"],
        actions=["evolve", "check", "query"],
        default_operator=EdgeOperator.DI2I,
        denied={
            ("evolve", "checker"): True,
            ("evolve", "querier"): True,
        },
        overrides={
            ("evolve", "steward"): EdgeOperator.I2I,
            ("check", "checker"): EdgeOperator.NI2I,
            ("query", "querier"): EdgeOperator.NI2I,
        },
    )

    return GovernanceFramework(
        said=said,
        name="KGQL Self-Governance",
        version_info=FrameworkVersion(
            said=said, version=version, steward_aid=steward_aid,
        ),
        steward=steward_aid,
        rules=rules,
        credential_matrix=matrix,
        authorities={"steward": [steward_aid]},
    )


def build_stack_framework(
    steward_aid: str,
    version: str = "1.0.0",
) -> GovernanceFramework:
    """
    GovernedStack: Hierarchical delegation, master AID root.

    Rules:
    - Master AID is root of trust
    - Session AIDs delegate from master (depth 1)
    - Turn attestation requires session signature
    - External credential issuance requires Touch ID (I2I)
    """
    said = _compute_said("stack-governance", version)

    rules = [
        *chain_integrity(
            chain_edges=["master_to_session", "session_to_turn"],
            root_operator=EdgeOperator.I2I,
            intermediate_operator=EdgeOperator.DI2I,
            leaf_operator=EdgeOperator.DI2I,
        ),
        *delegation_depth("delegate", max_depth=2),
    ]

    matrix = role_action_matrix(
        roles=["master", "session"],
        actions=["delegate", "attest", "issue_external", "issue_self"],
        default_operator=EdgeOperator.DI2I,
        denied={
            ("delegate", "session"): True,
            ("issue_external", "session"): True,
        },
        overrides={
            ("delegate", "master"): EdgeOperator.I2I,
            ("issue_external", "master"): EdgeOperator.I2I,
            ("attest", "session"): EdgeOperator.DI2I,
            ("issue_self", "session"): EdgeOperator.DI2I,
        },
    )

    return GovernanceFramework(
        said=said,
        name="Governed Stack Governance",
        version_info=FrameworkVersion(
            said=said, version=version, steward_aid=steward_aid,
        ),
        steward=steward_aid,
        rules=rules,
        credential_matrix=matrix,
        authorities={"master": [steward_aid]},
    )


# ---------------------------------------------------------------------------
# Builder Registry
# ---------------------------------------------------------------------------

_BUILDERS = {
    "claudemd": build_claudemd_framework,
    "daid": build_daid_framework,
    "skill": build_skill_framework,
    "artifact": build_artifact_framework,
    "deliberation": build_deliberation_framework,
    "plan": build_plan_framework,
    "kgql": build_kgql_framework,
    "stack": build_stack_framework,
}


def build_framework(
    system: str,
    steward_aid: str,
    version: str = "1.0.0",
) -> GovernanceFramework:
    """
    Build a governance framework for a named system.

    Args:
        system: System slug (one of SYSTEM_CATALOG keys)
        steward_aid: AID of the framework steward
        version: Semantic version

    Returns:
        GovernanceFramework configured for the system

    Raises:
        KeyError: If system is not in the catalog
    """
    if system not in _BUILDERS:
        raise KeyError(
            f"Unknown system '{system}'. "
            f"Available: {', '.join(_BUILDERS.keys())}"
        )
    return _BUILDERS[system](steward_aid=steward_aid, version=version)


def build_all_frameworks(
    steward_aid: str,
    version: str = "1.0.0",
) -> dict[str, GovernanceFramework]:
    """
    Build governance frameworks for all 8 systems.

    Args:
        steward_aid: AID of the framework steward (typically master AID)
        version: Semantic version for all frameworks

    Returns:
        Dict mapping system slug to GovernanceFramework
    """
    return {
        slug: builder(steward_aid=steward_aid, version=version)
        for slug, builder in _BUILDERS.items()
    }


def register_all_frameworks(
    resolver: FrameworkResolver,
    steward_aid: str,
    version: str = "1.0.0",
) -> dict[str, str]:
    """
    Build and register all 8 governance frameworks in a resolver.

    Args:
        resolver: FrameworkResolver to register frameworks in
        steward_aid: AID of the framework steward
        version: Semantic version

    Returns:
        Dict mapping system slug to framework SAID
    """
    saids = {}
    for slug, fw in build_all_frameworks(steward_aid, version).items():
        resolver.register(fw)
        saids[slug] = fw.said
    return saids
