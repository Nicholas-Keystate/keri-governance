# -*- encoding: utf-8 -*-
"""
keri-governance - KERI Governance Engine.

Standalone governance infrastructure for the KERI ecosystem.
Consumed by KGQL (query-time governance), keri-sec (artifact governance),
and any other KERI application needing constraint evaluation.

Provides:
- Constraint algebra: EdgeOperator + StrengthLevel partial orders
- GovernanceFramework: Parsed governance framework credentials
- ConstraintChecker: Evaluates constraints during execution
- ConstraintCompiler: Compiles declarative rules into executables
- FrameworkResolver: Resolves framework SAIDs with version chains
- GovernanceEvolution: Framework versioning via supersession
- Pattern library: Reusable constraint templates
- Systems catalog: 8 workspace governance builders
- Cardinal Rules Engine: GAID artifact governance

Four Unifications (from autonomic-governance MANIFESTO):
1. Rules ARE Credentials
2. Enforcement IS Verification
3. Authority IS Delegation
4. Evolution IS Supersession
"""

__version__ = "0.1.0"

from keri_governance.primitives import (
    EdgeOperator,
    StrengthLevel,
    operator_satisfies,
    strength_satisfies,
    OPERATOR_STRENGTH,
    operator_name,
    strength_name,
)

from keri_governance.schema import (
    GovernanceFramework,
    ConstraintRule,
    CredentialMatrixEntry,
    FrameworkVersion,
    RuleEnforcement,
)

from keri_governance.checker import (
    ConstraintChecker,
    CheckResult,
    ConstraintViolation,
)

from keri_governance.compiler import (
    ConstraintCompiler,
    CompiledFramework,
    CompiledFieldConstraint,
    compile_field_expression,
)

from keri_governance.resolver import (
    FrameworkResolver,
    VersionChain,
)

from keri_governance.evolution import (
    GovernanceEvolution,
    EvolutionResult,
)

from keri_governance.patterns import (
    jurisdiction_match,
    delegation_depth,
    operator_floor,
    role_action_matrix,
    temporal_validity,
    chain_integrity,
    vlei_standard_framework,
)

from keri_governance.cardinal import (
    ArtifactType,
    Operation,
    CardinalRule,
    CardinalRuleSet,
    CardinalChecker,
    CardinalCheckResult,
    default_cardinal_rules,
)

from keri_governance.systems import (
    SystemEntry,
    SYSTEM_CATALOG,
    build_claudemd_framework,
    build_daid_framework,
    build_skill_framework,
    build_artifact_framework,
    build_deliberation_framework,
    build_plan_framework,
    build_kgql_framework,
    build_stack_framework,
    build_framework,
    build_all_frameworks,
    register_all_frameworks,
)

__all__ = [
    # Primitives
    "EdgeOperator",
    "StrengthLevel",
    "operator_satisfies",
    "strength_satisfies",
    "OPERATOR_STRENGTH",
    "operator_name",
    "strength_name",
    # Schema
    "GovernanceFramework",
    "ConstraintRule",
    "CredentialMatrixEntry",
    "FrameworkVersion",
    "RuleEnforcement",
    # Checker
    "ConstraintChecker",
    "CheckResult",
    "ConstraintViolation",
    # Compiler
    "ConstraintCompiler",
    "CompiledFramework",
    "CompiledFieldConstraint",
    "compile_field_expression",
    # Resolver
    "FrameworkResolver",
    "VersionChain",
    # Evolution
    "GovernanceEvolution",
    "EvolutionResult",
    # Patterns
    "jurisdiction_match",
    "delegation_depth",
    "operator_floor",
    "role_action_matrix",
    "temporal_validity",
    "chain_integrity",
    "vlei_standard_framework",
    # Cardinal Rules
    "ArtifactType",
    "Operation",
    "CardinalRule",
    "CardinalRuleSet",
    "CardinalChecker",
    "CardinalCheckResult",
    "default_cardinal_rules",
    # Systems
    "SystemEntry",
    "SYSTEM_CATALOG",
    "build_claudemd_framework",
    "build_daid_framework",
    "build_skill_framework",
    "build_artifact_framework",
    "build_deliberation_framework",
    "build_plan_framework",
    "build_kgql_framework",
    "build_stack_framework",
    "build_framework",
    "build_all_frameworks",
    "register_all_frameworks",
]
