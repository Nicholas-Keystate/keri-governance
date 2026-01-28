# -*- encoding: utf-8 -*-
"""
KERI Governance Evolution - Framework versioning via supersession.

Implements two evolution modes from the Governance Maturity Model:

Mode A (Steward Supersession):
    Framework steward directly creates a new framework credential with
    a 'supersedes' edge to the prior version. Authority is centralized
    in the steward AID. The steward must be the same AID that issued
    the current active framework, or authorized by delegation.

Mode B (Emergent Deliberation):
    A ratified deliberation produces a new framework credential. The
    ratification credential IS the authorization to evolve. Maps
    deliberation output to framework credential structure.

Mode C (Algorithmic Adaptation) is deferred to WARI integration.

Key Principle (Four Unifications):
    Evolution IS Supersession — every framework change produces a new
    credential with an edge to the one it replaces.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from keri_governance.schema import (
    GovernanceFramework,
    ConstraintRule,
    CredentialMatrixEntry,
    FrameworkVersion,
)
from keri_governance.resolver import FrameworkResolver


@dataclass
class EvolutionResult:
    """Result of a governance evolution operation."""
    success: bool
    new_framework: Optional[GovernanceFramework] = None
    prior_said: Optional[str] = None
    mode: str = ""
    reason: str = ""


class GovernanceEvolution:
    """
    Manages governance framework evolution through supersession.

    Tracks the active framework and produces new versions via
    Mode A (steward) or Mode B (deliberation).

    Usage:
        evolution = GovernanceEvolution(resolver)

        # Mode A: steward directly supersedes
        result = evolution.supersede(
            current_said="Eold...",
            steward_aid="Esteward...",
            new_name="Updated Framework",
            new_version="2.0.0",
            new_rules=[...],
            new_matrix=[...],
        )

        # Mode B: deliberation ratification produces new framework
        result = evolution.evolve_from_ratification(
            current_said="Eold...",
            ratification_said="Erat...",
            ratification_data={...},
        )
    """

    def __init__(
        self,
        resolver: FrameworkResolver,
        credential_factory: Optional[Callable[..., str]] = None,
    ):
        """
        Initialize governance evolution.

        Args:
            resolver: FrameworkResolver for looking up current frameworks
            credential_factory: Optional callable that produces a SAID for
                a new framework credential dict. If None, uses a simple
                content-addressed hash. In production, this would call
                proving.credential() and issue to TEL.
        """
        self._resolver = resolver
        self._credential_factory = credential_factory or self._default_said

    @staticmethod
    def _default_said(credential: dict) -> str:
        """
        Produce a deterministic SAID from credential content.

        For testing and non-TEL environments. Production should use
        proving.credential() with TEL anchoring.
        """
        import hashlib
        import json
        content = json.dumps(credential, sort_keys=True)
        digest = hashlib.blake2b(content.encode(), digest_size=32).digest()
        import base64
        b64 = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return f"E{b64[:43]}"

    def supersede(
        self,
        current_said: str,
        steward_aid: str,
        new_name: Optional[str] = None,
        new_version: Optional[str] = None,
        new_rules: Optional[list[ConstraintRule]] = None,
        new_matrix: Optional[list[CredentialMatrixEntry]] = None,
        new_authorities: Optional[dict[str, list[str]]] = None,
        reason: str = "",
    ) -> EvolutionResult:
        """
        Mode A: Steward supersession.

        The steward creates a new framework credential with a 'supersedes'
        edge to the current active version. The steward must be the same
        AID that issued the current framework.

        Args:
            current_said: SAID of the current active framework
            steward_aid: AID of the steward requesting supersession
            new_name: Updated framework name (inherits if None)
            new_version: New semantic version (auto-bumps minor if None)
            new_rules: New rule set (inherits if None)
            new_matrix: New credential matrix (inherits if None)
            new_authorities: New authorities (inherits if None)
            reason: Human-readable reason for the change

        Returns:
            EvolutionResult with the new framework or failure reason
        """
        # Resolve current framework
        current = self._resolver.resolve(current_said)
        if current is None:
            return EvolutionResult(
                success=False,
                mode="A",
                reason=f"Current framework {current_said} not found",
            )

        # Verify steward authority
        if current.steward and current.steward != steward_aid:
            return EvolutionResult(
                success=False,
                prior_said=current_said,
                mode="A",
                reason=(
                    f"Steward {steward_aid[:16]}... is not authorized. "
                    f"Framework steward is {current.steward[:16]}..."
                ),
            )

        # Inherit unchanged fields
        name = new_name if new_name is not None else current.name
        rules = new_rules if new_rules is not None else current.rules
        matrix = new_matrix if new_matrix is not None else current.credential_matrix
        authorities = new_authorities if new_authorities is not None else current.authorities

        # Auto-bump version if not specified
        if new_version is None:
            new_version = self._bump_version(current.version)

        # Build the new framework credential
        credential = {
            "v": "ACDC10JSON000000_",
            "d": "",
            "i": steward_aid,
            "s": "GovernanceFramework",
            "a": {
                "d": "",
                "name": name,
                "version": new_version,
                "rules": [r.to_dict() for r in rules],
                "credential_matrix": [e.to_dict() for e in matrix],
                "authorities": authorities,
            },
            "e": {
                "supersedes": {
                    "d": current_said,
                },
            },
        }

        # Compute SAID
        new_said = self._credential_factory(credential)
        credential["d"] = new_said
        credential["a"]["d"] = new_said

        # Build GovernanceFramework object
        new_framework = GovernanceFramework(
            said=new_said,
            name=name,
            version_info=FrameworkVersion(
                said=new_said,
                version=new_version,
                supersedes_said=current_said,
                steward_aid=steward_aid,
            ),
            steward=steward_aid,
            rules=rules,
            credential_matrix=matrix,
            authorities=authorities,
            raw=credential,
        )

        # Register in resolver
        self._resolver.register(new_framework)
        self._resolver.register_supersession(new_said, current_said)

        return EvolutionResult(
            success=True,
            new_framework=new_framework,
            prior_said=current_said,
            mode="A",
            reason=reason,
        )

    def evolve_from_ratification(
        self,
        current_said: str,
        ratification_said: str,
        ratification_data: dict,
    ) -> EvolutionResult:
        """
        Mode B: Emergent deliberation evolution.

        A ratified deliberation produces a new framework credential.
        The ratification credential serves as the authorization proof —
        instead of requiring a single steward, the collective consensus
        authorizes the evolution.

        The ratification_data must contain:
            - proposed_rules: List of rule dicts (optional, inherits if absent)
            - proposed_matrix: List of matrix entry dicts (optional)
            - proposed_authorities: Dict (optional)
            - proposed_name: str (optional)
            - proposed_version: str (optional)
            - proposer_aid: str (required — becomes steward of new version)

        Args:
            current_said: SAID of the current active framework
            ratification_said: SAID of the ratification credential
            ratification_data: Dict containing the ratified proposal content

        Returns:
            EvolutionResult with the new framework or failure reason
        """
        # Resolve current framework
        current = self._resolver.resolve(current_said)
        if current is None:
            return EvolutionResult(
                success=False,
                mode="B",
                reason=f"Current framework {current_said} not found",
            )

        # Extract proposed changes from ratification data
        proposer_aid = ratification_data.get("proposer_aid")
        if not proposer_aid:
            return EvolutionResult(
                success=False,
                prior_said=current_said,
                mode="B",
                reason="Ratification data missing 'proposer_aid'",
            )

        # Parse proposed rules if present
        proposed_rules = None
        if "proposed_rules" in ratification_data:
            proposed_rules = [
                ConstraintRule.from_dict(r)
                for r in ratification_data["proposed_rules"]
            ]

        # Parse proposed matrix if present
        proposed_matrix = None
        if "proposed_matrix" in ratification_data:
            proposed_matrix = [
                CredentialMatrixEntry.from_dict(e)
                for e in ratification_data["proposed_matrix"]
            ]

        proposed_authorities = ratification_data.get("proposed_authorities")
        proposed_name = ratification_data.get("proposed_name")
        proposed_version = ratification_data.get("proposed_version")

        # Inherit unchanged fields
        name = proposed_name if proposed_name is not None else current.name
        version = proposed_version if proposed_version is not None else self._bump_version(current.version)
        rules = proposed_rules if proposed_rules is not None else current.rules
        matrix = proposed_matrix if proposed_matrix is not None else current.credential_matrix
        authorities = proposed_authorities if proposed_authorities is not None else current.authorities

        # Build the new framework credential with deliberation provenance
        credential = {
            "v": "ACDC10JSON000000_",
            "d": "",
            "i": proposer_aid,
            "s": "GovernanceFramework",
            "a": {
                "d": "",
                "name": name,
                "version": version,
                "rules": [r.to_dict() for r in rules],
                "credential_matrix": [e.to_dict() for e in matrix],
                "authorities": authorities,
                "evolution_mode": "B",
            },
            "e": {
                "supersedes": {
                    "d": current_said,
                },
                "ratification": {
                    "d": ratification_said,
                },
            },
        }

        # Compute SAID
        new_said = self._credential_factory(credential)
        credential["d"] = new_said
        credential["a"]["d"] = new_said

        # Build GovernanceFramework object
        new_framework = GovernanceFramework(
            said=new_said,
            name=name,
            version_info=FrameworkVersion(
                said=new_said,
                version=version,
                supersedes_said=current_said,
                steward_aid=proposer_aid,
            ),
            steward=proposer_aid,
            rules=rules,
            credential_matrix=matrix,
            authorities=authorities,
            raw=credential,
        )

        # Register in resolver
        self._resolver.register(new_framework)
        self._resolver.register_supersession(new_said, current_said)

        return EvolutionResult(
            success=True,
            new_framework=new_framework,
            prior_said=current_said,
            mode="B",
            reason=f"Ratified via {ratification_said[:16]}...",
        )

    @staticmethod
    def _bump_version(version: str) -> str:
        """
        Auto-bump semantic version (minor).

        1.0.0 -> 1.1.0
        2.3.1 -> 2.4.0
        """
        parts = version.split(".")
        if len(parts) != 3:
            return "1.1.0"
        try:
            major, minor, _ = int(parts[0]), int(parts[1]), int(parts[2])
            return f"{major}.{minor + 1}.0"
        except ValueError:
            return "1.1.0"
